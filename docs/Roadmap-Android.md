# Android App — Design & Roadmap

An Android application that embeds `dgaard-engine` via [UniFFI](https://mozilla.github.io/uniffi-rs/) and uses Android's `VpnService` to intercept DNS traffic on-device. No root required. UI in Kotlin (Jetpack Compose). Rust engine runs in-process inside the VpnService.

## Goals

- **On-device DNS filtering** without root, via `VpnService` (DNS-only scope).
- **Dual-mode engine**: forwarder (encrypted upstream) OR full recursive resolver + local cache, user-selectable at runtime.
- **Live UI**: sub-second query feed, hourly histograms, block-reason pie chart, per-application statistics.
- **Reuse `dgaard-engine`** as-is — the same crate powers the desktop proxy, the OpenWrt package, and this app. No Android-only fork.
- **Compact binary**: prefer ABI-split APKs / AABs so each device installs only its `armeabi-v7a`, `arm64-v8a`, `x86_64` slice of the Rust `.so`.

## Non-goals (for this roadmap)

- **No full VPN tunnel**: only DNS packets are captured. Every other packet bypasses the tunnel via `Builder.addDisallowedApplication`-style routing tricks. See _VPN scope_ below.
- **No TLS SNI inspection, no IP-level blocklists** in the first release — DNS-only. IP-level blocking is left as a future phase requiring full-tunnel scope.
- **No cross-device sync, no cloud dashboard.** All state stays on-device. If remote telemetry is wanted later, the existing `dgaard-monitor-nats` frontend is the intended path.
- **No ad-hoc root/`iptables` mode.** The app must work for the median non-technical Android user.
- **No Play Store-specific features** (in-app billing, Play Integrity) in the roadmap. Distribution channel is an open question — see _Decisions to make_.

---

## Architecture overview

```text
┌─────────────────────────────────────────────────────────────────────┐
│                       Android app process                            │
│                                                                      │
│  ┌───────────────────────────┐        ┌─────────────────────────┐   │
│  │  Kotlin UI (Compose)      │        │  DgaardVpnService       │   │
│  │  - Dashboard              │        │  (extends VpnService)   │   │
│  │  - Live queries           │◄──────►│                         │   │
│  │  - Per-app stats          │  Flow  │  ┌───────────────────┐  │   │
│  │  - Settings               │        │  │  Rust engine      │  │   │
│  └──────────┬────────────────┘        │  │  (dgaard-engine)  │  │   │
│             │                          │  │                   │  │   │
│             │                          │  │  - FilterEngine   │  │   │
│             │  UniFFI Kotlin bindings  │  │  - Recursive res. │  │   │
│             └─────────────────────────►│  │  - LRU cache      │  │   │
│                                        │  │  - Ring buffer    │  │   │
│                                        │  │  - SQLite writer  │  │   │
│                                        │  └───────┬───────────┘  │   │
│                                        │          │              │   │
│                                        │  ┌───────▼───────────┐  │   │
│                                        │  │  tun fd (DNS      │  │   │
│                                        │  │  packets only)    │  │   │
│                                        │  └───────┬───────────┘  │   │
│                                        └──────────┼──────────────┘   │
│                                                   │                   │
│                                                   ▼                   │
│                                            Encrypted upstream         │
│                                          (DoH / DoT / DoQ / recursive)│
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                             SQLite (batched, on-device)
```

Two independent data paths from the engine to the UI:

1. **Live path** — in-memory ring buffer (last N events) surfaced via UniFFI callback → Kotlin `SharedFlow`. Sub-millisecond latency. Used by the _live queries_ panel.
2. **Historical path** — batched SQLite writer (hybrid: flush every 1000 ms OR every 200 events). All aggregations (pie chart, hourly bars, per-app stats, cache-hit %, block totals) read from SQL. Room DAO on the Kotlin side observes tables via `Flow`.

---

## Engine role — dual mode

Both modes ship in the same binary; user selects one in settings. Rebuilding the engine on mode switch is acceptable (rare event).

### Mode A — Forwarder + filter (default)

- Engine scores each query with `dgaard_engine::resolve_with_score`.
- Blocked queries: reply `NXDOMAIN` or configured sinkhole IP directly from the VpnService.
- Allowed queries: forward to a configurable encrypted upstream (DoH / DoT / DoQ). Transport code reuses `digaard`'s existing client stack (`hickory-proto`, `rustls`, `hyper`, `quinn`).
- Local cache: LRU with TTL respect, keyed by `(qname, qtype, qclass)`. Not a full recursive cache — only positive/negative answers from the upstream.

### Mode B — Full recursive resolver + local cache

- Engine iterates the delegation chain from root hints (see [Roadmap-recursive-DNS.md](Roadmap-recursive-DNS.md)).
- No external resolver; queries only leave the device to reach authoritative nameservers.
- Local cache is the full RFC 1034 negative + positive cache with popularity tracking.
- Root-hints file bundled in the APK; user-refreshable.

**UI implication**: the "when acting as a DNS resolver" panel — total resolved queries and % local cache used — is populated in Mode B only. In Mode A, that panel shows _"forwarder mode — upstream cache hit ratio not available"_.

**Runtime switch**: engine held behind `arc-swap`; toggling in settings rebuilds and swaps atomically without dropping the tun fd.

---

## VPN scope — DNS-only

```kotlin
val builder = Builder()
    .setSession("Dgaard")
    .addAddress("10.0.0.2", 32)           // opaque local address for the tun
    .addAddress("fd00:d9::2", 128)
    .addDnsServer("10.0.0.1")             // route DNS to us
    .addDnsServer("fd00:d9::1")
    .addRoute("10.0.0.1", 32)             // and only DNS
    .addRoute("fd00:d9::1", 128)
    .setMtu(1500)
    .setBlocking(true)
```

Only packets to the fake DNS server IP enter the tun fd. Everything else uses the underlying network directly. This is the same pattern as Nebulo / RethinkDNS.

Consequences:

- **Battery** — near-zero overhead when idle; only DNS packets are copied to user-space.
- **Compatibility** — coexists with other DNS-hijack apps only if the OS lets one hold the VPN slot at a time (it doesn't — but this is the standard tradeoff).
- **Per-app blocking** — dropping the DNS packet blocks name resolution for that app. TCP/UDP payload to already-known IPs still flows; acceptable for DNS-level defence.
- **IPv6** — the tun advertises both IPv4 and IPv6 DNS. Skipping IPv6 causes leaks on modern Android networks.

**Packet handling**: raw IP packets are parsed in Rust. Suggested crate: `etherparse` (no_std-friendly, zero-alloc for header parsing). DNS payload goes into `hickory-proto` for parse/build.

**Reply path**: engine builds the DNS reply, wraps it in a UDP/IP frame with swapped src/dst, writes to the same tun fd. No socket round-trip.

---

## IPC / storage — two-tier

Decided: **in-memory ring buffer** (live UI) + **batched SQLite writer** (historical/aggregations). Both fed from the same event emit point in the engine.

### Live tier — ring buffer

- Bounded lock-free ring, capacity ~500 events, in Rust.
- UniFFI exposes a callback trait; on each event, Rust invokes the Kotlin callback with a lightweight `QueryEvent` value type.
- Kotlin side: callback pushes into `MutableSharedFlow<QueryEvent>` (replay = 0, extraBufferCapacity = 512, `BufferOverflow.DROP_OLDEST`).
- Compose UI collects with `collectAsStateWithLifecycle`. Only the _live queries_ panel subscribes.
- **Backpressure**: if the SharedFlow buffer fills (UI hidden, phone laggy), drops are silent — the SQLite tier remains authoritative.

### Historical tier — batched SQLite

- Rust-side buffer accumulates events. Background task (single dedicated OS thread, not tokio, to keep the crate `no-tokio` in Mode A) flushes on **whichever fires first**:
  - Time trigger: 1000 ms since first buffered event (user-configurable 250–5000 ms).
  - Size trigger: 200 events buffered.
- Flush is a single transaction with a multi-row `INSERT` — one `fsync` per flush.
- Schema (initial draft):

```sql
CREATE TABLE query_event (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_millis     INTEGER NOT NULL,
    domain        TEXT    NOT NULL,
    qtype         INTEGER NOT NULL,
    action        INTEGER NOT NULL,          -- 0=allow 1=block 2=local 3=redirect
    block_reason  INTEGER,                   -- BlockReason discriminant, NULL if not blocked
    score         INTEGER,                   -- 0-10, NULL if not scored
    latency_us    INTEGER NOT NULL,
    upstream_us   INTEGER,                   -- NULL on cache hit
    cache_hit     INTEGER NOT NULL,          -- 0/1
    client_uid    INTEGER,                   -- ConnectivityManager result, NULL if unknown
    upstream      TEXT                       -- 'cache' | 'doh:1.1.1.1' | 'recursive' | ...
);
CREATE INDEX idx_ts       ON query_event(ts_millis);
CREATE INDEX idx_uid_ts   ON query_event(client_uid, ts_millis);
CREATE INDEX idx_action   ON query_event(action, ts_millis);

CREATE TABLE hour_bucket (
    hour_epoch    INTEGER PRIMARY KEY,
    total         INTEGER NOT NULL,
    blocked       INTEGER NOT NULL,
    cache_hits    INTEGER NOT NULL
);

CREATE TABLE app_stats (
    client_uid    INTEGER NOT NULL,
    date_epoch    INTEGER NOT NULL,
    total         INTEGER NOT NULL,
    blocked       INTEGER NOT NULL,
    PRIMARY KEY (client_uid, date_epoch)
);
```

- **Rotation**: keep `query_event` for N days (default 7, configurable), then delete rows older than the retention window on each flush. Aggregate tables (`hour_bucket`, `app_stats`) kept for N days too but at much lower row count.
- Rust owns the DB. Kotlin reads via **Room in read-only mode** on the same file — Room's entities mirror the schema, but only for `SELECT`. No writes from Kotlin.
- **WAL mode** enabled — Kotlin reads never block Rust writes.

### Data-shape choice recap

| Consumer             | Source        | Latency  |
| -------------------- | ------------- | -------- |
| Live queries panel   | ring + Flow   | ~ms      |
| Total / % blocked    | SQLite view   | ≤ 1 s    |
| Pie chart (reasons)  | SQLite GROUP  | ≤ 1 s    |
| Hourly bar chart     | `hour_bucket` | on flush |
| Per-app stats        | `app_stats`   | on flush |
| Cache-hit % (Mode B) | SQLite view   | ≤ 1 s    |

---

## Per-app attribution

Decided: `ConnectivityManager.getConnectionOwnerUid(...)` on API 29+ (Android 10, released 2019).

- On every DNS packet, before scoring, the VpnService looks up the owning UID via:

```kotlin
connectivityManager.getConnectionOwnerUid(
    protocol,           // IPPROTO_UDP or IPPROTO_TCP
    local  = InetSocketAddress(srcIp, srcPort),
    remote = InetSocketAddress(dstIp, dstPort)
)
```

- The UID crosses into Rust via a small callback (Kotlin-side because `ConnectivityManager` is not accessible from JNI without another round-trip). Rust attaches it to the `QueryEvent`.
- **Fallback**: `INVALID_UID` (-1) when the OS can't resolve — recorded as `NULL` in `client_uid`. UI groups these under _"System / unknown"_.
- **App metadata** (name, icon): resolved in Kotlin via `PackageManager` lazily as the UI renders, cached in a Compose-scoped map. Never stored in SQLite — package names change; UID → package resolution is done at read time.
- **Per-app blocking rules**: settings screen shows a UID → package list; user can toggle _"block all DNS from this app"_. Rules stored in a small `app_rule` table:

```sql
CREATE TABLE app_rule (
    client_uid    INTEGER PRIMARY KEY,
    block         INTEGER NOT NULL   -- 1 = drop all DNS
);
```

Rules propagate to the engine on save via UniFFI (`engine.set_app_rules(...)`).

**Minimum SDK**: `getConnectionOwnerUid` requires API 29. Setting `minSdk = 29` also aligns with foreground-service and per-app networking model changes. See _Decisions to make_ — this cuts ~5 % of Android devices as of 2026.

---

## UniFFI surface (Rust → Kotlin)

Draft `.udl` — will evolve during prototyping.

```udl
namespace dgaard_android {};

dictionary EngineConfig {
    string   mode;                       // "forwarder" | "recursive"
    string?  upstream_url;               // DoH/DoT/DoQ endpoint, forwarder only
    u32      flush_interval_ms;          // default 1000
    u32      flush_batch_size;           // default 200
    u32      ring_capacity;              // default 500
    u32      retention_days;             // default 7
    string   sqlite_path;                // full path (context.filesDir + /dgaard.db)
    string   config_toml_path;           // dgaard-engine TOML config
};

dictionary QueryEvent {
    u64      ts_millis;
    string   domain;
    u16      qtype;
    u8       action;                     // 0 allow 1 block 2 local 3 redirect
    u8?      block_reason;
    u8?      score;
    u32      latency_us;
    boolean  cache_hit;
    i32?     client_uid;
    string   upstream;
};

callback interface EventListener {
    void on_event(QueryEvent event);
};

dictionary Snapshot {
    u64  total_queries;
    u64  total_blocked;
    u64  total_cache_hits;
    u64  total_recursive;
    u32  cache_size;
    u32  cache_capacity;
};

interface Engine {
    [Throws=EngineError]
    constructor(EngineConfig config);

    void start();                        // consume events from the ring, start SQLite writer
    void stop();
    void set_listener(EventListener? listener);
    void set_app_rules(sequence<AppRule> rules);
    void reload_config();                // re-read TOML, rebuild FilterEngine via arc-swap
    Snapshot snapshot();

    // Called by Kotlin per DNS packet coming off the tun fd.
    // Returns the raw reply bytes (or empty vec = drop).
    sequence<u8> handle_dns_packet(sequence<u8> packet, i32? client_uid);
};
```

**Ownership**: `Engine` is instantiated once by `DgaardVpnService.onCreate`, held for the service lifetime, dropped in `onDestroy`.

**Async**: Kotlin coroutines wrap `handle_dns_packet` when the engine is in recursive mode (may take hundreds of ms). UniFFI's async support (`async fn` in Rust exposed as `suspend fun` in Kotlin) is used only there — the fast path (cache hit, forwarder synchronous send) stays blocking to avoid coroutine overhead per packet.

---

## UI screens (Jetpack Compose)

### Dashboard (main)

Top of screen, always visible:

- Big "Protection: ON / OFF" toggle. Tapping OFF calls `stopService`; tapping ON triggers the `VpnService.prepare()` intent if needed.
- Mode badge: _Forwarder_ or _Recursive_.

Cards below:

- **Total queries** — big number, delta over last hour.
- **Blocked** — big number + percentage of total.
- **Block reasons pie** — one slice per `BlockReason` variant (Blocklist, Static, HighEntropy, NGram, Rebinding, GeoIP, CustomFlag(…), …). Tap a slice → filtered live-query view.
- **Cache hit ratio** (Mode B only) — gauge with % + absolute counters.
- **Hourly bar chart** — last 24 h, stacked: allowed (green) + blocked (red) + cache-hit (blue) per hour, sourced from `hour_bucket`.

Chart library: **Vico** or **Compose Charts** — final choice deferred; both are Compose-native, MIT/Apache. Bar chart and pie chart must be available without pulling MPAndroidChart (heavier, older API).

### Live queries

- Streamed list, newest on top, capped at ~500 rows (matches ring capacity). Older rows disappear as new arrive.
- Row: `[icon] domain — qtype — action badge — latency`.
- Filter chips: _Blocked only_, _By app_ (opens app-picker), _By reason_.
- Tap a row → detail sheet: full score breakdown (`SuspicionScore.reasons`), upstream, cache-hit flag, resolved IPs (Mode B), timing breakdown.

### Per-app statistics

- List of apps sorted by traffic (descending), pulled from `app_stats` for the current time range picker (Today / 7 d / 30 d).
- Row: app icon + name, total queries, blocked count, blocked %.
- Tap → app detail: hourly bar chart for that UID, top domains, top block reasons, toggle _"Block all DNS from this app"_.

### Settings

- **Mode**: Forwarder / Recursive radio.
- **Upstream** (Forwarder only): dropdown of presets (Cloudflare DoH, Quad9 DoT, NextDNS DoH, …) + custom URL field.
- **Blocklists**: list of configured sources with mtime + entry count; _Reload_ button; add-URL button.
- **Retention**: slider 1–30 days.
- **Flush interval**: slider 250–5000 ms.
- **Ring buffer capacity**: 100–2000.
- **Battery**: _"Disable live feed when screen off"_ toggle (drops the ring buffer listener; SQLite tier keeps running).
- **Export**: dump SQLite as gzipped JSONL to a user-chosen `content://` URI.

---

## Permissions & manifest

```xml
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"
                 tools:ignore="QueryAllPackagesPermission"/>
<uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE"/>
<uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>

<service
    android:name=".DgaardVpnService"
    android:permission="android.permission.BIND_VPN_SERVICE"
    android:foregroundServiceType="specialUse"
    android:exported="false">
    <intent-filter>
        <action android:name="android.net.VpnService"/>
    </intent-filter>
    <property
        android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
        android:value="On-device DNS filtering VPN"/>
</service>
```

`QUERY_ALL_PACKAGES` is required by Play Store review for per-app statistics apps; F-Droid does not require the extra property but doesn't reject it. Justification is standard: "app displays per-application network usage".

---

## Native library packaging

- Rust crate: new workspace member `android/` containing an `android/engine/` cdylib producing `libdgaard_engine_uniffi.so`.
- Cross-compile targets: `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`, `i686-linux-android`.
- **NDK version pinning** in `rust-toolchain.toml` deferred until the first build attempt validates the toolchain.
- Build system: `cargo-ndk` invoked by a Gradle task. Bindings generated with `uniffi-bindgen-kotlin` into `app/build/generated/`.
- APK/AAB splits: per-ABI, via `splits.abi { enable true; ... }` in Gradle. Cuts install size by ~4×.
- **`opt-level` and LTO**: the Android target does _not_ share the workspace's `opt-level = "z" / panic = "abort"` release profile — VPN throughput matters more than binary size. Override in a new `[profile.release-android]` custom profile, invoked by `cargo-ndk --profile release-android`.

---

## Milestones

### Phase 0 — Foundation (spike)

- Empty Android app + Compose scaffold.
- `libdgaard_engine_uniffi.so` cross-compiled for `arm64-v8a` and loaded from Kotlin.
- Round-trip: Kotlin calls a Rust fn, gets a string back. Confirms UniFFI + NDK toolchain works.
- **Exit criteria**: `Engine::new(config)` succeeds on-device, `Engine::snapshot()` returns zeros, no crash.

### Phase 1 — DNS-only VPN, forwarder mode

- `DgaardVpnService` builds the tun, reads packets, hands them to `Engine::handle_dns_packet`.
- Forwarder upstream: single DoH endpoint hardcoded (Cloudflare).
- No blocking logic yet — pure passthrough with logging to logcat.
- **Exit criteria**: enabling the VPN on a physical device resolves `example.com` via DoH; `adb logcat` shows every query.

### Phase 2 — Engine + SQLite

- Wire `FilterEngine::build_from_files` with a bundled default `config.toml` and a small StevenBlack subset.
- SQLite writer + schema.
- Blocked queries return `NXDOMAIN`.
- **Exit criteria**: opening a Steam page shows blocked telemetry domains in `query_event`; browsing works.

### Phase 3 — UI dashboard

- Room read-only DAO on the same SQLite file, WAL mode.
- Dashboard cards + hourly bar chart + block-reason pie, sourced from SQL views.
- **Exit criteria**: dashboard reflects real traffic within 1 s of a query.

### Phase 4 — Live feed

- Ring buffer + UniFFI callback + SharedFlow.
- Live queries screen.
- Battery-saver toggle for the listener.
- **Exit criteria**: opening the app while browsing shows a scrolling feed within 100 ms of the underlying query.

### Phase 5 — Per-app statistics

- UID lookup via `ConnectivityManager.getConnectionOwnerUid`.
- Per-app screen, app icons via `PackageManager`.
- Per-app blocking rules.
- **Exit criteria**: opening a known telemetry-heavy app shows its blocked count rise in real time.

### Phase 6 — Recursive resolver mode

- Wire the recursive resolver (see [Roadmap-recursive-DNS.md](Roadmap-recursive-DNS.md)) as an alternative code path behind `mode = "recursive"`.
- Cache-size + hit-ratio panels light up.
- **Exit criteria**: switching to recursive mode in settings still resolves domains correctly; cache-hit ratio climbs above 50 % after a browsing session.

### Phase 7 — Polish

- Settings screen (retention, flush interval, upstream picker, blocklist manager).
- Export.
- Notification (foreground service) with live counters.
- APK size audit + ABI splits.

---

## Testing strategy

- **Rust unit tests**: reused as-is from `dgaard-engine`.
- **UniFFI integration tests**: a small `androidTest` (instrumented) module that spins up `Engine`, feeds it packet fixtures, asserts events land in both the callback and SQLite.
- **VPN integration**: `adb shell dumpsys connectivity` + `dig @<phone-ip>` on the local network is impractical (VPN is intra-device). Use `am instrument`-driven `HttpURLConnection` to trigger real DNS, then assert on the SQLite state.
- **Screenshot tests**: Roborazzi + Compose preview per screen, run in CI.
- **Battery**: `dumpsys batterystats` before/after 1 h of heavy browsing, gate PRs on a regression threshold.

---

## Decisions still to make

These are deferred until Phase 0/1 experience informs them. Not blockers for starting.

1. **App name** — `dgaard`, `Dgaard`, `DgaardShield`, other? Also determines Play Store listing wording.
2. **Distribution** — F-Droid only? Play Store? GitHub Releases sideload APKs? Play Store adds review friction (VPN policy) but wider reach.
3. **`minSdk`** — 29 (recommended, unlocks `getConnectionOwnerUid`) vs 26 (broader reach, requires a `/proc/net/*` fallback that is broken on modern Android).
4. **Bundled blocklists** — ship StevenBlack subset in-APK? Fetch on first run? User-supplied only?
5. **Chart library** — Vico vs Compose Charts vs custom Canvas.
6. **Update channel for blocklists** — WorkManager periodic job? Manual refresh only? Both?
7. **Crash reporting** — none (privacy stance) vs opt-in Sentry vs Firebase Crashlytics (excludes F-Droid).
8. **Multi-process** — keep VPN + UI in the same process (simpler) vs `:vpn` process (more resilient to UI crashes; complicates the ring-buffer path, would force option 2 or 3 from the IPC discussion).
9. **License** — inherit workspace license (EUPL-1.2 per `LICENCE.md`) — confirm compatibility with Play Store and F-Droid inclusion guidelines.
10. **Icon / branding** — no assets exist yet.

---

## Open risks

- **VpnService reliability**: Android OEMs (Xiaomi, Huawei, OnePlus) aggressively kill background services. Persistent notification + `FOREGROUND_SERVICE_SPECIAL_USE` mitigates but doesn't eliminate. Public issue trackers of RethinkDNS / Nebulo document the pain.
- **Recursive resolver on mobile networks**: cellular networks often block outbound port 53 to non-carrier resolvers, and NAT rebinding may kill long-lived UDP sessions. Recursive mode may work on Wi-Fi only in practice.
- **UniFFI async story**: production-grade but younger than the sync one; the recursive-mode `handle_dns_packet` async path is where friction is most likely.
- **SQLite disk pressure**: 200 queries/s sustained = ~17 M rows/day. Retention windows and aggregation tables must actually be enforced; a bug that skips the DELETE will fill the phone within days.
- **Play Store VPN policy**: the app must convince review that it uses `VpnService` only for on-device filtering. RethinkDNS-style disclosure text is the model.

---

## Cross-references

- [Roadmap-recursive-DNS.md](Roadmap-recursive-DNS.md) — recursive resolver design, feeds Mode B.
- [Roadmap-digaard.md](Roadmap-digaard.md) — DoH/DoT/DoQ client transports, reused for Mode A upstream.
- [Roadmap-refactor-monitor.md](Roadmap-refactor-monitor.md) — protocol and state store from `dgaard-monitor-core`; the SQLite schema here is a simplified relative.
- [Architecture.md](Architecture.md) — overall workspace layout.
