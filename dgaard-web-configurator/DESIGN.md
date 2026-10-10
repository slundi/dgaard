# dgaard-web-configurator — design

A dependency-free, static web page that generates `config.toml` (dgaard engine) and
`dgaard-monitor.toml` (telemetry agent). No server, no framework, no CDN: plain HTML,
CSS custom properties, and vanilla ES modules.

## 1. Goals and non-goals

**Goals**

- Produce a valid `config.toml` / `dgaard-monitor.toml` without reading 638 lines of TOML.
- Import an existing config file and edit it (round-trip of _values_, not of user comments).
- Refuse to emit a file the Rust parser would reject — mirror `Config::validate()` in the browser.
- Work offline, including from `file://`, and on a static host (Codeberg/GitHub Pages).
- system / light / dark theme, consistent with the existing monitor SPA.
- Persist drafts and named profiles in `localStorage`.

**Non-goals**

- Pushing config to a running daemon (no network calls at all; CSP-friendly).
- Preserving hand-written comments across import → export.
- Editing blocklist _contents_ (only the list of paths/URLs).

## 2. The hard part: the schema is big

The engine config exposes **~109 scalar keys across 24 tables**, plus two array-of-tables
(`[[overrides]]`, `[[security.custom_flags]]`). The monitor adds **36 keys across 10 tables**.
Hand-writing ~145 `<input>` elements plus their serialisers, validators, defaults and help
text is unmaintainable and will drift from the Rust code within one release.

**Decision: the page is schema-driven.** One JS object literal per config file describes every
key; generic code turns that into DOM, into TOML, and into validation. Adding a key to dgaard
then means adding one object entry here, not touching four files.

The schema is transcribed from `dgaard-engine/src/config/parser.rs` (`parse_*` functions) and
the `Default` impls in `dgaard-engine/src/config/model.rs` — **not** from `config.example.toml`,
which has drifted (see §10).

### Schema entry shape

```js
// js/schema/engine.js
export const ENGINE_SCHEMA = {
  file: "config.toml",
  sections: [
    {
      path: "server",                       // TOML table path
      title: "Server",
      doc: "Listener, ACL and pipeline order.",
      fields: [
        {
          key: "listen_addr",
          type: "socketaddr",               // widget + validator selector
          default: "127.0.0.1:53",          // must match the Rust Default impl
          doc: "Address and port the proxy listens on (53 in production).",
          placeholder: "192.168.1.1:53",
        },
        {
          key: "mode",
          type: "enum",
          values: ["forwarder", "recursive"],   // exactly what parse_server accepts
          default: "forwarder",
          doc: "…",
        },
        {
          key: "pipeline",
          type: "ordered-enum-list",
          values: ["Whitelist", "HotCache", "StaticBlock",
                   "SuffixMatch", "Heuristics", "Upstream"],
          default: ["Whitelist", "HotCache", "StaticBlock",
                    "SuffixMatch", "Heuristics", "Upstream"],
          doc: "…",
        },
        {
          key: "metrics_listen",
          type: "socketaddr",
          optional: true,                   // Option<String> → emitted commented-out when unset
          default: null,
          doc: "…",
        },
      ],
    },
    { path: "server.runtime", /* … */ },
    { path: "security.custom_flags", repeatable: true, /* [[array of tables]] */ },
  ],
};
```

### Field types → widget + validator

| `type`              | Widget                         | Validation                                            | Used by                                              |
| ------------------- | ------------------------------ | ----------------------------------------------------- | ---------------------------------------------------- |
| `bool`              | switch                         | —                                                     | ~30 `enabled` flags                                  |
| `int`               | `<input type=number>`          | range from `rust: "u8"\|"u16"\|"u32"\|"u64"\|"usize"` | thresholds, ports, sizes                             |
| `float`             | number, `step`                 | optional `min`/`max`                                  | `entropy_threshold`, `beaconing_cov_threshold`       |
| `string`            | text                           | optional `pattern`                                    | `token`, `template`                                  |
| `path`              | text + monospace               | non-empty unless `emptyDisables`                      | `*_path`, `db`, `socket`                             |
| `socketaddr`        | text                           | `ip:port` / `[v6]:port`                               | `listen_addr`, `metrics_listen`, `forwarder.servers` |
| `enum`              | `<select>`                     | value ∈ `values`                                      | `mode`, `idn.mode`, `dnssec.action`, `format`, …     |
| `string-list`       | chip editor (add/remove)       | per-item validator                                    | keywords, countries, scripts, languages              |
| `tld-list`          | chip editor                    | lowercase, no leading dot                             | `tld.*`, `extra_local_tlds`                          |
| `cidr-list`         | chip editor                    | IPv4/IPv6 CIDR                                        | `allowed_networks`, `blocked_ranges`                 |
| `source-list`       | one row per entry, reorderable | URL or absolute path                                  | `blacklists`, `whitelists`, `ngram_models`           |
| `int-list`          | chip editor + named presets    | 0–65535                                               | `qtype_warden.blocked_types`                         |
| `ordered-enum-list` | checkbox list with ↑/↓         | no duplicates                                         | `server.pipeline`                                    |
| `worker-threads`    | radio `auto` \| number         | `"auto"` or integer ≥ 1                               | `server.runtime.worker_threads`                      |
| `repeatable`        | sub-form, add/remove card      | per-entry schema                                      | `[[overrides]]`, `[[security.custom_flags]]`         |

Eleven widget factories cover all ~145 fields. `optional: true` wraps any widget in an
"unset / set" checkbox so `Option<T>` keys round-trip faithfully.

## 3. State model

State is a **sparse diff against the defaults**, not a full config object:

```js
{ schemaVersion: 1,
  engine:  { "server.listen_addr": "192.168.1.1:53",
             "security.lexical.banned_keywords": ["casino", "porn"] },
  monitor: { "web.enabled": true } }
```

Why sparse:

- it _is_ the minimal-output mode — no diffing step at export time;
- drafts stay a few hundred bytes in `localStorage`;
- a dgaard release that changes a default propagates automatically to untouched keys;
- "modified" indicators and per-field **Reset to default** are a key-presence check.

Array-of-tables entries are stored under their own key as arrays of plain objects
(`"overrides": [{domain, to}, …]`).

Single source of truth; the DOM is never read during export. `input`/`change` handlers write
into the store, the store notifies subscribers (preview pane, validation banner, nav badges).

## 4. Module layout

```
dgaard-web-configurator/
├── index.html                 # shell: header, tabs, nav, form host, preview drawer
├── css/
│   └── style.css              # same token names as dgaard-monitor-rest/assets/style.css
├── js/
│   ├── main.js                # bootstrap, tab routing, keyboard, wiring
│   ├── theme.js               # system/light/dark cycle
│   ├── store.js               # sparse state, subscribe(), localStorage drafts + profiles
│   ├── widgets.js             # type → element factory (11 factories)
│   ├── render.js              # schema → DOM, two-way binding to store
│   ├── validate.js            # per-field + cross-field rules, severity levels
│   ├── toml-emit.js           # state → TOML (annotated | minimal)
│   ├── toml-parse.js          # TOML subset → state
│   ├── presets.js             # OpenWrt / desktop / parental-control / hardened patches
│   └── schema/
│       ├── engine.js
│       └── monitor.js
├── dist/
│   └── dgaard-configurator.html   # generated: single self-contained file
├── scripts/build.sh           # inlines css + modules into dist/ (no bundler)
├── tests/                     # node --test, no deps
│   ├── toml-roundtrip.test.js
│   ├── schema-defaults.test.js
│   └── validate.test.js
└── README.md
```

ES modules during development (`just configurator-serve`); `scripts/build.sh` concatenates the
modules in dependency order into one `<script>` and inlines the CSS, producing a single
`dist/dgaard-configurator.html` that opens from `file://`. The build is `cat` + `sed`, ~40 lines
of POSIX shell — no npm, nothing to audit.

## 5. TOML emission

Two modes, toggled in the preview header; mode is remembered per profile.

**Annotated** (default) — regenerates the shape of today's `config.example.toml`: section banner
comments, the `doc` string of each field as a `#` comment, every key written explicitly, optional
keys that are unset emitted commented-out with their default:

```toml
# -----------------------------------------------------------------------------
# [security.scoring] — suspicion score thresholds
# -----------------------------------------------------------------------------
[security.scoring]
# Score at or above which a domain is considered malicious and blocked.
blocking_threshold = 10

# Optional cache TTL floor in seconds…
# min_ttl_floor_secs = 30
```

**Minimal** — only keys present in the sparse state, with their section headers; no comments.
Typically 10–30 lines. This is the OpenWrt / `diff`-friendly form.

Emission rules: strings always basic-quoted with `\` and `"` escaped; floats always carry a
decimal point (`4.0`, never `4` — `get_float` accepts integers, but the file should read as a
float); arrays of more than three items or longer than 80 columns break one item per line with a
trailing comma; `[[array of tables]]` entries emitted in order after their parent section.
Section order is the schema order, which is the example file's order, so `diff` against an
existing deployment stays readable.

## 6. TOML import

A ~200-line recursive-descent parser for the subset both files use:

supported — comments, `[table]`, `[a.b.c]`, `[[array of tables]]`, basic strings (with escapes),
literal strings, integers (incl. `_` separators), floats, booleans, arrays (nested, multi-line,
trailing commas).
unsupported (rejected with a clear message, not silently) — inline tables `{}`, datetimes,
dotted keys outside a header (`a.b = 1`).

Import flow: drop a file / paste text / pick a file → parse → map each `table.key` onto the
schema → only keys that differ from the default enter the state.

Unknown keys are **not dropped**. They land in an "Unrecognised keys" panel with three choices:
keep as-is (re-emitted verbatim at the end of the file), discard, or — when the key matches a
known rename — one-click migrate. Seed migrations: `[upstream]` → `[forwarder]` (the parser
rejects `[upstream]` outright today), and the stray `[recursive].timeout_ms` /
`[recursive].use_0x20_randomization` → `[forwarder]` (see §10). This is what turns the page from
a generator into an upgrade assistant.

## 7. Validation

Three severities, shown inline on the field, counted in the nav, summarised in a banner:

- **error** — the Rust parser or `validate()` would reject this. Export stays available but the
  Download button carries a warning (never silently blocked; the user may be editing toward a
  target).
- **warning** — accepted but almost certainly not what was meant.
- **info** — a documented foot-gun.

Rules mirrored from the Rust side:

| Rule                                                                                     | Severity | Source                                   |
| ---------------------------------------------------------------------------------------- | -------- | ---------------------------------------- |
| `forwarder.servers[]`, `server.metrics_listen` parse as a socket address                 | error    | `Config::validate`                       |
| `asn_filter.blocked_ranges[]` are valid CIDR (when the filter is enabled)                | error    | `Config::validate`                       |
| `idn.mode != "Off"` requires `block_idn = false` **and** `force_lowercase_ascii = false` | error    | `Config::validate`                       |
| TLD entries lowercase and without a leading dot                                          | error    | `get_tld_array`                          |
| `custom_flags[].bit` ∈ 16–31, unique, ≤ 16 entries; `bit` and `code` required            | error    | `parse_custom_flags`                     |
| `overrides[].to` is a valid IP; `domain` required                                        | error    | `parse_overrides`                        |
| enum values restricted to the exact strings the parser accepts                           | error    | all `parse_*`                            |
| integer in range for its Rust type; `worker_threads ≥ 1`                                 | error    | `get_typed_integer`                      |
| `geo_ip.enabled = true` needs a build with `--features geoip`                            | warning  | `Config::validate` (`cfg(not(geoip))`)   |
| `pipeline` missing `Upstream` → nothing ever resolves; duplicate steps                   | warning  | pipeline semantics                       |
| `mode = "recursive"` → `[forwarder]` is dead config (and vice-versa for `[recursive]`)   | info     | `ResolutionMode`                         |
| `suspicious ≤ highly_suspicious ≤ blocking` thresholds                                   | warning  | `ScoringConfig` semantics                |
| `drop_entries_hard_blocked_at_load = true` can silently un-block listed domains          | warning  | the ⚠ block in `config.example.toml:162` |
| `use_ngram_model = true` + `ngram_use_embedded = false` + empty `ngram_models`           | warning  | `IntelligenceConfig`                     |
| `lexical.enabled = true` with empty `banned_keywords`                                    | info     | no-op filter                             |

Monitor-specific:

| Rule                                                                         | Severity |
| ---------------------------------------------------------------------------- | -------- |
| `api`/`websocket`/`mcp`/`web` ports must be distinct when enabled            | error    |
| `server.token = "changeme"` while a module is enabled on a non-loopback bind | warning  |
| `forwarding.filter[]` ∈ Allowed/Proxied/Blocked/Suspicious/HighlySuspicious  | error    |
| `forwarding.format = "template"` with `{placeholders}` not in the known set  | warning  |
| `forward_url` is `http://` rather than `https://`                            | info     |

**Cross-file rules** (the reason both configs live on one page):

| Engine key                 | must equal | Monitor key    | Severity |
| -------------------------- | ---------- | -------------- | -------- |
| `server.stats_socket_path` | =          | `input.socket` | error    |
| `sources.host_index_path`  | =          | `input.index`  | error    |

Plus an info nudge: set `monitor.input.engine_config_path` when `[[security.custom_flags]]` is
non-empty, otherwise custom bits render as `CUSTOM_BIT_<n>` in the TUI. A one-click
"sync from engine tab" fixes each mismatch.

## 8. Theme and persistence

Theme reuses the monitor SPA's convention verbatim so the two UIs stay coherent:
dark tokens on `:root`, `@media (prefers-color-scheme: light)` for the system default,
`[data-theme="light"]` / `[data-theme="dark"]` to force, and the same inline pre-paint script in
`<head>` reading `localStorage['dgaard-theme']` to avoid a flash. The header control cycles
System → Light → Dark.

`localStorage` keys, all namespaced except the shared theme:

| Key                   | Contents                                        |
| --------------------- | ----------------------------------------------- |
| `dgaard-theme`        | `system` \| `light` \| `dark` (shared with SPA) |
| `dgaard-cfg:draft`    | current sparse state, debounced 400 ms          |
| `dgaard-cfg:profiles` | `{ [name]: { engine, monitor, savedAt } }`      |
| `dgaard-cfg:ui`       | active tab, output mode, collapsed sections     |

Every blob carries `schemaVersion`. On a version mismatch the draft is kept and a banner offers
migrate-or-discard — never a silent reset of someone's work. Profiles can be exported to / imported
from a `.json` file so a config survives a browser profile wipe.

## 9. Presets

Presets are sparse patches applied over the current state behind a confirm dialog that lists what
will change:

- **OpenWrt / low RAM** — `worker_threads = 1`, `stack_size = 2 MiB`,
  `max_concurrent_queries = 256`, `cache.max_entries = 2000`, embedded n-grams, trimmed lists.
- **Desktop / server** — `worker_threads = "auto"`, 8 MiB stacks, 50 k cache entries, prefetch on.
- **Parental control** — `security.lexical` on with a keyword starter set + `suspicious_tlds`
  (cf. `docs/Parental-control.md`).
- **Hardened** — DNSSEC on, qtype warden, rebinding shield + PTR leak block, special-use
  isolation, tunneling detection tightened, scoring thresholds lowered.

## 10. Drift found between `config.example.toml` and the parser

Found while transcribing the schema; worth fixing in the repo independently of this page, and the
importer's migration rules will cover the first two for existing users.

1. **`config.example.toml:266` `timeout_ms` and `:273` `use_0x20_randomization` sit inside
   `[recursive]`** — `parse_recursive` ignores both. They are `[forwarder]` keys
   (`parser.rs:817-822`). Anyone who tuned them there has been running the 2000 ms / `true`
   defaults.
2. **`[security.inbound]` (`config.example.toml:188-205`) is not parsed at all** — there is no
   `parse_inbound`, and `parse_security` never looks for an `inbound` table. All five keys
   (`enabled`, `max_txt_entropy`, `unmask_cname_cloaking`, `block_private_ip_in_public_res`,
   `forbidden_qtypes`) are silently dead. The live equivalent of `forbidden_qtypes` is
   `[security.qtype_warden].blocked_types`, which takes numeric DNS types (`[10, 13, 255]`).
3. **Two real sections are undocumented in the example file**: `[security.qtype_warden]` and
   `[[security.custom_flags]]`.
4. **Defaults drift** between the example file and the `Default` impls:
   `consonant_ratio_threshold` 0.7 vs 0.6, `server.runtime.stack_size` 8388608 vs 2097152,
   `sources.reload_timeout_secs` 30 vs 15, `security.lexical.banned_keywords` four entries vs
   empty, `server.stats_socket_path` and `sources.*` paths.
5. **Monitor example omits** `forwarding.format` (`template` | `json` | `syslog` | `cef` |
   `elasticsearch`) and `input.engine_config_path`.

Because the schema encodes both the doc text and the true defaults, a later
`just gen-config-examples` can regenerate both example files from it in annotated mode — making
drift structurally impossible. Proposed as a follow-up, not part of v1.

## 11. Tooling integration

**justfile**

```just
# --- Web configurator ---

# Serve the configurator at http://127.0.0.1:8000 (ES modules need HTTP, not file://)
configurator-serve:
    python3 -m http.server 8000 --directory dgaard-web-configurator

# Build the single self-contained dgaard-configurator.html (works from file://)
configurator-build:
    ./dgaard-web-configurator/scripts/build.sh

# Run the configurator unit tests (node --test, no npm dependencies)
configurator-test:
    node --test dgaard-web-configurator/tests/

# Format + lint the configurator sources
configurator-lint:
    biome check dgaard-web-configurator/js dgaard-web-configurator/tests
```

`fmt` gains `biome format --write`, `ci-all` gains `configurator-test configurator-lint`, and
`configurator-build` runs before packaging so `dist/` ships with releases.

**flake.nix** — `devShells.default.buildInputs` gains `nodejs_22` (tests only; the page itself
needs no runtime) and `biome` (format + lint for JS/CSS). `python3` is already available via the
Nix stdenv but should be listed explicitly since `configurator-serve` depends on it.
Optionally `packages.dgaard-configurator` as a `runCommand` producing the built single file, so
`nix build .#dgaard-configurator` yields a releasable artifact.

**dprint** does not currently handle JS/CSS (`includes: **/*.{json,toml,md}`); biome covers them
instead rather than adding two more wasm plugins.

**.woodpecker** — one extra step running `just configurator-test configurator-lint`.

## 12. Testing

`node --test`, zero dependencies, running on the same ES modules the page loads:

1. **schema ↔ Rust defaults** — every `default` in the schema matches the `Default` impl. A
   generator script parses `model.rs` and emits a fixture, so a changed Rust default fails CI
   instead of drifting.
2. **emit → re-import → emit is a fixed point**, for the default state, a fully-populated state,
   and a randomised sparse state.
3. **import of the shipped example files** — `config.example.toml` and
   `dgaard-monitor.example.toml` import with zero unrecognised keys (this test fails today
   because of §10.1/§10.2, which is exactly the signal wanted).
4. **validator rules** — one positive and one negative case per rule in §7.
5. **annotated output parses** — a smoke test feeding generated output back through the importer.

A Rust-side integration test (`dgaard/tests/config_test.rs`) can additionally assert that a
checked-in golden file produced by the generator parses and validates in the real parser — the
only way to prove the browser and the daemon agree.

## 13. Build order

1. `store.js`, `theme.js`, shell `index.html` + `style.css` — tabs, theme, empty form host.
2. `widgets.js` + `render.js` + `schema/monitor.js` (36 keys) — smallest real schema, exercises
   every widget type except `repeatable` and `ordered-enum-list`.
3. `toml-emit.js` both modes + preview/copy/download.
4. `schema/engine.js` (~109 keys + 2 repeatables) — the bulk of the transcription work.
5. `validate.js` including the cross-file rules.
6. `toml-parse.js` + import UI + unknown-key migrations.
7. `presets.js`, profile management, export/import of profiles.
8. `scripts/build.sh`, justfile + flake.nix + CI wiring, tests.

Steps 1–4 already give a usable generator; 5–8 are what make it trustworthy.
