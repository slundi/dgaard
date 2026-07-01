# History & Motivations

`dgaard` name is the combination of `DNS + DGA + guard`.

Why Dgaard is a workspace with many crates instead of a single binary.

## 1. Origins

_How Dgaard started: the problem it was meant to solve, the initial constraints (OpenWrt / SME networks / heuristic filtering), and the first shape of the codebase._

I have colleagues in cyber security, and once they were talking about randomly generated domains (DGA). Since I was using the adblock inside my OpenWRT router, I noticed that DGA detection was missing. It was also an opportunity to add newly registered domains (NRD) to the blocklists — big lists that adblock was dropping. But I needed to solve the problem of loading big lists in RAM, so I used XXH3_64 hashes + bitflags instead of keeping the domain strings in memory. With this I decided to start building `dgaard` as a DNS filtering proxy that can run on my OpenWRT router.

By asking questions to AI, it suggested existing DNS-related threats (Punycode, TXT, CNAME, …), so `dgaard` now integrates many filtering and protection capabilities.

While browsing various blocklists and their different formats, I made `adblockptimize` to split what goes on the browser from what goes on the network filter. Along the way I also built `list-stats` to see what is actually inside each blocklist before deciding to ingest it.

Since I am a father with young children, when they grow up I want to protect them from harmful websites. To avoid loading millions of domains in parental-control blocklists, I made the lexical filter.

In the design of `dgaard`, I wanted to keep it focused on DNS filtering, so to avoid being too verbose I chose a Unix socket to transmit what it is doing. Naturally, a second tool appeared: `dgaard-monitor`, to display live events and statistics in a TUI.

The idea to add an MCP server came from work, where I was adding MCP routes to a Python application at that time.

One day I noticed that we had MCP but no REST (which is more common), and since the REST layer was close I added it at the same time.

`dgaard-monitor` also gained a headless mode (just to print events to the console) because it was a pain to debug the encoded feed.

Also from day-job work, I added NATS to `dgaard-monitor` and `dgaard-daemon` at the same time.

## 2. Extracting the engine — `dgaard-engine`

The filtering pipeline was pulled out of the DNS proxy into a standalone `[lib]` crate for three reasons:

- I wanted the scoring to be callable from an MTA / spam pipeline (I even wanted to host mails but I dropped the idea because of reputation constraints).
- I wanted to expose it over HTTP without forcing consumers to inherit the DNS proxy's Tokio stack.
- I wanted to trim what the DNS proxy pulls in, keeping the OpenWrt binary small.

The idea was to have a library, so since it only processes domain strings, no async was needed. Sync-friendly, no `tokio` / `hyper` / `rustls`, and no global statics — that shape was a design goal from the start of the extraction, not something I had to refactor toward. `FilterEngine` and `Config` are plain structs passed by reference, and `FilterEngine` carries its own `seed: u64` so multiple independent instances can coexist safely.

## 3. Standalone engine wrappers — `dgaard-daemon` and `dgaard-rest`

Once `dgaard-engine` was a proper library, two ready-made wrappers appeared at roughly the same time:

- **`dgaard-daemon`** — a Unix-socket sidecar. I wanted to build an MTA agent with a spam filter on top of the engine, and a Unix socket was the fastest channel for that: one newline-terminated domain in, one JSON verdict out, no HTTP overhead.
- **`dgaard-rest`** — an HTTP server exposing the same engine. It was driven by wanting an internal dashboard / web UI on top of the engine, and by the fact that a REST API is the common integration surface for pretty much everything else.

They are kept as two separate binaries (rather than one binary behind cargo features) because their dependency footprints don't overlap: `dgaard-rest` pulls in `axum` + `rustls`, `dgaard-daemon` doesn't. Keeping them apart keeps the daemon binary small — the same trade-off that motivated extracting `dgaard-engine` in the first place.

## 4. Splitting the monitor — `dgaard-monitor-core` / `-tui` / `-rest` / `-nats`

At this point `dgaard-monitor` was doing too much stuff, and that is where the split happened.

Two things tipped it over:

- I wanted the frontends to be embeddable elsewhere — the REST/WS/MCP layer or the NATS publisher can be useful outside the monitor binary.
- People wanted optional dependencies. Not every deployment wants NATS or the whole HTTP stack, and feature-gating those on top of one big crate was getting messy.

`-core` was extracted first because it was the only sane cut: protocol parsing, state aggregation, the SQLite store and the IO / forwarding layer have no UI or sink concerns of their own, and every frontend depends on them. Once `-core` was clean, each frontend (`-tui`, `-rest`, `-nats`) peeled off on top of it as a separate crate.

The umbrella `dgaard-monitor` binary still exists because it holds the headless mode (the "just print events to the console" fallback from Section 1) and there was no other obvious home for it. In the same binary, the frontends are toggled via cargo features: `tui` and `rest` are on by default, `nats` is opt-in.

## 5. Companion tools — `adblockptimize` and `list-stats`

Two tools in the workspace never touch the DNS runtime — they exist for the blocklists themselves.

- **`adblockptimize`** — introduced in Section 1. Browsing various adblock lists, I kept seeing browser cosmetic rules mixed with network-level entries. `adblockptimize` splits an input list into two deduplicated, sorted outputs: one for network filters (DNS, dnsmasq, Unbound, Pi-hole, AdGuard Home, `dgaard`) and one for browser filters (CSS/JS/HTML cosmetics).
- **`list-stats`** — I wanted to actually see what is inside each blocklist before deciding to ingest it: entry counts, plain vs wildcard vs regex, top TLDs, tokenised word frequencies. It's also the groundwork for a lexical analysis I still want to run — extracting the most-used words across lists to feed back into the lexical filter (not done yet).

Both stay in the same workspace as the DNS runtime because they share code with it — list parsers and list-format handling in particular. Splitting them into separate repos would mean publishing intermediate crates just to keep those shared bits in lockstep.

## 6. What's next

`dgaard` has grown a recursive DNS resolver — that part still needs testing. A word list for lexical analysis (the `list-stats` follow-up from Section 5) also still needs to be created.

See also: [Roadmap.md](Roadmap.md), [Roadmap-recursive-DNS.md](Roadmap-recursive-DNS.md), [Roadmap-refactor-monitor.md](Roadmap-refactor-monitor.md).
