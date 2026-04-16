# Agent Instructions: Dgaard Implementation Details

You are assisting in the development of **Dgaard**, a Rust-based DNS proxy. Adhere to these architectural constraints to ensure performance on low-resource hardware.

## 🏗️ Architectural Principles
- **Memory First:** Avoid `clone()` on large strings. Use `Arc<str>` or `Cow<str>`.
- **Fail Fast:** The matching order must always be: 
  `Whitelist -> Cache -> Exact Match -> Suffix Match -> Heuristics -> Regex`.
- **Async Non-Blocking:** Use `tokio` with the `rt` (basic scheduler) feature to keep the binary small.
- **No Heavy Crates:** Avoid `serde_json` or heavy web frameworks. Stick to `toml`, `bincode`, and `nom` for parsing.

## 🧩 Data Structures
- **Exact Matches:** Use `HashSet<u64>` (storing xxh64 hashes) or a `BloomFilter`. Do not store raw strings for blocklists.
- **Wildcards:** Store reversed domains in an `FST` or a `Trie` for efficient suffix matching.
- **Stats:** Use `#[repr(packed)]` structs for `StatEvent` to ensure predictable binary layout over Unix Sockets.

## 🚦 Logic Rules
- **Entropy:** Use the Shannon Entropy formula. Only run on strings > 8 characters.
- **NRD:** Treat the NRD list as a static Bloom Filter updated via a background thread or SIGHUP.
- **DNS Wire Format:** Use `trust-dns-proto` for packet manipulation, but prioritize zero-copy where possible.

### 🛡️ Deep Packet Inspection (DPI) Lite
Dgaard doesn't just look at names; it inspects the payload:
- **TXT Entropy:** Scans TXT records for high-entropy payloads (Exfiltration/C2).
- **CNAME Unmasking:** Follows CNAME chains to block hidden trackers.
- **Rebinding Defense:** Rejects public domain queries resolving to private IP ranges.
- **Null-Type Blocking:** Drops DNS `NULL` type queries used for data smuggling.

## 🛠️ Target Environment
- **OS:** OpenWrt (Linux kernel)
- **Arch:** MIPS/ARM (Big-endian vs Little-endian awareness is crucial for xxh64 hashes).
- **RAM Target:** < 20MB for 100k blocked domains.