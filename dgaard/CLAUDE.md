# 🧠 AGENT.md: The Dgaard Intelligence Logic

This document defines the autonomous decision-making process of the Dgaard engine. It explains how the agent evaluates a DNS query from "Unknown" to "Verified" or "Malicious."

## 🤖 Agent Philosophy

Dgaard acts as a Heuristic Sentry. While traditional DNS filters are "reactive" (waiting for a list update), the Dgaard agent is "proactive"—it analyzes the mathematical and lexical structure of a domain to predict intent.

## 🔄 The Decision Loop (Per Query)

Dgaard operates on a **Stratified Inference Loop**. For every incoming packet, the agent executes the following steps in order of computational cost:
### 1. The Sanity Check (Gatekeeper)

Before any heavy lifting, the agent validates the "Physical" structure of the request.
* **Action**: Enforce `max_subdomain_depth` and `force_lowercase_ascii`.
* **Goal**: Instant drop of malformed or obvious tunneling attempts.

### 2. The Memory Match (Reflexes)

The agent checks its "Long-term Memory" (Static Lists) and "Short-term Memory" (LRU Cache).

* **Zero-Copy Lookup**: Uses `rkyv` to query millions of domains in sub-millisecond time.
* **Bloom Filter**: Provides a probabilistic "Quick No" to save CPU cycles.

### 3. Lexical Inference (The Brain)

If the domain is unknown, the agent performs active analysis:

* **Shannon Entropy**: Calculates the randomness of the string. High entropy (>4.0) suggests an Algorithmically Generated Domain (DGA).
* **N-Gram Probability**: Checks the domain against multiple language models (English, French, etc.). If a domain has a low probability in all models, it is flagged as "non-human readable."
* **Consonant Clustering**: Detects "impossible" phonetic structures (e.g., `vbx-rtz91`).

### 4. Behavioral Monitoring (Context Awareness)

The agent looks at the Client behavior, not just the domain.

* **NXDOMAIN Hunting**: If a client triggers multiple "Not Found" responses in a short window, the agent flags the client as potentially infected with a botnet scanner.
* **Tunneling Detection**: Monitors the volume of unique subdomains per minute to block DNS exfiltration.

## 🛠️ Internal State & Capabilities

| Capability | Model / Implementation | Target |
|:-----------|:-----------------------|:-------|
| **DGA Detection** | Shannon Entropy (Custom Rust Impl) | Malware C2 |
| **Phishing Defense** | Smart-IDN / Punycode Analysis | Homograph Attacks |
| **Exfiltration Block** | TXT Length & Subdomain Depth | DNS Tunneling |
| **Scaling** | Multi-threaded Tokio Runtime | High Concurrency |
| **Communication** | Postcard-encoded Unix Socket | Dashboard/TUI |

## 📡 Output Actions

Based on its inference, the agent returns one of the following to the main runtime:

* `Action::LocalResolve`: Instant success from memory.
* `Action::ProxyToUpstream`: Domain is clean; forward via UDP/DoH.
* `Action::Block(Reason)`: Execution of a block with a specific heuristic signature.

## 📈 Evolution

The Dgaard agent is designed to be Model-Agnostic. Future versions will support:

* ML-Inference: Loading lightweight .tflite models for more complex threat detection.
* DoQ Upstream: Support for DNS-over-QUIC to reduce latency in agent-to-cloud communication.

## 🛠️ Development Stack & Constraints

To maintain a footprint under 5MB and support MIPS/ARM architectures, we use a strictly curated set of crates:

### Rust crates

* **Runtime**: `tokio` (Multi-threaded with custom `Builder`).
* **CLI Parsing**: `gumdrop` (Zero-cost macro-based parsing).
* **Configuration**: `toml-span` (Low-dependency, span-aware parsing).
* **Serialization**: `rkyv` (Zero-copy) and `postcard` (Compact binary).
* **Hashing**: `xxhash-rust` (XXH3_64) for O(1) lookups.
* **DNS Protocol**: `trust-dns-proto` for low-level packet manipulation.

### 📂 File Tree Structure

The project follows a "Logic vs. Engine" separation:

```
.
├── Cargo.toml
├── dgaard.toml           # Example configuration
├── AGENT.md              # Logic & Philosophy
├── README.md             # Market-facing docs
├── config.example.toml   # Documented example/template configuration
├── src/
│   ├── main.rs           # Entry point & Runtime Builder
│   ├── config.rs         # toml-span mapping
│   ├── server/           # Networking & SO_REUSEPORT
│   │   ├── mod.rs
│   │   └── udp.rs
│   ├── filters/          # The Stratified Pipeline
│   │   ├── mod.rs
│   │   ├── gatekeeper.rs # Structure checks
│   │   ├── intelligence.rs # Entropy & N-Grams
│   │   └── static_list.rs  # rkyv/Bloom lookups
│   ├── models/           # Pre-computed N-Gram binaries
│   └── stats/            # Unix Socket & Telemetry
└── tests/                # Integration tests
```

### Development steps

After coding (implementing feature, refactoring, fixing) you must ends with the following steps:

1. format the code using `cargo fmt`
2. ensure nothing is broken by running `cargo nextest run`
3. run cargo clippy to fix warnings from modified coded
4. suggest a conventionnal commit

### 🧪 Testing Strategy

We use `cargo nextest` for a faster, parallelized test execution environment.
* **Unit Tests**: Every filter (Entropy, TLD, Structure) must have a unit test in its respective file.
* **Integration Tests**: Located in `/tests`, simulating real DNS queries against a local Dgaard instance.
* **Benchmarking**: Use `criterion` to ensure that new filters do not push the "Processing Time" over 1ms per query.

Command: `cargo nextest run`

### 📜 Contribution Rules

#### 1. Conventional Commits

We follow the Conventional Commits specification. This allows for automated changelog generation and easier auditing of the security pipeline.

* `feat`: New filter or capability.
* `fix`: Bug in DNS parsing or logic error.
* `perf`: Optimization (e.g., switching from HashSet to sorted Vec).
* `refactor`: Internal code changes with no logic impact.
* `docs`: Changes to README, AGENT, or code comments.

#### 2. No-Std & Alloc Philosophy

While we currently use std, code within the filters/ module should prioritize zero-allocation algorithms. Use bytes() instead of chars() and avoid String cloning inside the hot path.

#### 3. Binary Size Guardrail

Every PR that adds a dependency will be scrutinized for its impact on the final binary size. Dgaard must remain viable for routers with limited Flash memory.

### 🚀 Cross-Compilation

To test on target architectures (MIPS/ARM), use the `cross` tool:
`cross build --target mips-unknown-linux-musl --release`
