# Installation

## From crates.io (not available yet)

All packages are published to [crates.io](https://crates.io) and can be installed with Cargo:

```bash
cargo install dgaard
cargo install dgaard-monitor   # Linux only
cargo install adblockptimize
```

To use `dgaard-engine` as a library in your own project:

```toml
[dependencies]
dgaard-engine = "0.2"
```

## Pre-build Linux binaries (not available yet)

Pre-built binaries for Linux (musl) are available on the [Releases](../../releases) page. Each package is released independently and tagged `<package>-v<version>`.

## Quick install (Linux)

The repository ships a small installer that pulls the latest matching release
from Codeberg and drops the binary in your PATH:

```bash
# dgaard (default)
curl -fsSL https://codeberg.org/slundi/dgaard/raw/branch/master/scripts/install.sh | bash

# dgaard-monitor or adblockptimize
curl -fsSL https://codeberg.org/slundi/dgaard/raw/branch/master/scripts/install.sh \
  | bash -s -- --package dgaard-monitor

# pin a specific version / change install location
curl -fsSL https://codeberg.org/slundi/dgaard/raw/branch/master/scripts/install.sh \
  | bash -s -- --package dgaard --version 1.2.3 --install-dir /usr/local/bin
```

Linux only — `dgaard-monitor` depends on `inotify` and unix sockets, and the
release pipeline only produces musl builds for `x86_64`, `aarch64`, and
`armv7`. On macOS/Windows, install from source (see below) or grab the
matching archive from the Releases page manually.

---

## NixOS install

Will come when 1st version will be released. But a draft is [there](nix/modules) (options are not up to date yet).

---

## Building from source

```bash
git clone https://codeberg.org/slundi/dgaard
cd dgaard

# build all packages
cargo build --release

# build a specific package
cargo build --release -p dgaard
cargo build --release -p dgaard-engine
cargo build --release -p dgaard-monitor
cargo build --release -p adblockptimize
```

Cross-compilation via [`cross`](https://github.com/cross-rs/cross):

```bash
cargo install cross --git https://github.com/cross-rs/cross

cross build --release --target aarch64-unknown-linux-musl -p dgaard
cross build --release --target armv7-unknown-linux-musleabihf -p dgaard
```
