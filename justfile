# --- Variables ---
binary_name := "MY_PROJECT" # Change this to your project name

# --- Development ---

# Build the project in debug mode
build:
    cargo build

# Run the project
run *args:
    cargo run -- {{args}}

# Watch for changes and run (requires cargo-watch)
watch:
    cargo watch -x run

# --- Quality Control ---

# Run all tests
test:
    cargo nextest run

# Run a full health check (Vulnerabilities, Unused Deps, Licenses)
health-check:
    cargo audit
    cargo machete
    cargo deny check

# Run clippy with strict warnings
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Format all code
fmt:
    cargo fmt --all
    dprint fmt
    find . -name '*.nix' -not -path './target/*' | xargs --no-run-if-empty nixfmt
    yamlfmt -exclude "target/**" .

# Run all pre-commit hooks manually on all files
check:
    prek run --all-files

# Force update hooks
update-hooks:
    prek autoupdate

# Run gitleaks to scan for secrets
scan-secrets:
    gitleaks detect --verbose --redact

# Generate lcov.info for editor coverage display (vscode-coverage-gutters)
coverage:
    cargo llvm-cov --lcov --output-path lcov.info

# Check that overall line coverage meets the 80% threshold
# BASE is accepted for interface compatibility with CI (e.g.: just coverage-check master)
coverage-check BASE="master":
    cargo build -p dgaard-monitor
    cargo llvm-cov --lcov --output-path lcov.info
    cargo llvm-cov report --fail-under-lines 80

# --- Operational ---

# Verify the compiled-in root-server hints still match IANA's published
# `named.root`. Run on a weekly cron; fails CI on drift so the operator
# regenerates ROOT_HINTS_V4/V6 in dgaard/src/dns/recursive.rs.
# See CONTRIBUTING.md for the manual regeneration procedure.
check-root-hints:
    ./scripts/check-root-hints.sh

# --- Cleanup ---

# Clean build artifacts
clean:
    cargo clean

# --- CI ---

# Check dgaard-monitor compiles for all feature combinations
check-features:
    cargo check -p dgaard-monitor
    cargo check -p dgaard-monitor --no-default-features
    cargo check -p dgaard-monitor --features nats
    cargo check -p dgaard-monitor --all-features
    @echo "All feature combinations OK"

# Run the complete CI pipeline (use this when already inside `nix develop`)
ci-all: fmt lint test check-features health-check scan-secrets

# Run the complete CI pipeline via Nix devshell — no docker/podman needed
# Equivalent to what Woodpecker and Forgejo Actions run in containers
ci-local:
    nix develop --command just fmt
    nix develop --command just lint
    nix develop --command just test
    nix develop --command just health-check
    nix develop --command just scan-secrets
    @echo "All CI checks passed!"

# Run a quick subset (format + lint + test) — fast feedback loop
ci: fmt lint test
    @echo "Quick checks passed!"

# --- Changelog ---

# Generate or update CHANGELOG.md from conventional commits
changelog:
    git cliff -o CHANGELOG.md
    @echo "CHANGELOG.md updated — commit it before tagging"

# Preview changelog entries for commits not yet in a release
changelog-unreleased:
    git cliff --unreleased

# --- Release ---

# Create and push an annotated release tag, triggering the release workflow
# Usage: just tag v1.2.3
tag VERSION:
    git tag -a {{VERSION}} -m "Release {{VERSION}}"
    git push origin {{VERSION}}
    @echo "Pushed tag {{VERSION}} — release workflow will start on Codeberg"

# Build a release binary for the current platform
build-release:
    cargo build --release

# Build a release binary for a specific cross-compilation target
# Requires `cross` in your PATH (included in flake.nix devShell)
# Usage: just build-release-cross aarch64-unknown-linux-gnu
build-release-cross TARGET:
    cross build --release --target {{TARGET}}

# Cross-compile dgaard for aarch64-musl (OpenWrt on MediaTek/Filogic routers
# such as GL-MT6000 Flint 2, Banana Pi R3). Output is at ./result/bin/dgaard.
nix-release-build:
    nix build .#dgaard-aarch64-musl
    @echo "→ dgaard (aarch64-musl): $(readlink -f result)/bin/dgaard"

# Cross-compile dgaard-monitor for aarch64-musl. Output at ./result/bin/dgaard-monitor.
nix-release-build-monitor:
    nix build .#dgaard-monitor-aarch64-musl -o result-monitor
    @echo "→ dgaard-monitor (aarch64-musl): $(readlink -f result-monitor)/bin/dgaard-monitor"

# Build both dgaard and dgaard-monitor for aarch64-musl
nix-release-build-all: nix-release-build nix-release-build-monitor
