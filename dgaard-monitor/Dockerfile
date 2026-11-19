# syntax=docker/dockerfile:1

# Exact image versions: a floating tag (rust:1-alpine, alpine:3) changes what
# the same Dockerfile builds. Renovate proposes the bumps; keep one Alpine
# release for both stages.

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.99.0-alpine3.24 AS builder

WORKDIR /build

# build-base (gcc + make + musl-dev) is required by rusqlite's bundled feature,
# which compiles SQLite from C source via the cc crate.
# Packages are not pinned (DL3018): Alpine drops old package versions from its
# repositories, so exact pins break the build; the pinned base image already
# fixes the release branch, and apk then brings its security updates.
# hadolint ignore=DL3018
RUN apk add --no-cache build-base pkgconf

# The repository's .dockerignore keeps target/, .git/ and the docs out of the
# build context, so this copy stays small.
COPY . .

# The cache mounts keep the downloaded crates and the compiled artifacts
# (bundled SQLite included) from one build to the next, even when a source
# change invalidates the COPY layer above. --locked builds what Cargo.lock says.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked -p dgaard-monitor && \
    cp target/release/dgaard-monitor /dgaard-monitor

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM alpine:3.24.3

# A dedicated unprivileged user, and a directory it owns for the SQLite
# history. (Packages unpinned on purpose, see the build stage.)
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates && \
    addgroup -S -g 10001 dgaard-monitor && \
    adduser -S -D -H -u 10001 -G dgaard-monitor dgaard-monitor && \
    install -d -o dgaard-monitor -g dgaard-monitor -m 0750 /var/lib/dgaard-monitor

COPY --from=builder /dgaard-monitor /usr/local/bin/dgaard-monitor

VOLUME ["/var/lib/dgaard-monitor"]
USER dgaard-monitor:dgaard-monitor

# Running:
#   - Mount dgaard's stats socket and host index, e.g.
#       -v /run/dgaard:/run/dgaard:ro -v /var/dgaard:/var/dgaard:ro
#     and pass --socket/--index (or a config file) if they are not at the
#     defaults (/tmp/dgaard_stats.sock, /var/dgaard/host_mapping.bin).
#   - dgaard creates its socket with mode 0660: give the container that
#     socket's group, e.g. --group-add "$(stat -c %g /run/dgaard/stats.sock)".
#   - The monitor checks who serves the socket ([input] peer_uid).
#
# No HEALTHCHECK: in the default headless mode the monitor serves no endpoint
# to probe, and a running process is all Docker can see (use a restart
# policy). With the REST API enabled ([api] enabled = true), add one, e.g.
#   HEALTHCHECK CMD wget -q -O /dev/null http://127.0.0.1:8080/health || exit 1
#
# Default mode is headless so the container works without a TTY (the monitor
# also switches to headless by itself when stdout is not a terminal).
# Override CMD and pass -it to docker run to launch the interactive TUI.
ENTRYPOINT ["/usr/local/bin/dgaard-monitor"]
CMD ["--headless", "--db", "/var/lib/dgaard-monitor/stats.sqlite"]
