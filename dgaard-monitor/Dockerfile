# syntax=docker/dockerfile:1

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1-alpine AS builder

WORKDIR /build

# build-base (gcc + make + musl-dev) is required by rusqlite's bundled feature,
# which compiles SQLite from C source via the cc crate.
RUN apk add --no-cache build-base pkgconf

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p dgaard-monitor && \
    cp target/release/dgaard-monitor /dgaard-monitor

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM alpine:3

RUN apk add --no-cache ca-certificates

COPY --from=builder /dgaard-monitor /usr/local/bin/dgaard-monitor

# The monitor connects to dgaard's Unix socket (mount it as a volume at runtime).
# Default mode is headless so the container works without a TTY.
# Override CMD with [] and pass -it to docker run to launch the interactive TUI.
ENTRYPOINT ["/usr/local/bin/dgaard-monitor"]
CMD ["--headless"]
