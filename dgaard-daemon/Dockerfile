# syntax=docker/dockerfile:1

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1-alpine AS builder

WORKDIR /build

RUN apk add --no-cache musl-dev pkgconf

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p dgaard-daemon && \
    cp target/release/dgaard-daemon /dgaard-daemon

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM alpine:3

RUN apk add --no-cache ca-certificates

COPY --from=builder /dgaard-daemon /usr/local/bin/dgaard-daemon

# The daemon creates a Unix domain socket; mount the socket directory as a volume
# so other containers (MTA, spam filter) can reach it.
# Example: -v /run/dgaard:/run/dgaard
ENTRYPOINT ["/usr/local/bin/dgaard-daemon"]
