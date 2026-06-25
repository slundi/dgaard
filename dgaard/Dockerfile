# syntax=docker/dockerfile:1

# ── Stage 1: Build ────────────────────────────────────────────────────────────
# rust:alpine defaults to x86_64-unknown-linux-musl, producing a statically
# linked binary with no glibc dependency.
FROM rust:1-alpine AS builder

WORKDIR /build

RUN apk add --no-cache musl-dev pkgconf

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p dgaard && \
    cp target/release/dgaard /dgaard

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM alpine:3

RUN apk add --no-cache ca-certificates

COPY --from=builder /dgaard /usr/local/bin/dgaard

# 5353 is the default listen port (unprivileged).
# Bind to 53 at runtime via --listen if you need the standard DNS port
# (requires NET_BIND_SERVICE capability or host networking).
EXPOSE 5353/udp
EXPOSE 5353/tcp

ENTRYPOINT ["/usr/local/bin/dgaard"]
