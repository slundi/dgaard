# syntax=docker/dockerfile:1

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1-alpine AS builder

WORKDIR /build

RUN apk add --no-cache musl-dev pkgconf

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p dgaard-rest && \
    cp target/release/dgaard-rest /dgaard-rest

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM alpine:3

RUN apk add --no-cache ca-certificates

COPY --from=builder /dgaard-rest /usr/local/bin/dgaard-rest

EXPOSE 8080/tcp

ENTRYPOINT ["/usr/local/bin/dgaard-rest"]
