# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM rust:1.85-bookworm AS builder

WORKDIR /workspace

# chadex depends on the local Contrix SDK by path. Build with:
# docker build --build-context contrix-rust-sdk=../contrix-rust-sdk -t chadex .
COPY --from=contrix-rust-sdk . ./contrix-rust-sdk
COPY . ./chadex

WORKDIR /workspace/chadex

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/chadex/target \
    cargo build --locked --release && \
    cp target/release/chadex /usr/local/bin/chadex

FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/chadex /usr/local/bin/chadex

USER 10001:10001
WORKDIR /var/lib/chadex

ENV CHADEX_BIND=0.0.0.0:7781
EXPOSE 7781

ENTRYPOINT ["/usr/local/bin/chadex"]
