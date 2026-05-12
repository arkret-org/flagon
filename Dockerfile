# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM rust:1.88-bookworm AS builder

WORKDIR /workspace

# teabay depends on the local Contrix SDK by path. Build with:
# docker build --build-context contrix-rust-sdk=../contrix-rust-sdk -t teabay .
COPY --from=contrix-rust-sdk . ./contrix-rust-sdk
COPY . ./teabay

WORKDIR /workspace/teabay

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/teabay/target \
    cargo build --locked --release -p server && \
    cp target/release/server /usr/local/bin/server

FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/server /usr/local/bin/server

USER 10001:10001
WORKDIR /var/lib/teabay

ENV TEABAY_BIND=0.0.0.0:7781
EXPOSE 7781

ENTRYPOINT ["/usr/local/bin/server"]
