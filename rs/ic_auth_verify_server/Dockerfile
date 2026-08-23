# base image
FROM rust:slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y gcc g++ libc6-dev pkg-config libssl-dev wget

WORKDIR /build
COPY rs ./rs
# Cargo.lock must be copied too: without it cargo re-resolves every dependency
# at image build time, so the published image is not reproducible from a commit.
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release --locked -p ic_auth_verify_server

FROM debian:bookworm-slim AS runtime

# install dependency tools
RUN apt-get update \
    && apt-get install -y net-tools iptables iproute2 ca-certificates tzdata openssl \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# working directory
WORKDIR /app

# your custom setup goes here
COPY --from=builder /build/target/release/ic_auth_verify_server ./ic_auth_verify_server

EXPOSE 8080
# entry point
ENTRYPOINT [ "/app/ic_auth_verify_server" ]