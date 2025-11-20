# base image
FROM rust:slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y gcc g++ libc6-dev pkg-config libssl-dev wget

WORKDIR /build
COPY rs ./rs
COPY Cargo.toml ./
RUN cargo build --release -p ic_auth_verify_server

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

# entry point
ENTRYPOINT [ "/app/ic_auth_verify_server" ]