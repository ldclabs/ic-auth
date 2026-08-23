# ic_auth_verify_server — static musl binary, no runtime dependencies.
# Keep the image minimal: one binary, no shell, no state.
#
# The service verifies signatures locally and never opens an outbound
# connection, so it needs no CA bundle, no OpenSSL, and no DNS resolver
# (SOCKET_ADDR is parsed as a numeric SocketAddr). That leaves nothing for a
# base image to provide.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /build
# Workspace manifests first, then the crates they reference.
COPY Cargo.toml Cargo.lock ./
COPY rs ./rs
# --locked: a Cargo.toml/Cargo.lock skew must fail the build, not silently
# re-resolve deps, so the image stays reproducible from the commit.
RUN cargo build --release --locked -p ic_auth_verify_server

FROM scratch
COPY --from=build /build/target/release/ic_auth_verify_server /ic_auth_verify_server
# The binary defaults to 127.0.0.1, which is unreachable from outside the
# container; bind all interfaces so `docker run -p 8080:8080` just works.
ENV SOCKET_ADDR=0.0.0.0:8080
# Numeric UID: `scratch` has no /etc/passwd to resolve a name against.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/ic_auth_verify_server"]
