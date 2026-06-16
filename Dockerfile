# Build a fully static binary with musl, then ship it in an empty image.
FROM rust:1.83-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# Prepare a writable data dir owned by the unprivileged user.
RUN mkdir -p /data && chown 65534:65534 /data

FROM scratch
COPY --from=build /app/target/release/oauth-shim /oauth-shim
COPY --from=build --chown=65534:65534 /data /data
USER 65534:65534
ENV DB_PATH=/data/shim.db \
    LISTEN_ADDR=0.0.0.0:8080
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/oauth-shim"]
