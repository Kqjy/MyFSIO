FROM rust:1-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY myfsio-engine ./myfsio-engine

RUN cd myfsio-engine \
    && cargo build --release --bin myfsio-server \
    && strip target/release/myfsio-server


FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app/data \
    && useradd -m -u 1000 myfsio \
    && chown -R myfsio:myfsio /app

COPY --from=builder /build/myfsio-engine/target/release/myfsio-server /usr/local/bin/myfsio-server
COPY --from=builder /build/myfsio-engine/templates /app/templates
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

RUN chmod +x /app/docker-entrypoint.sh \
    && chown -R myfsio:myfsio /app

USER myfsio

EXPOSE 5000
ENV HOST=0.0.0.0 \
    PORT=5000 \
    STORAGE_ROOT=/app/data \
    RUST_LOG=info

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS "http://localhost:${PORT}/myfsio/health" || exit 1

CMD ["/app/docker-entrypoint.sh"]
