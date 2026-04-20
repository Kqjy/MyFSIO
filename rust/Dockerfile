FROM rust:1-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config libssl-dev \
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
COPY --from=builder /build/myfsio-engine/crates/myfsio-server/templates /app/templates
COPY --from=builder /build/myfsio-engine/crates/myfsio-server/static /app/static
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

RUN chmod +x /app/docker-entrypoint.sh \
    && chown -R myfsio:myfsio /app

USER myfsio

EXPOSE 5000
EXPOSE 5100
ENV HOST=0.0.0.0 \
    PORT=5000 \
    UI_PORT=5100 \
    STORAGE_ROOT=/app/data \
    TEMPLATES_DIR=/app/templates \
    STATIC_DIR=/app/static \
    RUST_LOG=info

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS "http://localhost:${PORT}/myfsio/health" || exit 1

CMD ["/app/docker-entrypoint.sh"]
