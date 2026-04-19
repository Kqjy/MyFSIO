FROM python:3.14.3-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.cargo/bin:${PATH}"

RUN pip install --no-cache-dir maturin

COPY myfsio_core ./myfsio_core
RUN cd myfsio_core \
    && maturin build --release --out /wheels


FROM python:3.14.3-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --from=builder /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

COPY app ./app
COPY templates ./templates
COPY static ./static
COPY run.py ./
COPY docker-entrypoint.sh ./

RUN chmod +x docker-entrypoint.sh \
    && mkdir -p /app/data \
    && useradd -m -u 1000 myfsio \
    && chown -R myfsio:myfsio /app

USER myfsio

EXPOSE 5000 5100
ENV APP_HOST=0.0.0.0 \
    FLASK_ENV=production \
    FLASK_DEBUG=0

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/myfsio/health', timeout=2)"

CMD ["./docker-entrypoint.sh"]
