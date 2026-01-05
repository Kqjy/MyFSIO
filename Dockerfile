# syntax=docker/dockerfile:1.7
FROM python:3.12.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install build deps for any wheels that need compilation, then clean up
RUN apt-get update \ 
    && apt-get install -y --no-install-recommends build-essential \ 
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Make entrypoint executable
RUN chmod +x docker-entrypoint.sh

# Create data directory and set permissions
RUN mkdir -p /app/data \
    && useradd -m -u 1000 myfsio \ 
    && chown -R myfsio:myfsio /app

USER myfsio

EXPOSE 5000 5100
ENV APP_HOST=0.0.0.0 \
    FLASK_ENV=production \
    FLASK_DEBUG=0

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/healthz', timeout=2)"

CMD ["./docker-entrypoint.sh"]
