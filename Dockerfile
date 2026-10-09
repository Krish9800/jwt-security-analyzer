# Multi-stage rootless production Dockerfile for JWT Security Analyzer
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip build wheel \
    && pip install --no-cache-dir --prefix=/build/deps .

# Runtime Stage
FROM python:3.12-slim AS runner

WORKDIR /app

# Create non-privileged user and group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/sh -M appuser

COPY --from=builder /build/deps /usr/local
COPY pyproject.toml README.md ./
COPY src/ ./src/

USER 10001:10001

EXPOSE 8082

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8082/health')" || exit 1

ENTRYPOINT ["uvicorn", "jwtsec.api.app:app", "--host", "0.0.0.0", "--port", "8082"]
