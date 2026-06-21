# ============================================
# Judol Detector - Dockerfile
# Optimized for Raspberry Pi (ARM64/ARMv7)
# ============================================
FROM python:3.11-slim-bookworm

LABEL maintainer="Judol Detector"
LABEL description="Sistem Deteksi Link Judi Online via Pi-hole + DeepSeek LLM"

# Minimal system deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libsqlite3-0 \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r judol && useradd -r -g judol -d /app -s /sbin/nologin judol

WORKDIR /app

# Install Python deps (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY judol_detector/ ./judol_detector/

# Create data directories
RUN mkdir -p /app/data /app/reports /app/logs && \
    chown -R judol:judol /app

USER judol

# Health check - pastikan proses masih jalan
HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD python -c "import sqlite3; conn = sqlite3.connect('/app/data/judol_history.db'); conn.close()" || exit 1

# Default: jalankan daemon mode
ENTRYPOINT ["python", "-m", "judol_detector"]
CMD ["daemon"]
