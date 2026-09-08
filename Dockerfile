FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

# Install project dependencies
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy application source code and scripts
COPY app/ ./app/
COPY scripts/ ./scripts/

# Create startup entrypoint that automatically seeds SpiceDB and starts Uvicorn
RUN printf '#!/bin/sh\n\
echo "Starting Zero-Trust Gateway..."\n\
python scripts/setup_spicedb.py\n\
exec uvicorn app.gateway.main:app --host 0.0.0.0 --port 8000\n\
' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV SPICEDB_ENDPOINT=spicedb:50051
ENV REDIS_URL=redis://redis:6379/0

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
