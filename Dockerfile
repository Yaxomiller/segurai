# The Segurai collector and web view, packaged for a single-tenant pilot.
#
#   docker build -t segurai-collector .
#   docker run -e SEGURAI_COLLECTOR_TOKEN=... -v segurai-data:/data -p 127.0.0.1:4318:4318 segurai-collector
#
# Most deployments should use deploy/compose.yaml instead, which wires in the
# token, the organisation's public key and a persistent volume. See
# docs/PILOT_RUNBOOK.md for the whole setup.

FROM python:3.12-slim

# Don't write .pyc files into the image, and send logs straight to the console.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Only what the package needs to install - no tests, evals or local databases
# (see .dockerignore).
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install ".[collector]"

# Run as an ordinary user that owns only the data directory, never as root.
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin segurai \
    && mkdir -p /data \
    && chown segurai:segurai /data
USER segurai

# Everything the collector stores lives in /data, so mount a volume there.
VOLUME ["/data"]

# Configuration comes from the environment (the CLI reads these):
#   SEGURAI_DB               database file
#   SEGURAI_KEY              the organisation's PUBLIC key (.pub), to check signatures
#   SEGURAI_COLLECTOR_TOKEN  required: the collector refuses to listen beyond
#                            this machine without one
#   SEGURAI_HOST / SEGURAI_PORT
ENV SEGURAI_DB=/data/segurai.db \
    SEGURAI_HOST=0.0.0.0 \
    SEGURAI_PORT=4318

EXPOSE 4318

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:4318/healthz', timeout=3)"]

CMD ["segurai", "collect"]
