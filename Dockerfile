# Segurai: the dashboard, span ingest, issuer, gateway, alerts and checkpoints,
# run together by `segurai serve` from one configuration file.
#
# Use deploy/compose.yaml rather than running this by hand: it publishes the
# ports on 127.0.0.1 only, keeps the data on a volume and makes the root
# filesystem read-only. deploy/README.md has the three commands to start it.
#
#   docker build -t segurai .

FROM python:3.12-slim

LABEL org.opencontainers.image.title="Segurai" \
      org.opencontainers.image.description="Proof of who authorised each AI agent action, and whether it stayed within bounds" \
      org.opencontainers.image.source="https://github.com/Yaxomiller/segurai" \
      org.opencontainers.image.licenses="Apache-2.0"

# Don't write .pyc files (the root filesystem is read-only at run time), and
# send logs straight to the console.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Only what the package needs to install: no tests, evals or local databases
# (see .dockerignore). "server" is the dashboard, ingest and company sign-in;
# "postgres" lets the same image use a PostgreSQL database.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install ".[server,postgres]" \
    && segurai --help > /dev/null

# Run as an ordinary user that owns only the data directory, never as root.
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin segurai \
    && mkdir -p /data \
    && chown segurai:segurai /data
USER segurai

# Everything Segurai keeps lives in /data: segurai.toml, the organisation's
# key, the SQLite database (unless PostgreSQL is used) and the witness file.
VOLUME ["/data"]
WORKDIR /data

# 8700: dashboard, span ingest (/v1/traces), issuer (/v1/sessions).
# 8800: the gateway, when segurai.toml configures one.
EXPOSE 8700 8800

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8700/healthz', timeout=3)"]

ENTRYPOINT ["segurai"]
CMD ["serve", "--config", "/data/segurai.toml"]
