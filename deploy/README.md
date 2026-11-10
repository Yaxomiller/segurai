# Deploying Segurai with Docker

One container runs everything `segurai serve` runs:

- the dashboard, with sign-in;
- span ingest and the issuer;
- the gateway, if configured;
- alerts and signed checkpoints.

Everything it keeps lives on one volume, `/data`. You need Docker with the compose plugin.

## SQLite (the simplest)

```bash
export SEGURAI_INGEST_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose -f deploy/compose.yaml run --rm segurai init --dir /data --for-docker
docker compose -f deploy/compose.yaml run --rm segurai users add --config /data/segurai.toml \
    --email you@acme.example --role admin
docker compose -f deploy/compose.yaml up -d
```

1. **The ingest token** is what agents send their spans with. Keep it in your secrets store, and set it again whenever you run `docker compose`.
2. **`init`** writes two files to the volume. `/data/segurai.toml` is the configuration, commented throughout. `/data/segurai.key` is the organisation's signing key. Back the key up somewhere safe: warrants signed with it can only be verified with it.
3. **`users add`** creates the first admin. It asks for a password of at least 12 characters. Admins can add everyone else from the dashboard.
4. **`up -d`** starts the server. Open <http://127.0.0.1:8700/> and sign in.

To change the configuration, edit `segurai.toml` on the volume, check it, and restart:

```bash
docker compose -f deploy/compose.yaml run --rm segurai config check --config /data/segurai.toml
docker compose -f deploy/compose.yaml restart
```

## PostgreSQL

Add `deploy/compose.postgres.yaml`. It runs PostgreSQL 16 beside Segurai, and only Segurai can reach it.

```bash
export SEGURAI_INGEST_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export SEGURAI_DB_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
alias segurai-compose='docker compose -f deploy/compose.yaml -f deploy/compose.postgres.yaml'
segurai-compose run --rm segurai init --dir /data --for-docker --postgres
segurai-compose run --rm segurai users add --config /data/segurai.toml --email you@acme.example --role admin
segurai-compose up -d
```

With `init --postgres`, the configuration says `database_env = "SEGURAI_DATABASE_URL"`, so the database password exists only in the environment.

For a managed database (RDS, Cloud SQL, Azure), leave out `compose.postgres.yaml`. Set `SEGURAI_DATABASE_URL` on the `segurai` service to that database's URL.

Several Segurai containers can share one PostgreSQL database. They take turns appending to the tamper-evident log, so it never forks.

## What the container does and doesn't do

- **Ports.** They are published on `127.0.0.1` only: 8700 for the dashboard, ingest and issuer, and 8800 for the gateway. Put your usual TLS reverse proxy in front for anything wider, and set `public_url` in `segurai.toml`. With Caddy:

  ```
  segurai.acme.example {
      reverse_proxy 127.0.0.1:8700
  }
  ```

- **Privileges.** It runs as an unprivileged user, on a read-only root filesystem, with no Linux capabilities and no privilege escalation.
- **Secrets.** None are in the image or in `segurai.toml`. Every secret comes from a variable that the configuration names (`..._env`).
- **Backups.** For SQLite: `docker compose -f deploy/compose.yaml exec segurai segurai --db /data/segurai.db backup --out /data/backup.db`, then copy it off the volume. For PostgreSQL, use `pg_dump` or the provider's backups. Either way, also keep a copy of `/data/segurai.key` and of the witness file named in `segurai.toml`.

## Checking a deployment works

```bash
deploy/smoke-test.sh            # SQLite
deploy/smoke-test.sh postgres   # PostgreSQL
```

Each run builds the image, sets up a throwaway deployment, then checks it end to end:

- the first run and an admin account;
- a healthy start;
- an agent's actions recorded;
- sign-in, and the dashboard showing those actions;
- a clean audit.

It then removes everything it created. CI runs both on every push.

## Prebuilt images

Each release is published as `ghcr.io/yaxomiller/segurai:<version>`, for Linux on Intel and ARM. To use one instead of building, replace `build:` and `image:` in `compose.yaml` with `image: ghcr.io/yaxomiller/segurai:0.4.0`.
