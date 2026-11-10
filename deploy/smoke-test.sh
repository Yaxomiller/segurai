#!/usr/bin/env bash
# Build the image and prove a deployment works end to end, the way an operator
# would set it up: first-run configuration, an admin account, the server
# coming up healthy, an agent's actions recorded, sign-in, the dashboard
# showing them, and a clean audit. Everything is torn down afterwards.
#
#   deploy/smoke-test.sh             # with a SQLite file
#   deploy/smoke-test.sh postgres    # with PostgreSQL (deploy/compose.postgres.yaml)
#
# CI runs both on every push. Needs Docker with the compose plugin, curl and
# python3. Uses ports 8700 and 8800 on 127.0.0.1.

set -euo pipefail
cd "$(dirname "$0")/.."

variant="${1:-sqlite}"
files=(-f deploy/compose.yaml)
init_flags=(--for-docker)
if [ "$variant" = "postgres" ]; then
    files+=(-f deploy/compose.postgres.yaml)
    init_flags+=(--postgres)
    SEGURAI_DB_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
    export SEGURAI_DB_PASSWORD
fi
SEGURAI_INGEST_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export SEGURAI_INGEST_TOKEN
export COMPOSE_PROJECT_NAME="segurai-smoke-$variant"
ADMIN_PASSWORD="smoke-test-password-$RANDOM-$RANDOM"
export ADMIN_PASSWORD

compose() { docker compose "${files[@]}" "$@"; }
step() { printf '\n== %s\n' "$*"; }
finish() {
    status=$?
    if [ "$status" -ne 0 ]; then
        echo "FAILED ($variant). Last server output:"
        compose logs --no-color --tail 60 segurai || true
    fi
    compose down -v --remove-orphans > /dev/null 2>&1 || true
    exit "$status"
}
trap finish EXIT

step "build the image"
compose build --quiet

step "first run: configuration and the organisation's key"
compose run --rm -T segurai init --dir /data "${init_flags[@]}"

step "the first admin"
compose run --rm -T -e ADMIN_PASSWORD segurai users add --config /data/segurai.toml \
    --email admin@example.com --role admin --password-env ADMIN_PASSWORD

step "start, and wait until healthy"
compose up -d
container="$(compose ps -q segurai)"
health=starting
for _ in $(seq 1 60); do
    health="$(docker inspect --format '{{.State.Health.Status}}' "$container")"
    [ "$health" = healthy ] && break
    sleep 2
done
[ "$health" = healthy ] || { echo "the server never became healthy ($health)"; exit 1; }
curl -fsS http://127.0.0.1:8700/healthz && echo

step "an agent's actions, recorded into the deployment's store"
compose exec -T segurai python - <<'PY'
import segurai
from segurai.config import load_config

config = load_config("/data/segurai.toml")
segurai.configure(store=config.server.database, key=config.server.key)
granted = segurai.Scope.of(operations=["read", "archive"], targets=["crm.*"], max_scale=50)
with segurai.session(principal="sarah@example.com", request="smoke test: tidy stale deals", scope=granted):
    segurai.act("read", "crm.opportunities", scale=12)
    segurai.act("delete", "crm.opportunities", scale=400)     # outside what was granted
store = segurai._runtime.store
print("database:", store.dialect, store.path)
report = store.audit(segurai._runtime.authority.public_only())
assert report.ok, report.to_text()
print("audit: ok,", report.entries, "log entries")
PY

step "sign in and see the request on the dashboard"
python3 - <<'PY'
import http.cookiejar
import os
import re
import urllib.parse
import urllib.request

base = "http://127.0.0.1:8700"
jar = http.cookiejar.CookieJar()
web = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None                      # surface the redirect itself as an HTTPError


try:
    urllib.request.build_opener(NoRedirects).open(base + "/")
    raise SystemExit("the dashboard opened without signing in")
except urllib.error.HTTPError as exc:
    assert exc.code in (302, 303, 401), exc.code
    print("signed out: / sends you to sign in")

form = web.open(base + "/login").read().decode()
csrf = re.search(r"name='csrf' value='([^']+)'", form).group(1)
body = urllib.parse.urlencode({"csrf": csrf, "next": "/", "email": "admin@example.com",
                               "password": os.environ["ADMIN_PASSWORD"]}).encode()
page = web.open(base + "/login", data=body).read().decode()
assert "smoke test: tidy stale deals" in page, "the recorded request is not on the dashboard"
assert "Records verified" in page, "the dashboard does not show a clean audit"
print("signed in; the dashboard shows the request and verified records")
PY

step "audit from the command line"
compose exec -T segurai sh -c 'segurai --db "${SEGURAI_DATABASE_URL:-/data/segurai.db}" --key /data/segurai.pub audit'

step "passed ($variant)"
