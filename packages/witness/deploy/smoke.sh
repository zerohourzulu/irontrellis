#!/usr/bin/env bash
# Smoke test for the IronTrellis witness image: the container, driven from the host by the repo's
# own `irontrellis` CLI, as a history owner would use it.
#
#   packages/witness/deploy/smoke.sh <image>
#
# Needs: docker, node >= 22.18 and a built workspace (pnpm install && pnpm -r build: the host side
# runs packages/cli/bin/irontrellis.mjs). Runs on Linux and on macOS with Docker Desktop (bash 3.2,
# BSD userland), and in CI (.github/workflows/docker-witness.yml).
#
# What it checks, in order:
#   1. the image: --version matches packages/witness/package.json, non-root user, /data volume,
#      port 8411, a healthcheck; an uninitialized volume without IRONTRELLIS_WITNESS_NAME is refused
#   2. first start on an empty volume initializes it (entrypoint), /healthz answers, the container
#      turns healthy, /v1/witness serves the verifier key that `verifier-key` prints
#   3. `token create` via docker exec, then SIGHUP (node is PID 1) loads it into the running server
#   4. host: `irontrellis init --witness <url> --verifier-key <k> --token <t> --mode sync` registers the
#      genesis; two more events; `verify` is VERIFIED with the remote witness OK; `witness status`
#      shows the receipt verified, consistency ok and no unwitnessed tail
#   5. an older copy of the history is refused by `verify` (REMOTE_WITNESS_ROLLBACK): the point of it
#   6. `check-log` inside the container is VALID
#   7. `docker restart` (graceful: SIGTERM reaches the server), then verify, write, status, check-log
#   8. with the container stopped, `verify` fails closed (REMOTE_WITNESS_UNREACHABLE)
#   9. SIGKILL (a crash that leaves server.lock behind), start again: the lock is reclaimed (same
#      --hostname), verify and check-log pass
#
# Environment: SMOKE_KEEP=1 keeps the container, volume and temp directory for inspection;
# IRONTRELLIS_CLI_BIN overrides the host CLI (default <repo>/packages/cli/bin/irontrellis.mjs);
# SMOKE_TIMEOUT (seconds, default 90) bounds each wait; SMOKE_PORT picks the host port (default: a
# free one), published on 127.0.0.1 only.
# The admin token never reaches the output (and is masked in GitHub Actions logs).
set -euo pipefail

usage() { printf 'usage: %s <image>\n' "$0" >&2; exit 2; }
[ "$#" -eq 1 ] || usage
IMAGE=$1

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
CLI_BIN=${IRONTRELLIS_CLI_BIN:-$ROOT/packages/cli/bin/irontrellis.mjs}
TIMEOUT=${SMOKE_TIMEOUT:-90}
WITNESS_NAME=smoke.witness.test
NAME=irontrellis-witness-smoke-$$
VOLUME=$NAME-data
PROBE_VOLUME=$NAME-probe
WORK=$(mktemp -d "${TMPDIR:-/tmp}/irontrellis-witness-smoke.XXXXXX")
HISTORY=$WORK/owner/history.jsonl
OLD_COPY=$WORK/old/history.jsonl
TOKEN=""
STEP=0

# The host CLI must not pick up a developer's own settings.
unset IRONTRELLIS_HISTORY IRONTRELLIS_CONTROLLER IRONTRELLIS_WITNESS_POLICY || true
export NO_COLOR=1

# ---------------------------------------------------------------- helpers

step() { STEP=$((STEP + 1)); printf '\n==> %d. %s\n' "$STEP" "$*"; }
ok() { printf '    ok  %s\n' "$*"; }
redact() { sed -E 's/itw_[A-Za-z0-9_-]+/itw_<redacted>/g'; }
fail() {
  printf '\nFAIL: %s\n' "$1" >&2
  if [ "$#" -gt 1 ]; then printf '%s\n' "$2" | redact | head -c 6000 >&2; printf '\n' >&2; fi
  exit 1
}

cleanup() {
  status=$?
  set +e
  if [ "$status" -ne 0 ] && docker container inspect "$NAME" >/dev/null 2>&1; then
    printf '\n---- container log (last 60 lines) ----\n' >&2
    docker logs --tail 60 "$NAME" 2>&1 | redact >&2
    printf -- '---- health ----\n' >&2
    docker inspect --format '{{json .State.Health}}' "$NAME" 2>/dev/null | redact >&2
  fi
  if [ "${SMOKE_KEEP:-0}" = 1 ]; then
    printf '\nSMOKE_KEEP=1: kept container %s, volume %s and %s\n' "$NAME" "$VOLUME" "$WORK" >&2
  else
    docker rm -f "$NAME" >/dev/null 2>&1
    docker volume rm -f "$VOLUME" "$PROBE_VOLUME" >/dev/null 2>&1
    rm -rf "$WORK"
  fi
  if [ "$status" -eq 0 ]; then printf '\nSMOKE TEST PASSED (%s)\n' "$IMAGE"; else printf '\nSMOKE TEST FAILED (%s)\n' "$IMAGE" >&2; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# js <expression over j> : evaluates a JavaScript expression against the JSON document on stdin and
# prints the result (strings bare, everything else as JSON). Exit 1 on unparsable input.
js() {
  node -e '
    let j;
    try { j = JSON.parse(require("fs").readFileSync(0, "utf8")); } catch { process.exit(1); }
    const v = new Function("j", "return (" + process.argv[1] + ");")(j);
    process.stdout.write(typeof v === "string" ? v : JSON.stringify(v ?? null));
  ' "$1"
}
# expect <what> <expression over j> <json> : fails the test unless the expression is true.
expect() {
  local result
  result=$(printf '%s' "$3" | js "$2") || fail "$1: not JSON" "$3"
  [ "$result" = true ] || fail "$1 (expected: $2)" "$3"
  ok "$1"
}

irontrellis() { node "$CLI_BIN" "$@"; }
witness_exec() { docker exec "$NAME" irontrellis-witness "$@"; }

wait_for_health() {
  local waited=0 health=""
  while [ "$waited" -lt "$TIMEOUT" ]; do
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$NAME" 2>/dev/null || true)
    if [ "$health" = healthy ]; then ok "container healthy after ${waited}s"; return 0; fi
    if [ "$(docker inspect --format '{{.State.Running}}' "$NAME" 2>/dev/null || true)" != true ]; then fail "the container exited" "$(docker logs --tail 40 "$NAME" 2>&1)"; fi
    sleep 1
    waited=$((waited + 1))
  done
  fail "the container did not turn healthy within ${TIMEOUT}s (last: $health)"
}

wait_for_healthz() {
  local waited=0 body=""
  while [ "$waited" -lt "$TIMEOUT" ]; do
    if body=$(curl -fsS --max-time 3 "$URL/healthz" 2>/dev/null); then
      expect "/healthz answers ok" 'j.status === "ok"' "$body"
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  fail "$URL/healthz did not answer within ${TIMEOUT}s"
}

wait_for_log() {
  local pattern=$1 waited=0 logs
  while [ "$waited" -lt "$TIMEOUT" ]; do
    logs=$(docker logs "$NAME" 2>&1 || true)
    if grep -Fq -- "$pattern" <<<"$logs"; then return 0; fi
    sleep 1
    waited=$((waited + 1))
  done
  fail "no log line containing $pattern within ${TIMEOUT}s"
}

count_log() { local logs; logs=$(docker logs "$NAME" 2>&1 || true); grep -Fc -- "$1" <<<"$logs" || true; }

# A fixed host port: the witness URL is bound into the history, so it must survive restarts.
free_port() { node -e 'const s = require("net").createServer(); s.listen(0, "127.0.0.1", () => { process.stdout.write(String(s.address().port)); s.close(); });'; }

verify_ok() {
  local out
  out=$(irontrellis verify --history "$HISTORY" --json) || fail "irontrellis verify failed ($1)" "$out"
  expect "verify: VERIFIED ($1)" 'j.ok === true && j.failures.length === 0' "$out"
  expect "verify: the remote witness answered OK ($1)" 'j.report.remoteWitnessStatus === "OK" && j.report.remoteWitnesses.length === 1 && j.report.remoteWitnesses[0].status === "OK"' "$out"
}

status_ok() {
  local out
  out=$(irontrellis witness status --history "$HISTORY" --json) || fail "irontrellis witness status failed ($1)" "$out"
  expect "witness status: ok, receipt verified, consistent ($1)" 'j.ok === true && j.remote.length === 1 && j.remote[0].status === "OK" && j.remote[0].receiptVerified === true && j.remote[0].consistent === true' "$out"
  expect "witness status: the witness holds the head, nothing unwitnessed ($1)" 'j.unwitnessedEvents === 0 && j.pending.length === 0 && j.remote[0].latest.hash === j.head.hash && j.remote[0].latest.position === j.head.position' "$out"
}

check_log_ok() {
  local out
  out=$(witness_exec check-log --data /data --json) || fail "check-log failed ($2)" "$out"
  expect "check-log: VALID, $1 entries ($2)" "j.status === \"VALID\" && j.ok === true && j.problems.length === 0 && j.entries === $1 && j.lastCheckpointSize === $1" "$out"
}

# ---------------------------------------------------------------- 0. prerequisites

command -v docker >/dev/null || fail "docker is not on PATH"
command -v node >/dev/null || fail "node is not on PATH"
command -v curl >/dev/null || fail "curl is not on PATH"
[ -f "$CLI_BIN" ] || fail "no host CLI at $CLI_BIN (run pnpm install && pnpm -r build first, or set IRONTRELLIS_CLI_BIN)"
[ -f "$(dirname "$CLI_BIN")/../dist/cli.js" ] || fail "the host CLI is not built (run pnpm -r build)"
docker image inspect "$IMAGE" >/dev/null 2>&1 || fail "image $IMAGE is not present locally (build or pull it first)"
EXPECTED_VERSION=$(node -p 'require(process.argv[1]).version' "$ROOT/packages/witness/package.json")
mkdir -p "$WORK/owner" "$WORK/old"
PORT=${SMOKE_PORT:-$(free_port)}
URL=http://127.0.0.1:$PORT

# ---------------------------------------------------------------- 1. the image

step "image $IMAGE"
version=$(docker run --rm "$IMAGE" --version | tr -d '\r\n')
[ "$version" = "$EXPECTED_VERSION" ] || fail "the image reports version $version, the checkout is $EXPECTED_VERSION"
ok "irontrellis-witness $version"
uid=$(docker run --rm "$IMAGE" id -u | tr -d '\r\n')
[ "$uid" != 0 ] || fail "the image runs as root"
ok "runs as uid $uid"
config=$(docker image inspect --format '{{json .Config}}' "$IMAGE")
expect "declares VOLUME /data, EXPOSE 8411/tcp and a HEALTHCHECK" 'j.Volumes && "/data" in j.Volumes && j.ExposedPorts && "8411/tcp" in j.ExposedPorts && j.Healthcheck && j.Healthcheck.Test.length > 1' "$config"
docker volume create "$PROBE_VOLUME" >/dev/null
if probe=$(docker run --rm -v "$PROBE_VOLUME:/data" "$IMAGE" 2>&1); then fail "an uninitialized volume without IRONTRELLIS_WITNESS_NAME was served" "$probe"; fi
grep -Fq "IRONTRELLIS_WITNESS_NAME" <<<"$probe" || fail "the refusal does not say how to initialize" "$probe"
ok "an uninitialized volume without IRONTRELLIS_WITNESS_NAME is refused, with instructions"

# ---------------------------------------------------------------- 2. first start

step "first start on an empty volume"
docker volume create "$VOLUME" >/dev/null
# --health-interval shortens the image's 30 s interval for the test; the probe itself is the image's.
docker run -d --name "$NAME" --hostname "$NAME" \
  -e IRONTRELLIS_WITNESS_NAME="$WITNESS_NAME" \
  -v "$VOLUME:/data" -p "127.0.0.1:$PORT:8411" \
  --health-interval 2s \
  "$IMAGE" >/dev/null
ok "container $NAME, witness at $URL"
wait_for_healthz
wait_for_health
wait_for_log '"msg":"listening"'
logs=$(docker logs "$NAME" 2>&1)
grep -Fq "first start: initializing /data as witness $WITNESS_NAME" <<<"$logs" || fail "the entrypoint did not initialize the volume" "$logs"
if grep -Eq 'PRIVATE\+KEY|itw_' <<<"$logs"; then fail "the container log contains a secret" "$(redact <<<"$logs" | sed -E 's/PRIVATE\+KEY[^" ]*/PRIVATE+KEY<redacted>/g')"; fi
ok "initialized on first start; no private key or token in the log"
VERIFIER_KEY=$(witness_exec verifier-key --data /data | tr -d '\r\n')
case "$VERIFIER_KEY" in "$WITNESS_NAME+"*) ok "verifier key $VERIFIER_KEY" ;; *) fail "unexpected verifier key: $VERIFIER_KEY" ;; esac
info=$(curl -fsS --max-time 5 "$URL/v1/witness")
expect "/v1/witness serves that verifier key" "j.verifierKey === \"$VERIFIER_KEY\"" "$info"
modes=$(docker exec "$NAME" stat -c '%a %u %n' /data /data/witness-key.json /data/config.json)
if ! grep -Eq '^700 [0-9]+ /data$' <<<"$modes" || ! grep -Eq '^600 [0-9]+ /data/witness-key.json$' <<<"$modes"; then fail "unexpected modes in /data" "$modes"; fi
ok "/data 0700, witness-key.json 0600"

# ---------------------------------------------------------------- 3. admin token

step "admin token (docker exec token create, SIGHUP reload)"
token_json=$(witness_exec token create --data /data --json) || fail "token create failed"
TOKEN=$(printf '%s' "$token_json" | js 'j.token')
case "$TOKEN" in itw_*) ;; *) fail "token create returned no token" ;; esac
if [ "${GITHUB_ACTIONS:-}" = true ]; then printf '::add-mask::%s\n' "$TOKEN"; fi
ok "created (not shown)"
docker kill --signal HUP "$NAME" >/dev/null
wait_for_log '"msg":"reloaded admin token hashes"'
ok "SIGHUP reached the server; it reloaded the token hashes"

# ---------------------------------------------------------------- 4. a history bound to the witness

step "host CLI: init a history bound to the witness, write, verify, status"
out=$(irontrellis init --history "$HISTORY" --witness "$URL" --verifier-key "$VERIFIER_KEY" --token "$TOKEN" --mode sync --json) \
  || fail "irontrellis init --witness failed" "$out"
expect "init: bound to the witness, the head witnessed" "j.witnesses.length === 1 && j.witnesses[0].verifierKey === \"$VERIFIER_KEY\" && j.unwitnessedEvents === 0" "$out"
out=$(irontrellis agent create smoke-agent --history "$HISTORY" --json) || fail "agent create failed" "$out"
ok "event: agent smoke-agent"
# The older copy an attacker would restore: the file and its side files as they are now.
cp -p "$WORK/owner/"history.jsonl* "$WORK/old/"
out=$(irontrellis grant smoke-grant --to smoke-agent --actions read --resources doc:smoke --expires +1h --history "$HISTORY" --json) \
  || fail "grant failed" "$out"
ok "event: grant smoke-grant"
verify_ok "after writes"
status_ok "after writes"
ENTRIES=$(irontrellis witness status --history "$HISTORY" --json | js 'j.remote[0].checkpointSize')
ok "the witness log holds $ENTRIES entries"

# ---------------------------------------------------------------- 5. rollback detection

step "an older copy of the history is refused"
if out=$(irontrellis verify --history "$OLD_COPY" --json); then fail "verify accepted the older copy" "$out"; fi
expect "verify of the older copy: REMOTE_WITNESS_ROLLBACK" 'j.ok === false && j.failures.some((f) => f.startsWith("REMOTE_WITNESS_ROLLBACK"))' "$out"

# ---------------------------------------------------------------- 6. offline audit in the container

step "check-log in the container"
check_log_ok "$ENTRIES" "before restart"

# ---------------------------------------------------------------- 7. graceful restart

step "docker restart (SIGTERM to node as PID 1)"
docker restart "$NAME" >/dev/null
wait_for_healthz
wait_for_health
[ "$(count_log '"msg":"shutting down","signal":"SIGTERM"')" -ge 1 ] || fail "the server never logged a SIGTERM shutdown" "$(docker logs --tail 40 "$NAME" 2>&1)"
[ "$(count_log '"msg":"stopped"')" -ge 1 ] || fail "the server did not stop cleanly" "$(docker logs --tail 40 "$NAME" 2>&1)"
ok "the server received SIGTERM and stopped cleanly"
verify_ok "after restart"
out=$(irontrellis agent create smoke-agent-2 --history "$HISTORY" --json) || fail "a write after the restart failed" "$out"
ok "event: agent smoke-agent-2"
status_ok "after restart"
ENTRIES=$((ENTRIES + 1))
check_log_ok "$ENTRIES" "after restart"

# ---------------------------------------------------------------- 8. witness down

step "verify fails closed while the witness is down"
docker stop "$NAME" >/dev/null
if out=$(irontrellis verify --history "$HISTORY" --json); then fail "verify passed with the witness stopped" "$out"; fi
expect "verify: REMOTE_WITNESS_UNREACHABLE" 'j.ok === false && j.failures.some((f) => f.startsWith("REMOTE_WITNESS_UNREACHABLE"))' "$out"

# ---------------------------------------------------------------- 9. crash and stale lock

step "crash (SIGKILL) and start again: the stale lock is reclaimed"
docker start "$NAME" >/dev/null
wait_for_healthz
docker kill --signal KILL "$NAME" >/dev/null
docker wait "$NAME" >/dev/null || true
docker start "$NAME" >/dev/null
wait_for_healthz
wait_for_health
[ "$(count_log '"msg":"reclaiming a stale server lock"')" -ge 1 ] || fail "the server did not report reclaiming the stale lock" "$(docker logs --tail 40 "$NAME" 2>&1)"
ok "the lock left by the killed server was reclaimed"
verify_ok "after the crash"
status_ok "after the crash"
check_log_ok "$ENTRIES" "after the crash"
