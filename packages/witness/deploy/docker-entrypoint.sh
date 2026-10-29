#!/bin/sh
# Entrypoint of the IronTrellis witness image (packages/witness/deploy/Dockerfile).
#
#   <image>                          serve /data on 0.0.0.0:8411 (the default CMD); on the very first
#                                    start, initialize /data when IRONTRELLIS_WITNESS_NAME is set
#   <image> init|token|verifier-key|check-log|serve|help ... | --version | --help
#                                    run that irontrellis-witness command as given
#   <image> healthcheck              what HEALTHCHECK runs: GET /healthz (exit 0 when it answers 200)
#   <image> <anything else>          exec it (a shell for debugging, say)
#
# Environment:
#   IRONTRELLIS_WITNESS_NAME     witness name used by the first-start `init` (the checkpoint key's
#                                name; permanent for this data directory). Ignored once initialized.
#   IRONTRELLIS_WITNESS_ORIGIN   optional checkpoint origin for that `init` (default irontrellis-witness/<name>)
#   IRONTRELLIS_WITNESS_HEALTH_URL
#                                what `healthcheck` probes (default http://127.0.0.1:8411/healthz);
#                                change it together with --listen
#
# Secrets: this script never creates or prints a secret. The first-start `init` prints the verifier
# key (public: clients configure it) and the paths of the key and config files, never the private
# key. No admin token is created here, because container logs are kept and shipped: the script only
# prints the command that creates one (`token create` prints the token once, to the terminal of
# whoever runs it) and the SIGHUP that makes the running server load it.
set -eu

WITNESS_BIN=/opt/irontrellis-witness/bin/irontrellis-witness.mjs

say() { printf '%s\n' "irontrellis-witness entrypoint: $*" >&2; }

if [ "$#" -eq 0 ]; then
  set -- serve --data /data --listen 0.0.0.0:8411
fi

case "$1" in
  healthcheck)
    # busybox wget: -q quiet, -T timeout, -Y off ignores any http_proxy in the environment.
    exec wget -q -Y off -T 4 -O /dev/null "${IRONTRELLIS_WITNESS_HEALTH_URL:-http://127.0.0.1:8411/healthz}"
    ;;
  serve) ;;
  init | token | verifier-key | check-log | help | -*)
    exec node "$WITNESS_BIN" "$@"
    ;;
  *)
    exec "$@"
    ;;
esac

# ---- serve: find --data (the CLI requires it; without it, let the CLI report the usage error).
data=""
previous=""
for arg in "$@"; do
  case "$previous" in --data) data="$arg" ;; *) ;; esac
  case "$arg" in --data=*) data="${arg#--data=}" ;; *) ;; esac
  previous="$arg"
done

if [ -n "$data" ] && [ ! -e "$data/witness-key.json" ] && [ ! -e "$data/config.json" ] && [ ! -e "$data/log.jsonl" ]; then
  # A data directory with no key, no config and no log: the first start. (A directory holding some
  # of them but not the key is damaged or half-restored; `serve` refuses it with the file named, and
  # nothing here overwrites it.)
  if [ -e "$data" ] && [ ! -w "$data" ]; then
    say "$data is not writable by uid $(id -u); give the volume to the image's user (uid 10001), e.g. chown -R 10001:10001 <host dir>"
    exit 1
  fi
  if [ -z "${IRONTRELLIS_WITNESS_NAME:-}" ]; then
    say "$data is not initialized. Either set IRONTRELLIS_WITNESS_NAME=<name> (for example your witness's DNS name) to initialize it on this first start, or run once:"
    say "  docker run --rm -v <volume>:$data <image> init --data $data --name <name>"
    exit 2
  fi
  say "first start: initializing $data as witness ${IRONTRELLIS_WITNESS_NAME}"
  if [ -n "${IRONTRELLIS_WITNESS_ORIGIN:-}" ]; then
    node "$WITNESS_BIN" init --data "$data" --name "$IRONTRELLIS_WITNESS_NAME" --origin "$IRONTRELLIS_WITNESS_ORIGIN"
  else
    node "$WITNESS_BIN" init --data "$data" --name "$IRONTRELLIS_WITNESS_NAME"
  fi
  say "no admin token exists yet, so registration is refused until you create one. It is printed once, to your terminal, never to this log:"
  say "  docker exec <container> irontrellis-witness token create --data $data"
  say "  docker kill --signal HUP <container>    # the running server loads the new token hash"
fi

exec node "$WITNESS_BIN" "$@"
