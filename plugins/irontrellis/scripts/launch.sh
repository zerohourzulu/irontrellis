#!/bin/sh
# The IronTrellis plugin's hook entry point in Claude Code (macOS and Linux; on Windows use the hook route). It runs the node
# and launcher that `irontrellis-hook pin-runtime` (and every `irontrellis-hook init`) recorded in
# <IronTrellis home>/plugin-runtime, by absolute path: while a pin exists nothing is looked up on PATH. That guard decides
# whether this project is guarded by the plugin, by the settings hook (the plugin then steps aside), or not at all (a
# one-time notice and a choice). Exit codes: 2 only for PreToolUse; a failure on any other event is a warning (exit 1), so
# a broken setup never keeps Claude from stopping.
# No PATH lookups: the shell's own tools from /usr/bin and /bin only (the user's PATH is kept for the non-enforcing fallback
# below), and no NODE_* variable reaches the guard's node.
user_path=$PATH
PATH=/usr/bin:/bin; export PATH
for name in $(/usr/bin/env | /usr/bin/sed -n 's/^\(NODE_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$name"; done
event=$1
case "$event" in
  SessionStart|PreToolUse|Stop|SessionEnd) ;;
  *) echo "IronTrellis plugin: unknown event \"$event\"" >&2; exit 1 ;;
esac
fail() {
  # A refusal starts with a newline, so it stands on its own line under Claude Code's label (as the guard's own refusals).
  if [ "$event" = PreToolUse ]; then printf '\nIronTrellis · DENY: %s\n' "$1" >&2; exit 2; fi
  echo "IronTrellis: $1" >&2
  exit 1
}
run() {
  "$@" plugin claude-code "$event"
  code=$?
  if [ "$code" -eq 2 ] && [ "$event" != PreToolUse ]; then exit 1; fi
  exit "$code"
}
# The pinned guard: for PreToolUse any failure other than a refusal (a crash, a deleted dist/) is a refusal too.
run_pinned() {
  "$@" plugin claude-code "$event"
  code=$?
  if [ "$event" = PreToolUse ]; then
    if [ "$code" -ne 0 ] && [ "$code" -ne 2 ]; then printf '\nIronTrellis · DENY: the guard failed (exit %s); refusing\n' "$code" >&2; exit 2; fi
    exit "$code"
  fi
  if [ "$code" -eq 2 ]; then exit 1; fi
  exit "$code"
}
# Whether this project has an IronTrellis config: then a missing guard must refuse tool calls.
configured() {
  if [ -n "$IRONTRELLIS_HOOK_CONFIG" ]; then return 0; fi
  dir=${CLAUDE_PROJECT_DIR:-$PWD}
  while :; do
    if [ -e "$dir/irontrellis-hook.json" ]; then return 0; fi
    if [ "$dir" = / ] || [ -z "$dir" ]; then return 1; fi
    dir=$(dirname "$dir")
  done
}
home=${IRONTRELLIS_HOME:-$HOME/.irontrellis}
pin=$home/plugin-runtime
if [ -f "$pin" ]; then
  node=; launcher=
  { IFS= read -r node; IFS= read -r launcher; } < "$pin"
  again="run irontrellis-hook pin-runtime in your own terminal"
  case "$node" in /*) ;; *) fail "the plugin's runtime pin $pin names no absolute node; $again" ;; esac
  case "$launcher" in /*/bin/irontrellis-hook.mjs) ;; *) fail "the plugin's runtime pin $pin names no IronTrellis launcher; $again" ;; esac
  if [ ! -x "$node" ] || [ -d "$node" ]; then fail "the pinned node $node is missing; $again"; fi
  if [ ! -f "$launcher" ] || [ -L "$launcher" ]; then fail "the pinned launcher $launcher is missing (or a symlink); $again"; fi
  # The pinned launcher is a real path inside the installed hooks package, not just any file.
  bin=$(dirname "$launcher")
  if [ "$(cd "$bin" 2>/dev/null && pwd -P)" != "$bin" ]; then fail "the pinned launcher $launcher is not a real path; $again"; fi
  if ! grep -Eq '"name"[[:space:]]*:[[:space:]]*"@ramex-labs/irontrellis-hooks"' "$(dirname "$bin")/package.json" 2>/dev/null; then fail "the pinned launcher $launcher is not in the IronTrellis hooks package; $again"; fi
  run_pinned "$node" "$launcher"
fi
if configured; then
  fail "this project has an irontrellis-hook.json, but the plugin's runtime pin $pin is missing (run irontrellis-hook pin-runtime in your own terminal); refusing"
fi
# Not set up here: nothing is enforced. An irontrellis-hook on PATH shows the notice and keeps a decline silent.
if PATH=$user_path command -v irontrellis-hook >/dev/null 2>&1; then PATH=$user_path; export PATH; run irontrellis-hook; fi
if [ "$event" = SessionStart ]; then
  cat <<'EOF'
{"systemMessage":"The IronTrellis plugin is enabled, but the irontrellis-hook command is not installed, so IronTrellis does nothing here. Install it with npm install -g @ramex-labs/irontrellis-hooks@next, or disable the plugin (`irontrellis` in /plugin).","hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"The user has been told: The IronTrellis plugin is enabled, but the irontrellis-hook command is not installed, so IronTrellis does nothing here."}}
EOF
fi
exit 0
