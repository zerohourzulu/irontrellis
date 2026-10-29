# Witness service configuration and storage reference

> Reference from `WITNESS.md` at `00ca4c0` (SHA-256 `98a6297888278a5c2b9d16fce4b04f985d6b34168ad2f3957285b2986ad34ed4`). Established scope: the retained field, byte, code, limit and ordered-check contracts below. Not established: a new engine audit, deployment test or broader edition coverage.

Source section numbers are retained for cross-reference with [WITNESS.md](../WITNESS.md). Operational guidance stays in the narrative page. Format-2 owner-policy rules remain in the unchanged [owner-policy reference](owner-policy.md).

<!-- source: WITNESS.md:74-96; exact text except relative Markdown links -->

`init` creates the data directory (0700), the checkpoint key `witness-key.json` (0600) and `config.json` (0600), and prints the **verifier key** (`witness.example.com+<8 hex>+<base64>`): the only thing clients trust. The origin (first line of every checkpoint) defaults to `irontrellis-witness/<name>`; `--origin` sets another (never the literal `irontrellis-witness-latest/1`, the first line of the latest notes, §9.8). `init` refuses a directory that already holds a key, a config or a log. `token create` prints a registration token (`itw_` + 43 base64url characters, 256 bits) once and stores only its SHA-256 in `adminTokenHashes`. `serve` replays the log, logs one JSON object per line on stderr (the readiness line is `"msg":"listening"`), and serves plain HTTP. `irontrellis-witness verifier-key --data <dir>` prints the verifier key again.

Registration needs the admin token by default (`registration: "token"`); give it to whoever connects histories (`irontrellis witness add … --token`). Statements, key events and reads need no token: they are owner-signed, and everything the witness serves is meant to be public to its clients. The admin token also opens `POST /v1/admin/key-events`, the out-of-band delivery of an owner's key-event bundle (§7.3); `irontrellis-witness import-key-events --data <dir> <bundle>…` does the same offline while the server is stopped (it takes the server lock). Either way the bundle gets exactly the checks of the network route: the token or the lock only gate the channel.

Signals: SIGTERM or SIGINT stops accepting, finishes appends in flight, releases the lock and exits 0; SIGHUP reloads `adminTokenHashes` from the config (revoke a token by deleting its hash, then SIGHUP). `serve --reload-interval <seconds>` re-reads them whenever the config file changes instead (0 turns it off; otherwise at least 1 second, a smaller value is a usage error; off by default; 5 s by default on Windows, which has no SIGHUP and stops the server on Ctrl+C, Ctrl+Break or a closing console: docs/PLATFORMS.md §4). Every command takes `--json`, `--help` and `--version`; usage errors exit 2.

### 4.2 Configuration (`config.json`)

| key | default | meaning |
|---|---|---|
| `name` | (required) | the witness name, also the checkpoint key's name: 1..128 of letters, digits and `._:/-` |
| `origin` | `irontrellis-witness/<name>` | first line of every checkpoint; one printable ASCII line, not `irontrellis-witness-latest/1` |
| `listen` | `127.0.0.1:8411` | `host:port` (IPv6 as `[::1]:8411`); `serve --listen` overrides it |
| `registration` | `"token"` | `"token"`: `POST /v1/histories` needs `Authorization: Bearer <admin token>`; `"open"`: anyone may register |
| `adminTokenHashes` | `[]` | lowercase SHA-256 hex of each accepted admin token, compared in constant time |
| `rateLimit` | `{ "perIpPerMinute": 1200, "perHistoryPerMinute": 600, "monitoringPerIpPerMinute": 6000 }` | token buckets, burst one minute's worth; `0` disables one. The per-history bucket counts statement posts; key-event posts (`…/key-events`) have their own per-history bucket of the same size, so a flood of statements signed with a leaked key cannot starve the owner's rotation delivery; `/healthz` and `/metrics` have their own, more generous per-address bucket (`monitoringPerIpPerMinute`), so probes neither starve the API nor get starved by it |
| `maxHistories` | `10000` | registrations beyond it get 503 `HISTORY_LIMIT_REACHED` |
| `checkpointIntervalMs` | `0` | `0`: a checkpoint after every append; otherwise at most one per interval (0..60 000), and a reply waits for the checkpoint that covers it |
| `trustProxy` | `false` | `true`: the peer is a trusted proxy and the client address is the last `X-Forwarded-For` hop; or a list of proxy addresses to skip from the right |
| `requestTimeoutMs` | `10000` | whole-request receive timeout (408), at least 100 |
| `metricsToken` | (none) | when set, `GET /metrics` needs `Authorization: Bearer <metricsToken>` (401 otherwise); 16..512 visible ASCII characters. `/healthz` stays open |

Unknown keys are refused, so a typo cannot silently weaken a limit. The origin and the key cannot change for an existing data directory (the server refuses to start when the last checkpoint does not verify with them); a new key means a new directory (§8).

<!-- source: WITNESS.md:170-180; exact text except relative Markdown links -->

### 4.6 The data directory, backups and key custody

| file | content |
|---|---|
| `log.jsonl` | one canonical JSON line `{"index":N,"entry":{…}}` per Merkle leaf (§9.3). The only source of truth: at start the server replays it, rebuilds the tree and every history's state, and re-applies the acceptance rules |
| `checkpoints.jsonl` | every checkpoint issued, `{note, size, time}`, for audit |
| `witness-key.json` | `{version: "irontrellis-witness-key/1", name, publicKey, verifierKey, privateKey}` (0600); the private key is a signed-note signer key `PRIVATE+KEY+<name>+<hash>+<base64>` |
| `config.json` | §4.2 (0600) |
| `server.lock` | the single-writer lock |

Each append is written and fsynced before anything that depends on it is answered, so a crash loses nothing acknowledged. At start a torn final line (a crash mid-append, never acknowledged) is cut off with a warning. Any other malformed, non-canonical, out-of-order or rule-breaking line, or a log that no longer matches the last signed checkpoint (fewer entries than a checkpoint covered, or a different root), stops the server with the file and line named. After a storage failure while serving, the server refuses writes with 503 `INTERNAL`, `/healthz` answers 503 `failed`, and it needs a restart once the cause is fixed.

<!-- source: WITNESS.md:186-190; exact text except relative Markdown links -->

**Offline audit.** `irontrellis-witness check-log --data <dir>` replays the log under the acceptance rules, re-verifies every owner signature and key-event authorization (a `ROTATED` leaf carries the `previousHead` its owner signature binds, so it is verified from the leaf alone; a `SUPERSEDED` leaf's range must cover exactly the heads held after its last good head, ending at its own leaf, with the latest head and the count it names, and its rotation must be pre-rotated against the commitment the log recorded), recomputes the tree and checks every checkpoint in `checkpoints.jsonl`. It is read-only, prints `VALID` (exit 0) or `INVALID` with each problem (exit 1), and reports histories with recorded equivocations. `--verifier-key <vkey> --origin <origin>` audits a copy without the private key. It establishes that the log is internally consistent and signed by that key; it does not show that clients were shown the same log.

### 4.7 Monitoring

`GET /healthz` answers `{ status: "ok", entries, checkpointSize, checkpointAgeMs }`, or 503 with `status: "failed"` after a storage failure. `GET /metrics` is Prometheus text; scrape it from inside your network (both proxy examples hide it), and set `metricsToken` (§4.2) to require `Authorization: Bearer <metricsToken>` on it. Both go through their own per-address rate limit (`rateLimit.monitoringPerIpPerMinute`, default 6000 a minute). Metrics: `irontrellis_witness_info`, `_entries`, `_entries_by_kind{kind}`, `_histories`, `_equivocating_histories`, `_equivocations_capped_total`, `_log_bytes`, `_checkpoint_size`, `_checkpoint_age_seconds`, `_appends_total`, `_append_seconds_total`, `_storage_failed`, `_requests_total{route,method,status}`, `_rejections_total{code}`, `_request_seconds_total`.

