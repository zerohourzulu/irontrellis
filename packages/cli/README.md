# irontrellis

**Agents change. The structure holds.**

The `irontrellis` command creates, reads, verifies and changes an IronTrellis (formerly Continuity) history: a signed record of authority, duties and succession for AI agents. It answers three questions from that record:

| Question | Command |
| --- | --- |
| **Why** was an action allowed? | `irontrellis why` |
| **Who** is responsible for it now? | `irontrellis responsible` |
| **What** survives an agent that leaves? | `irontrellis survives` |

## 60 seconds

```sh
npx irontrellis@next demo
```

The demo plays a short scenario in a temporary history (a grant, a session, a duty, a handover from Bea to Alex), prints the three answers and the commands to ask the history yourself.

Your own history:

```sh
export IRONTRELLIS_HISTORY=./history.jsonl
irontrellis init --owner operations
mv history.jsonl.owner-next-key.json /media/offline/      # the next owner key belongs off this host
irontrellis agent create bea
irontrellis grant collect --to bea --actions read --resources incident:42 --expires +12h
irontrellis authorize --actor bea --action read --resource incident:42      # ALLOW, exit 0
irontrellis verify
```

Install: `npm install -g irontrellis@next` (Node 22.18 or later; one runtime dependency, `@ramex-labs/irontrellis`).

## The history format

`init` writes format 2 (`irontrellis-event/2`), and every write command writes format 2. Each line carries a record hash that chains to the line before it. A **state root** commits to everything the history establishes at a position; signed **checkpoints** and the owner's attestation in the pin file (`<history>.head`) name that root. `status` shows the root, its record count, the projection head and the latest checkpoint; `verify` recomputes the root with a full replay and checks the pin against it.

Publishing 1.0.0-rc.2 releases format 2. A history it writes keeps its verdicts: later versions read it exactly as 1.0.0-rc.2 does, or refuse it; rule fixes after 1.0.0-rc.2 come as a new format. Format 2 as released means challenge profile `g3`; the `frozen-r2.3` profile only verifies the frozen conformance vectors.

Older files are read only. A legacy (`continuity-event/0.2`) or format-1 (`irontrellis-event/1`) history answers every question and passes `verify`; every write is refused with `FORMAT_READ_ONLY` and a reason (`LEGACY`, `FORMAT_1`, or `MIGRATED`). Move it to format 2 with `migrate`.

## What a command establishes

| Commands | What they establish | What they do not establish |
| --- | --- | --- |
| Questions: `authorize`, `why`, `responsible`, `survives`, `handover`, `budget show`, `budget headroom`, `duty inspect` | An answer read from the history; nothing is executed | A permission: `ALLOW` is an answer about the record |
| Owner writes: the other commands that write | Events signed by the owner key, which sits next to the history (`<history>.owner-key.json`, mode 0600) or in a signer that file names | — |
| Session writes: `authorize --record-refusal`, and `duty activate`, `dispose` and `contest` | An event signed by a runtime session's key, not the owner key | An owner attestation or a witness statement: those come with the next owner write, and until then `verify` notes `PIN_ATTESTED_EARLIER`. The coding-agent hook's refusals and the MCP gateway's records are session writes too |
| `verify` | The file is intact: the chain, every signature, the pin and its attestation, anchors (anchored heads and anchor logs) and remote witnesses | That the file is the latest copy anywhere, unless a remote witness or an anchor log saw the later heads; that it is the history you mean (below); anything about anchors on a public chain |

### Is it the history you mean?

`verify` also does not establish, on its own, that the file is *the* history you mean. It reads the history id and the first owner keys from the file itself, so a substitute history signed with other keys verifies just as cleanly; the report says so. To rule that out, give the values the history's owner published, which are checked before anything else:

```sh
irontrellis --history ./history.jsonl verify --expect-history-id 0x… --expect-owner-key 0x…
irontrellis --history ./history.jsonl verify --expect-history-id 0x… --expect-owner-keys published-keys.txt
```

`init` (and `irontrellis-hook init`) ends with these values under "Publish these", with the command a reader runs; `verify` shows them too. The owner keys are compared as a set: order and key ids do not matter, a missing or an extra key is refused. A key is an Ed25519 public key as `0x` + 64 hex (or, in the file, an OpenSSH `ssh-ed25519` line) or an account address as `0x` + 40 hex. `export verify` takes the same options.

| Refused with | When |
| --- | --- |
| `HISTORY_ID_MISMATCH` | the history id is not the one you gave |
| `OWNER_KEYS_MISMATCH` | the first owner keys are not exactly the set you gave |
| `HISTORY_CHANGED` | read again after the verification, the file is another history, or the head the verification judged is not on its chain |

On `HISTORY_ID_MISMATCH` or `OWNER_KEYS_MISMATCH`, the expected and found values are in `identity` (`--json`), and nothing else is checked or written.

### A file that lost events

A file whose pin or anchor log shows removed events is refused by every command except `verify`, with `ROLLBACK_DETECTED` and the reason (`BEHIND_PIN`, `PIN_MISSING`, `PIN_UNATTESTED`, …). `verify --accept-rollback` re-pins it as it is and records that.

## Commands

Every command takes `--history <file>` (or `IRONTRELLIS_HISTORY`), `--json`, `--at <time>`, `--owner <id>`, `--controller <id>` and `--help`. Times are milliseconds, an ISO-8601 date, or a duration from now (`+30m`, `+12h`, `+7d`). `irontrellis <command> --help` lists every option.

| group | commands |
|---|---|
| history | `init`, `status`, `verify`, `repin`, `export`, `export verify`, `migrate`, `capacity`, `anchor` |
| checkpoints | `checkpoint create`, `checkpoint list`, `checkpoint verify` |
| owner keys | `owner status`, `owner commit-next-key`, `owner rotate-key`, `owner export-key-events` |
| key custody | `signer test`, `signer ref`, `signer list`, `signer to-ssh`, `doctor` |
| remote witnesses | `witness add`, `witness status`, `witness sync`, `witness remove` |
| structure | `agent create`, `agent terminate`, `role create`, `appoint`, `unappoint`, `succession declare`, `succeed`, `session admit`, `epoch advance` |
| authority | `grant`, `delegate`, `prohibit`, `revoke` |
| budgets | `budget declare`, `budget update`, `budget close`, `budget show`, `budget headroom` |
| counterparties | `counterparty register`, `counterparty rotate`, `counterparty retire`, `counterparty receipts` |
| investigation duties | `duty describe`, `duty activate`, `duty dispose`, `duty contest`, `duty inspect` |
| questions | `authorize`, `why`, `responsible`, `survives`, `handover` |

### init

`init` creates the history, its owner key and a committed next owner key (only the next key can rotate the owner key). Its options include:

- `--max-events` and `--max-state-records` set capacity limits;
- `--checkpoint-every <n>` writes a signed checkpoint every n events;
- `--witness <url> --verifier-key <key>` binds a remote witness from the first write;
- `--signer …` or `--owner-key-ref <file>` keeps the owner key in an ssh-agent, Vault Transit or a command signer.

The printed `historyId` goes into hook and gateway configs, so they refuse any other file. No option creates an older format.

### Budgets

```sh
irontrellis budget declare spend --actors bea --amount-cap 100 --per-operation-cap 60
irontrellis budget declare team --roles buyer --amount-cap 1000 --period-ms 86400000 --carry-unused --carry-cap 500
irontrellis budget update spend --amount-cap 80
irontrellis budget headroom spend
```

A budget limits a group of requests (actors, roles, actions, resources, metric) with an amount, count or per-request cap, for one period or fixed windows; unused allowance can roll over up to a cap. `update` applies from now on and keeps the usage; `close` is final. `declare` warns when no witness is bound (an older copy would restore spent budget), when a request could match more than 16 budgets (refused), and that only admitted operations are charged (gateway jobs, `recordCalls`, `run()`), never hook checks.

### Recording a refusal

```sh
irontrellis authorize --actor bea --action pay --resource vendor:1 --amount 80 \
  --record-refusal --session s:bea --session-key bea.key
```

A `DENY` or `INDETERMINATE` answer is then recorded as a refusal signed by the actor's own session (the key file `session admit --new-key` wrote). The engine decides the request again before it signs; one that would now be allowed is not recorded.

### Checkpoints

`checkpoint create` records a signed checkpoint (head, state root, record count, projection head); `list` shows them; `verify` replays from the genesis and checks each one against the recomputed roots.

### Counterparties

`counterparty register acme --key acme:1=0x…` registers a counterparty whose signed receipts may be recorded; `rotate` replaces its keys (the receipt chain continues); `receipts` lists what was recorded. A receipt's amount and outcome are the counterparty's claim, bound to the intent but not proven.

### Investigation duties

The duty commands continue an existing attempt duty under the investigation policy. They sign with the session of the duty's assignee (`--session`, `--session-key`).

```sh
S="--session worker:1 --session-key worker.key"
irontrellis duty describe duty:incident-42 --incident incident.txt --attester-role analyst $S
irontrellis duty activate investigation --duty duty:incident-42 --incident incident.txt --attester-role analyst --authority duty:activate $S
irontrellis duty dispose first --duty duty:incident-42 --disposition COMPLETED_UNDER_POLICY --report report.json --all-satisfied "Reviewed." --attestation-authority duty:attest --disposition-authority duty:dispose $S
irontrellis duty inspect duty:incident-42
```

`describe` writes and grants nothing; it prints the three grants the owner must make. Only the sha256 of the incident and report files enters the history. A repeat with the same id signs nothing; the same id with other content is `OPERATION_CONFLICT`. `irontrellis-mcp-gateway setup <dir> --investigation` creates a case to try this on.

### Export

`export` prints the events as a JSON array. `export --view` (or `--from <n> --to <n>`) prints the export view of a range; `--records` adds the state records at both ends, `--attestations` the owner attestations. `export verify <file>` checks a view on its own: every hash, both roots, every event between them. With `--expect-history-id` it first checks the history id of the genesis the view states; with `--expect-owner-key(s)` it compares the first owner keys once the view has verified (a view that carries no genesis has none).

### migrate

```sh
irontrellis migrate old.jsonl new.jsonl --accept-unpinned-source
irontrellis migrate --status new.jsonl.migration-plan.json
```

`migrate` re-records a legacy or format-1 history as format 2 under a new owner key, in steps a re-run resumes after a crash: plan, target, pin, snapshot, then a `.migrated` fence beside the source. The source is never changed; once fenced, writers and enforcing readers refuse it. Continuity files have no pin and need `--accept-unpinned-source` (check the source against a copy you trust first). `--status <plan>` reports the phase, whether the outputs verify, the target's root and the next step; without a plan it says whether the `--history` file is native format 2, a target, a fenced source or still needs migrating.

### Exit codes and errors

| exit | meaning |
|---|---|
| 0 | success; `authorize`: ALLOW; `verify`: every check passed |
| 1 | any failure, including a `verify`, `checkpoint verify` or `export verify` that found a problem |
| 2 | `authorize`: DENY; `doctor`: a usage error |
| 3 | `authorize`: INDETERMINATE |
| 4 | `WRITTEN_UNATTESTED`: the event is recorded, but the signer did not attest the new head; run `repin` later, do not retry |

A failure prints `error: <CODE> — <sentence>` on stderr, followed by the engine's own message on a second line when the sentence does not already carry it; with `--json`, `{ "error": { "code", "message", "detail"?, "context"? } }` on stdout, where `detail` is that engine message and `context` its machine-readable details (a lock path, for example). `--json` prints one document in the core's result shapes, bigints as decimal strings. Color appears only on a terminal; `--no-color` or `NO_COLOR` (any value) turns it off, and `FORCE_COLOR` turns it on without a terminal (`FORCE_COLOR=0` turns it off).

Write commands read the owner and domain from the file and retry while another writer holds the lock. The controller comes from `--controller`, `IRONTRELLIS_CONTROLLER`, the first `AGENT_CREATED` event, or the owner.

## Limits

- `--intent` re-checks the recorded runtime signature, which binds the domain at admission. Intents admitted before a migration are answered by the source archive; the migrated copy says so (`MIGRATED_INTENT`).
- `anchor --kind rekor` has not been run against a live Rekor log; treat its receipts as unverified.
- `verify` checks the anchors this command records (`anchor --kind local|rekor`) and the anchor logs. It does not verify anchors on a public chain ([known issues 54, 56 and 71](../../docs/records/KNOWN-ISSUES-r2.5.md)); the separate anchoring tools used for the public-chain demonstration records report `TRUSTED_NODE` only, never consensus-verified.
- Remote witnesses hold heads, not state roots. A rollback is detected against the head.
- Without `--expect-history-id` and `--expect-owner-key`, `verify` confirms the file against itself only: the history id and the first owner keys come from the file. The Python verifier and the programming interface have no such option yet.

## Reference

[docs/HISTORY-FORMAT.md](../../docs/HISTORY-FORMAT.md) (format 2, with formats 1 and 0.2 in a read-only appendix), [docs/MIGRATION.md](../../docs/MIGRATION.md), [docs/OPERATOR.md](../../docs/OPERATOR.md), [docs/CUSTODY.md](../../docs/CUSTODY.md), [docs/WITNESS.md](../../docs/WITNESS.md), and the engine: [`@ramex-labs/irontrellis`](../core/README.md).

Apache-2.0.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
