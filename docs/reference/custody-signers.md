# Custody signer protocol and CLI contracts

> Reference from `CUSTODY.md` at `00ca4c0` (SHA-256 `cd491c6547c2a2de0a0153060cc77539eb80aedd95d028b5d9f287f1632e66ab`). Established scope: the retained field, byte, code, limit and ordered-check contracts below. Not established: a new engine audit, deployment test or broader edition coverage.

Source section numbers are retained for cross-reference with [CUSTODY.md](../CUSTODY.md). Operational guidance stays in the narrative page. Format-2 owner-policy rules remain in the unchanged [owner-policy reference](owner-policy.md).

<!-- source: CUSTODY.md:38-56; exact text except relative Markdown links -->

## 3. Key references

An owner key file, a next-key file or an archived retired key file may hold a **reference** instead of key material (docs/HISTORY-FORMAT.md §13.1):

```json
{
  "version": "irontrellis-owner-key-ref/1",
  "keyId": "owner:1",
  "scheme": "ed25519",
  "publicKey": "0x4c9e…(64 hex)",
  "signer": { "kind": "ssh-agent" }
}
```

`irontrellis-owner-next-key-ref/1` marks a next key, as with key files, so neither loader takes the other's file. A reference holds no secret, but it decides which program signs as the owner, so it is kept like a key file: mode 0600, and (POSIX) owned by the user that runs IronTrellis; any other file is refused with `KEY_UNAVAILABLE`. Key files and references are never opened through a symbolic link (`O_NOFOLLOW`; reason `SYMLINK`): whoever can write the directory could otherwise point `<history>.owner-key.json` at another of the owner's references. A reference handed to the CLI (`--owner-key-ref`, `--next-key-ref`, `signer test --ref`) passes the same checks before it is copied. An external signer (anything without a synchronous local key) is asked for a control signature only when its key is an owner key in force (`CONTROL_AUTHORIZATION_INVALID` otherwise, nobody asked). Nothing is contacted when a reference is loaded; the signer is asked only when a signature is needed.

**Every signature a signer returns is verified locally** against the reference's `publicKey` before IronTrellis uses it. A wrong signature (a compromised or misconfigured signer, another key, a truncated answer) is `SIGNER_FAILED` and never written. Signatures are plain Ed25519 over the same 32-byte hashes as with a key file: the history, the wire formats and the verifiers (the Python one included) see no difference.

Failures, for every signer: **`KEY_UNAVAILABLE`**: the signer does not hold the key (removed from the agent, a locked 1Password vault, a card not inserted, the command's `KEY_UNAVAILABLE` answer); **`SIGNER_FAILED`**: anything else (no agent at the socket, a refusal or a declined approval, a timeout, a crash, garbage, a wrong signature). `detail.reason` names the case (`KEY_NOT_IN_AGENT`, `FIDO_KEY`, `KEY_NOT_FOUND`, `PUBLIC_KEY_MISMATCH`, `VERSION_UNAVAILABLE`, `VERSION_MISMATCH`, `UNREACHABLE`, `REFUSED`, `PERMISSION_DENIED`, `NO_TOKEN`, `TLS`, `TIMEOUT`, `EXIT`, `MALFORMED`, `SIGNATURE_INVALID`, …). A control event whose signature fails is not appended.

<!-- source: CUSTODY.md:68-72; exact text except relative Markdown links -->

Name references kept away from the history `*.owner-key-ref.json` / `*.owner-next-key-ref.json`: the hook's protective rules cover those names (§9).

## 4. The ssh-agent signer

IronTrellis speaks the SSH agent protocol itself (no `ssh` binary involved): it asks the agent for its key list, finds the `ssh-ed25519` key whose public key the reference names, and sends `SSH_AGENTC_SIGN_REQUEST` over the 32-byte hash. An `ssh-ed25519` signature is a plain Ed25519 signature over exactly those bytes (RFC 8709), so it is used as is, once verified. The agent is found at the reference's `socket`, else `$SSH_AUTH_SOCK`, else (Windows) the named pipe `\\.\pipe\openssh-ssh-agent`. The default timeout is 60 s (`timeoutMs` in the reference, `--signer-timeout-ms` on the command line): enough for a person to approve.

<!-- source: CUSTODY.md:81-83; exact text except relative Markdown links -->

**How many signatures.** Each owner write asks for two signatures (the event's control authorization, then the pin attestation of its head), and with remote witnesses one head statement per write and occasionally a cache seal per witness. A rotation also asks the next key for its proof and seals the prepared-rotation record. With a signer that asks a person each time, approve for the session where it offers that (1Password does).

### 4.1 OpenSSH agent (Linux, macOS)

<!-- source: CUSTODY.md:93-95; exact text except relative Markdown links -->

* **Confirm each use**: `ssh-add -c` makes the agent ask before every signature through `ssh-askpass` (`$SSH_ASKPASS`). Without an askpass program, and on a headless host, the agent refuses every request (`SIGNER_FAILED`, reason `REFUSED`): that is what our tests exercise, since this build machine has no display. With a desktop askpass it asks per signature: see "How many signatures".
* **macOS**: the system agent (launchd sets `SSH_AUTH_SOCK`) works as is; `ssh-add --apple-use-keychain` stores the passphrase in the login keychain. Secure Enclave keys (`sk-` or ECDSA P-256 keys from third-party agents) are not Ed25519 and cannot hold an owner key.
* **Not supported**: FIDO keys (`sk-ssh-ed25519@openssh.com`; they sign a structure with flags and a counter, not the hash: refused with a clear message, reason `FIDO_KEY`), every non-Ed25519 key type, and keys added with destination constraints (`ssh-add -h`: the agent refuses to sign data that is not an SSH login, `REFUSED`). Do not forward the owner's agent (`ssh -A`) to hosts the agent can reach.

<!-- source: CUSTODY.md:97-97; exact text except relative Markdown links -->

### 4.2 1Password SSH agent

<!-- source: CUSTODY.md:102-104; exact text except relative Markdown links -->

2. The socket: macOS `~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock`, Linux `~/.1password/agent.sock`, Windows the OpenSSH pipe `\\.\pipe\openssh-ssh-agent` (stop the Windows OpenSSH Authentication Agent service first).
3. Copy the item's public key (`ssh-ed25519 AAAA…`) and create the reference: `irontrellis signer ref --out … --signer ssh-agent --agent-socket ~/.1password/agent.sock --public-key "ssh-ed25519 AAAA…"`, or `init --signer ssh-agent --agent-socket … --public-key …`.
4. `irontrellis signer test --ref …`: 1Password asks for approval; declining is `SIGNER_FAILED` (`REFUSED`), a locked vault or a key not offered by the agent (`~/.config/1Password/ssh/agent.toml` limits which keys are) is `KEY_UNAVAILABLE`.

<!-- source: CUSTODY.md:108-110; exact text except relative Markdown links -->

### 4.3 gpg-agent with a YubiKey (OpenPGP Ed25519)

A YubiKey 5 (firmware 5.2.3 or later) holds an Ed25519 key in its OpenPGP applet; gpg-agent offers the card's **authentication** key over the ssh-agent protocol. The private key never leaves the card; with a touch policy, every signature needs a touch.

<!-- source: CUSTODY.md:121-125; exact text except relative Markdown links -->

A card that is not inserted is `KEY_UNAVAILABLE` (gpg-agent does not list the key); a touch that does not come within the timeout is `SIGNER_FAILED` (`TIMEOUT` or `REFUSED`). Raise `--signer-timeout-ms` if the card also asks for its PIN. A second YubiKey kept elsewhere is a good home for the **next** key: commit to its public key (`--next-public-key`), and bring it (with a reference: `signer ref --next --agent-socket …`) only for the rotation.

### 4.4 Windows

The Windows OpenSSH agent (`Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent`, then `ssh-add`) and the 1Password agent both listen on `\\.\pipe\openssh-ssh-agent`, which IronTrellis uses when neither the reference nor `SSH_AUTH_SOCK` names a socket. Named-pipe access follows the pipe's ACL: the agent service serves the user that runs it. (The pipe code path is tested against a fake agent; the build machine is Linux.)

<!-- source: CUSTODY.md:127-135; exact text except relative Markdown links -->

## 5. Pre-rotation with keys held elsewhere

The next key never needs to exist as a file near the history:

* **Commit by public key** (`init --next-public-key <key>`, `owner commit-next-key --public-key <key>`, API `nextPublicKey`): no next-key file is written (a commitment by `commit-next-key` still writes its key-event bundle, as every rotation does); `owner status` shows `NEXT_KEY_OFF_HOST`.
* **Commit by reference** (`init --next-key-ref <file>`, `owner commit-next-key --next-key-ref <file>`, API `nextKeyReference`): the reference becomes `<history>.owner-next-key.json`, so `owner rotate-key` finds it by default. Use it when the next key's signer is not reachable from the agent's host anyway.
* **Rotate** with the next key's signer: `irontrellis owner rotate-key --next-key-ref <file>` (API `rotateOwnerKey({ nextKeyFile: <reference> })`). The committed key's signer signs the rotation's proof of possession; the promoted reference becomes `<history>.owner-key.json` (the key stays in its signer), the old owner key's reference is archived as `<history>.owner-key.<keyId>.retired.json`, and the new owner key set commits to a fresh next key: `--new-next-public-key <key>`, `--new-next-key-ref <file>`, or by default a new next-key file (move it offline).

A rotation is crash-safe with references exactly as with key files (the staged reference files are completed or removed on the next open; tested for every crash window of the two-phase rotation with both keys in an ssh-agent). A retired key held by a signer can still sign a copy of the history cut back before the rotation: take it out of the signer once every bound witness has recorded the rotation.

<!-- source: CUSTODY.md:137-168; exact text except relative Markdown links -->

## 6. The command signer

A generic external program signs, like git's `gpg.program`:

```json
{ "kind": "command", "argv": ["/usr/bin/node", "/opt/irontrellis/aws-kms-sign.mjs", "--key-id", "arn:aws:kms:…"], "timeoutMs": 60000, "passEnv": ["AWS_PROFILE"] }
```

* `argv[0]` is an absolute path; there is no shell and PATH is not searched for it. Every other argument that names a file (it starts with `.` or `~`, or ends in a script or key extension: `.mjs`, `.js`, `.py`, `.sh`, `.json`, `.pem`, …, also as the value of `--option=value`) must be absolute too; resource names (`projects/…`, ARNs, URLs) pass as they are. The program runs in the file-system root (`cwd` `/`), never in the caller's directory, which may be the agent's project.
* Default timeout 30 s (100 ms to 10 min). At the timeout the program's whole process group is killed (it is started in its own group; on Windows `taskkill /T`), so a grandchild cannot finish signing after IronTrellis reported that nothing was signed.
* **Environment**: only `HOME`, `LANG`, `TMPDIR` and the Windows essentials (`SystemRoot`, `TEMP`, `TMP`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `PATHEXT`, `COMSPEC`) are copied from IronTrellis's environment, plus the names in `passEnv`; `env` sets fixed values. **PATH is never inherited**: it is `/usr/bin:/bin` (Windows: the system directories) unless the reference sets `path` (absolute directories); `passEnv`/`env` cannot set it. Name the tools a script calls by absolute path (the cloud examples take `--gcloud /usr/bin/gcloud`, `--aws /usr/local/bin/aws`).
* **stderr** goes into error messages only as its last three lines, at most 240 characters, with control characters removed and anything that looks like a credential (`token=…`, `Bearer …`, long base64 or hex runs) replaced by `[redacted]`: an error can reach the agent's context through a hook.
* **Request**, one JSON document on stdin: `{"version":"irontrellis-sign-request/1","keyId":"owner:1","scheme":"ed25519","publicKey":"0x…","message":"<base64 of the 32 bytes>","purpose":"control-authorization","historyId":"0x…"}`. `purpose` (`control-authorization`, `head-attestation`, `head-statement`, `next-key-proof`, `rotation-seal`, `cache-seal`, `signer-test`) and `historyId` are advisory: whoever can run the program can put anything there, so a program must not base security decisions on them (log them).
* **Answer**, on stdout with exit status 0: `{"signature":"<base64 of the 64-byte Ed25519 signature>"}`, optionally with `"publicKey"` (a mismatch is `KEY_UNAVAILABLE`). A non-zero exit is `SIGNER_FAILED` (stderr's last lines go into the message); a non-zero exit with `{"error":{"code":"KEY_UNAVAILABLE","message":"…"}}` on stdout is `KEY_UNAVAILABLE`. More than 64 KiB on stdout is refused.

**Examples** (`examples/signers/`): `file-signer.mjs` signs with a key file IronTrellis cannot read (tested: it runs as a history's owner key in the test suite); `gcp-kms-sign.mjs` uses Google Cloud KMS keys of algorithm `EC_SIGN_ED25519` (PureEdDSA over the raw data) through `gcloud kms asymmetric-sign`; `aws-kms-sign.mjs` uses AWS KMS keys of key spec `ECC_NIST_EDWARDS25519` (supported since November 2025) with `SigningAlgorithm` `ED25519_SHA_512` and `MessageType` `RAW` through `aws kms sign`. **The two cloud scripts are examples, not tested against the live services**: the test suite runs them against fake `gcloud` / `aws` programs that check the arguments they pass, nothing more. Each prints the key's public key with `--public-key`. Give the identity the script runs as the right to sign with that one key only, and keep that identity out of the agent's reach: a command signer is only as private as the credentials the program uses. (AWS's `ED25519_PH_SHA_512` with `MessageType DIGEST` is the pre-hashed HashEdDSA variant: its signatures are not the plain Ed25519 IronTrellis verifies. Do not use it.)

## 7. HashiCorp Vault Transit

Vault's Transit engine holds Ed25519 keys that never leave it (unless a key is created `exportable`, which an owner key should not be) and signs on request, with a policy per key and an audit log of every use. IronTrellis talks to Vault's HTTP API directly (no `vault` binary, no dependency):

1. `GET /v1/<mount>/keys/<key>`: the key must be of type `ed25519`, not derived, and hold version `keyVersion` — not trimmed, not below `min_encryption_version` — whose public key is the reference's `publicKey`. Otherwise `KEY_UNAVAILABLE` (reasons `KEY_NOT_FOUND`, `WRONG_KEY_TYPE`, `DERIVED_KEY`, `VERSION_UNAVAILABLE`, `PUBLIC_KEY_MISMATCH`), and nothing is signed.
2. `POST /v1/<mount>/sign/<key>` with `{ "input": "<base64 of the 32 bytes>", "key_version": <pinned>, "prehashed": false }`. That is PureEdDSA over the 32 bytes, the plain Ed25519 IronTrellis verifies. `prehashed: true` would ask for Ed25519ph (Vault Enterprise; Vault 1.19+ community edition answers "only Pure Ed25519 signatures supported"), a different signature; `hash_algorithm` is not valid for ed25519 keys, `signature_algorithm` applies to RSA keys only and `marshaling_algorithm` to ECDSA P-256 only, so none of them is sent. The answer `vault:v<N>:<base64>` must carry the pinned version `N`, otherwise `KEY_UNAVAILABLE` (`VERSION_MISMATCH`), and its 64 bytes are verified locally like every signature.

**The key version is pinned.** Rotating a Transit key (`vault write -f transit/keys/<name>/rotate`) adds a version with a *new* key pair; the reference keeps signing with the version it names, so a Vault-side rotation never silently changes the owner key. To move the owner key onto the new version, rotate the *IronTrellis* owner key onto it (write a next-key reference with `--vault-key-version <new>`; with pre-rotation, commit to it first). Raising `min_encryption_version` above the pinned version, or trimming it, makes that owner key unusable (`KEY_UNAVAILABLE`, `VERSION_UNAVAILABLE`).

**The token is never in the reference.** It is read at signing time from the reference's `tokenFile` (an absolute path), else `VAULT_TOKEN`, else `~/.vault-token` (what `vault login` writes). The namespace (Vault Enterprise) is the reference's `namespace`, else `VAULT_NAMESPACE` (checked with the same rule; anything else is `SIGNER_FAILED`, `NAMESPACE_INVALID`), sent as `X-Vault-Namespace`. TLS: `https://` only, except to a loopback host (the witness rule, without an override: the token travels in every request); a private CA is the reference's `caFile`, else `VAULT_CACERT`. No proxy is used and redirects are not followed (name the active node or the load balancer). Timeout 30 s for both calls (`timeoutMs`, `--signer-timeout-ms`). Failures that are not about the key are `SIGNER_FAILED`: `NO_TOKEN`, `PERMISSION_DENIED` (a revoked or expired token, or a policy without the path), `SEALED`, `UNREACHABLE`, `TLS`, `TIMEOUT`, `REDIRECT`, `HTTP_ERROR`, `MALFORMED`.

```json
{ "kind": "vault-transit", "address": "https://vault.example:8200", "mount": "transit", "key": "irontrellis-owner-1", "keyVersion": 1,
  "namespace": "team-a", "tokenFile": "/home/owner/.irontrellis/owner.vault-token", "caFile": "/etc/irontrellis/vault-ca.pem", "timeoutMs": 30000 }
```

<!-- source: CUSTODY.md:193-195; exact text except relative Markdown links -->

`init --signer vault-transit` (and `signer ref`, `signer test`) reads the key from Vault when `--public-key` or `--vault-key-version` is left out, and pins the latest version (or the version holding `--public-key`). `--vault-addr` defaults to `$VAULT_ADDR`; the other flags: `--vault-mount` (default `transit`), `--vault-key-version`, `--vault-namespace`, `--vault-ca-file`, `--vault-token-file`. For a next key held in Vault, write its reference with `signer ref --next --key-id owner:2 --signer vault-transit … --vault-token-file <its own token file>` and commit with `--next-key-ref` (or commit its public key alone and bring the reference for the rotation).

**Least privilege**: the owner's token needs `update` on `<mount>/sign/<key>` and `read` on `<mount>/keys/<key>` (IronTrellis reads the key before every signature to check the pinned version's public key), nothing else. A periodic token renewed by a Vault Agent sidecar writing to `tokenFile` works as is (the file is read on every signature). Two keys a single token can sign with are one holder: `NEXT_KEY_SAME_SIGNER`. Give the next key its own policy and token (`tokenFile`), and keep that token file where only the rotation ceremony can read it.

<!-- source: CUSTODY.md:286-300; exact text except relative Markdown links -->

## 13. Adding a signer backend

The backends are a registry (`@ramex-labs/irontrellis/custody`): built in are `ssh-agent`, `command` and `vault-transit`. A backend implements

```ts
type SignerBackend = {
  kind: string;                                              // the reference's signer.kind (lowercase, a-z0-9-)
  parse(spec: Record<string, unknown>): SignerSpec;          // validate and normalize the reference's signer record; throw Error("…") on a defect; no I/O
  describe(spec: SignerSpec): string;                        // one line for owner status, signer test and doctor
  identity(spec: SignerSpec): string;                        // what identifies the key store (same kind + identity = NEXT_KEY_SAME_SIGNER)
  sign(spec: SignerSpec, key: ReferencedKey, message: Uint8Array, context: SignContext): Promise<Uint8Array>;  // the raw 64-byte signature
};
```

and throws `EngineError("KEY_UNAVAILABLE", …)` when it does not hold the key and `EngineError("SIGNER_FAILED", …)` otherwise (anything else becomes `SIGNER_FAILED`). `referenceSigner` does the rest (the local verification, the error mapping, `custody` for status). A backend shipped with IronTrellis goes in `packages/core/src/custody/<kind>.ts` and is listed in `BUILT_IN` in `custody/registry.ts` (`vault-transit` was added this way; the CLI's `--signer` accepts the kinds it knows the flags of, `signer ref` builds references for them). A host application registers its own with `registerSignerBackend(backend)` before loading a reference that names it; a reference naming an unknown kind is `KEY_UNAVAILABLE` ("which this installation does not know").

