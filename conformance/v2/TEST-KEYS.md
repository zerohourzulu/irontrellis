# Published test keys for conformance/v2 (r2)

All keys are Ed25519 (RFC 8032). The private key is the 32-byte seed written as a big-endian integer; `keyPairFromPrivateKey('ed25519', keyId, seedHex)` of rc.1-final (or any RFC 8032 implementation: public key = Ed25519 point of SHA-512(seed) clamped scalar) gives the credential. They are deterministic so that any implementation can re-sign the vectors' challenges and check byte equality. **Test material only.**

| keyId | role in the history | seed (32 bytes, hex) | credential (public key, hex) |
|---|---|---|---|
| `owner:1` | owner key of epoch 0 (genesis `ownerKeys[0]`); signs every control event, every checkpoint and every attestation | `0x0000000000000000000000000000000000000000000000000000000000001001` | `0x967e264fa6b2e89fcfab4df3d4291cd1482a3a5a9f3836c9ce8f80d112d2ac4d` |
| `owner:2` | next owner key: its digest is the genesis `nextKeyDigests[0]` (`irontrellis-owner-key-digest/1` over `{version, scheme, credential}`); never used to sign in this suite | `0x…1102` (same padding) | `0x051215c6dcfdc4beaabee477011015f1e1a004b7b98f30f5a0518e59f0f42da6` |
| `key:spender` | session credential of `session:spender` (agent `spender`); signs intents, admissions, CORE/BUDGET refusals, effects and receipt wrappers | `0x…2004` | `0xcb75fed9c52f386f38a12a8aaffd593eab63603ae28b8056b894e8d08d53d71f` |
| `key:gateway` | session credential of `session:gateway` (agent `gateway`, the connector's own identity); signs the CONNECTOR refusal | `0x…2005` | `0xf30c274884eeddb70820f55bfd49114f00457292d2468e8f98a6f72efdeec445` |
| `acme:1` | counterparty key registered for `acme` (`COUNTERPARTY_REGISTERED.keys[0]`); signs the receipt envelopes | `0x…3001` | `0xe82a9aa41d740c74b238550f6fe970ba946e98499381af855c1bd0c3f616c26b` |
| `stranger:1` | a key that appears nowhere in the history; used for the "stranger" negative vectors (refusal signed by a stranger; attestation under a stranger key) | `0x…3999` | `0xa434f23c76408525b4fcd3ba47824df8ec912f6046fc4d95e1e43f448e156bf6` |

Genesis `nextKeyDigests[0]` = `0xec02d39d050ad408f7a0fa6a75604753cc9e4fafc6f78262a2026f3181832762` (digest of `owner:2`).

Signing convention (unchanged from rc.1-final): the signature is Ed25519 over the 32 raw bytes of the challenge hash (`hashCanonical(challenge)` with the `0x` removed), not over the hex text; signatures are 64 bytes hex with `0x`. Verification helper used by the self-check: `verifyEd25519(credential, hashHex, signatureHex)` in `generate/lib.mjs`.

Domain of every vector: `{protocol: "irontrellis", version: "2", deploymentId: "irontrellis-conformance-v2"}`; the format-1 twin uses `version: "1"` with the same deploymentId.
