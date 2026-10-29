# Vector adapter contract

This is a descriptive local verification interface over Core0.2.2, not an adopted Core0.3 standard. An adapter reads one JSON request line and writes one JSON response line. Diagnostic stdout, duplicate keys and non-finite values are invalid. Diagnostic stderr is permitted within the runner's bound. The program is long-lived until the runner closes it; this interface is not a remotely exposed service.

Success: `{"ok":true,"result":{...}}`. Execution failure: `{"ok":false,"error":"reason"}`. These envelopes have exactly the listed keys and `ok` is a boolean. A protocol-level DENY/INDETERMINATE/REJECTED answer is a successful operation result, not a broken adapter.

| Operation | Request | Result fields used by the retained corpus |
| --- | --- | --- |
| `describe` | `op` | Nonempty string `implementation`; language/version/operations may describe the implementation. This is self-reported identity, not authentication. |
| `replay` | `op`, `operationVersion`, `events` | `status`, `head` (explicit null when absent). |
| `authorize` | `op`, `events` plus the vector's `input` fields: operation version, expected head, domain, policy, root-recognition policy, request, evaluation time, authoritative/consequential flags | `decision`, explicit nullable `code`, `scopeAssurance`, nullable `controllingAuthorityIds`, ordered `failureCodes`. |
| `survives` | `op`, operation version, bounded event prefix, target actor, evaluation time | Established flag and the selected lifecycle, duty, assignment, tenure, invalidated-authority and unresolved-intent facts shown in the vector. Public minimal disclosure only. |

Arrays are ordered. The reference adapter sorts the obligation/invalidated-authority/unresolved-intent ID arrays; current assignments and failure codes retain returned order. Required fields cannot be omitted when their expected value is null. Additional result fields are ignored only because the corpus declares projections; this is not permission to change required meanings or protocol schemas. A field absent from a particular projection is not a general implementation freedom.

Quantities use the exact single-field JSON tag `{"$continuity.bigint":"2500"}`. Canonical spelling is zero or a signed nonzero decimal without leading zeros, within magnitude2^256−1; no additional tag fields are allowed. This follows Core's canonical representation. Whether a negative amount, omitted amount, zero or large positive quantity is valid for an authorization request is determined separately by Core. The adapter rejects malformed tag encodings as adapter input errors. No conversion through JavaScript Number is permitted. Operation envelopes contain no executable callbacks or trusted live capabilities.

The runner compares the vector's declared result projection, preserving scalar types (including integer versus floating-point representations), field presence and ordered arrays. It uses strict JSON parsing for responses. The local reference adapter receives runner-generated JSON; it is not a general untrusted network parser and carries no confidentiality or enforcement claim.

Use a command array after `--`, for example:

```sh
python3 -B conformance/run.py --level verifier -- node conformance/adapters/node.mjs
```

`verifier` selects replay/SURVIVES, `evaluator` adds authorization. These names describe vector coverage, not product certification tiers. Exit meanings and finite process limits are in the [runner guide](README.md). The actual permissive-adapter negative control is implemented in [test_runner.py](test_runner.py); it binds an absolute Core import and requires completed semantic differences, so a relocated broken import cannot pass it.
