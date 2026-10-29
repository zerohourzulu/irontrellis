"""Witness wire formats: the Python runner for ``conformance/transparency/vectors.json`` (every section,
the same checks as ``packages/core/test/transparency-conformance.test.mjs``) plus targeted tamper and property tests."""
from __future__ import annotations

import base64
import copy
import json
import random

import pytest

from irontrellis import transparency as t
from irontrellis.__main__ import main as cli_main
from irontrellis.crypto import ed25519
from conftest import CONFORMANCE, load_json

VECTORS_PATH = CONFORMANCE / "transparency" / "vectors.json"


@pytest.fixture(scope="module")
def V():
    if not VECTORS_PATH.exists():
        pytest.skip("conformance/transparency/vectors.json is not present")
    return load_json(VECTORS_PATH)


def hx(text: str) -> bytes:
    return bytes.fromhex(text)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def keys_at(epochs: list, position: int) -> list:
    """The keys of the last epoch whose fromPosition <= position (the vectors' rule)."""
    keys: list = []
    for epoch in epochs:
        if epoch["fromPosition"] <= position:
            keys = epoch["keys"]
    return keys


# ---------------------------------------------------------------- the conformance vectors


def test_vector_file_header(V):
    assert V["schemaVersion"] == "irontrellis-transparency-vectors/1"
    for section in ("merkle", "notes", "keys", "checkpoints", "statements", "entries", "receipts", "latestNotes"):
        assert V[section], section


def test_merkle_leaf_hashes_and_roots(V):
    for vector_set in (V["merkle"]["published"], V["merkle"]["generated"]):
        leaves: list[bytes] = []
        for i, leaf in enumerate(vector_set["leaves"]):
            assert t.leaf_hash(hx(leaf)).hex() == vector_set["leafHashes"][i]
            leaves.append(hx(vector_set["leafHashes"][i]))
        for size, root in enumerate(vector_set["roots"]):
            assert t.root_of(leaves[:size]).hex() == root, f"{vector_set['source']} root {size}"


def test_merkle_inclusion_vectors(V):
    valid = 0
    for v in V["merkle"]["inclusion"]:
        actual = t.verify_inclusion(hx(v["leafHash"]), v["index"], v["size"], [hx(p) for p in v["proof"]], hx(v["root"]))
        assert actual is v["valid"], f"{v['source']} {v.get('desc', '')} {v['index']}/{v['size']}"
        valid += 1 if v["valid"] else 0
    assert valid > 20


def test_merkle_consistency_vectors(V):
    for v in V["merkle"]["consistency"]:
        actual = t.verify_consistency(v["from"], v["to"], hx(v["fromRoot"]), hx(v["toRoot"]), [hx(p) for p in v["proof"]])
        assert actual is v["valid"], f"{v['source']} {v.get('desc', '')} {v['from']}->{v['to']}"


def test_merkle_proof_builders_reproduce_valid_vectors(V):
    """The Python proof builders produce exactly the published / generated proofs."""
    sets = {s["source"]: [hx(h) for h in s["leafHashes"]] for s in (V["merkle"]["published"], V["merkle"]["generated"])}
    checked = 0
    for v in V["merkle"]["inclusion"]:
        if not v["valid"] or v["source"] not in sets:
            continue
        leaves = sets[v["source"]][:v["size"]]
        if len(leaves) == v["size"] and leaves[v["index"]].hex() == v["leafHash"] and t.root_of(leaves).hex() == v["root"]:
            assert [p.hex() for p in t.inclusion_proof(leaves, v["index"])] == v["proof"]
            checked += 1
    for v in V["merkle"]["consistency"]:
        if not v["valid"] or v["source"] not in sets:
            continue
        leaves = sets[v["source"]][:v["to"]]
        if len(leaves) == v["to"] and t.root_of(leaves).hex() == v["toRoot"] and v["from"] > 0:
            assert [p.hex() for p in t.consistency_proof(leaves, v["from"])] == v["proof"]
            checked += 1
    assert checked > 10


def test_notes_open(V):
    for v in V["notes"]:
        try:
            opened = t.open_note(v["note"], v["verifierKeys"])
            actual = {"ok": True, "body": opened.body, "verifiedBy": opened.verified_by}
        except t.NoteError as error:
            actual = {"ok": False, "error": error.code}
        assert actual == v["expect"], f"{v['source']}: {v['desc']}"


def test_keys_and_deterministic_signing(V):
    for v in V["keys"]["verifierKeys"]:
        try:
            parsed = t.parse_verifier_key(v["vkey"])
        except t.NoteError as error:
            assert error.code == "INVALID_KEY"
            parsed = None
        assert (parsed is not None) is v["valid"], v["vkey"]
        if parsed is not None:
            assert (parsed.name, parsed.key_hash.hex(), parsed.public_key.hex()) == (v["name"], v["keyHash"], v["publicKey"])
            assert t.verifier_key(parsed.name, parsed.public_key) == v["vkey"]
    for v in V["keys"]["signerKeys"]:
        try:
            signer = t.parse_signer_key(v["skey"])
        except t.NoteError as error:
            assert error.code == "INVALID_SIGNER"
            signer = None
        assert (signer is not None) is v["valid"], v["skey"]
        if signer is not None:
            assert t.verifier_key(signer.name, signer.public_key) == v["verifierKey"]
    for v in V["keys"]["signing"]:
        assert t.sign_note(v["body"], t.parse_signer_key(v["signerKey"])) == v["note"], v["source"]


def test_checkpoints_strict_parse(V):
    for v in V["checkpoints"]:
        try:
            parsed = t.parse_checkpoint(v["body"])
        except t.NoteError as error:
            assert error.code == "MALFORMED_CHECKPOINT"
            parsed = None
        assert (parsed is not None) is v["valid"], json.dumps(v["body"])
        if parsed is not None:
            assert {"origin": parsed.origin, "size": parsed.size, "root": b64(parsed.root), "extensions": parsed.extensions} == \
                {"origin": v["origin"], "size": v["size"], "root": v["root"], "extensions": v["extensions"]}
            assert t.format_checkpoint(parsed.origin, parsed.size, parsed.root, parsed.extensions) == v["body"]


def test_statements(V):
    for v in V["statements"]:
        epochs = v["ownerKeyEpochs"]
        result = t.verify_signed_head_statement(v["signed"], lambda position, epochs=epochs: keys_at(epochs, position))
        assert ("OK" if result["ok"] else result["reason"]) == v["expect"], v["desc"]
        # The same outcome with the epochs handed over directly (owner_keys.owner_keys_at).
        direct = t.verify_signed_head_statement(v["signed"], epochs)
        assert ("OK" if direct["ok"] else direct["reason"]) == v["expect"], v["desc"]
        if v["statementHash"] is not None:
            assert t.head_statement_hash(v["signed"]["statement"]) == v["statementHash"], v["desc"]
        else:
            assert isinstance(t.validate_head_statement(v["signed"]["statement"]), str), v["desc"]


def test_entries(V):
    for v in V["entries"]:
        assert (t.validate_entry(v["entry"]) is None) is v["valid"], v["desc"]
        if v["valid"]:
            assert t.encode_entry(v["entry"]).decode("utf-8") == v["canonical"], v["desc"]
            assert t.entry_leaf_hash(v["entry"]).hex() == v["leafHash"], v["desc"]


def test_rotated_entries_carry_previous_head(scenario):
    """WITNESS-DESIGN §9.2: a ROTATED leaf names the head its owner signature binds, one position before rotationHead."""
    rotated = scenario["receipts"][4]["entry"]
    assert rotated["kind"] == "ROTATED" and t.validate_entry(rotated) is None
    assert rotated["rotationHead"]["position"] == rotated["previousHead"]["position"] + 1
    without = {k: v for k, v in rotated.items() if k != "previousHead"}
    assert "ROTATED entry fields" in t.validate_entry(without)
    assert t.validate_entry({**rotated, "previousHead": {**rotated["previousHead"], "position": 7}}) == "rotationHead.position must be previousHead.position + 1"
    assert t.validate_entry({**rotated, "previousHead": {"hash": rotated["previousHead"]["hash"]}}) == "previousHead must be {hash, position}"
    assert t.validate_entry({**rotated, "previousHead": {**rotated["previousHead"], "extra": 1}}) == "previousHead must be {hash, position}"
    # ROTATED is the only key-event leaf: a COMMITTED-shaped leaf is an unknown kind (as in TypeScript).
    committed = {**{k: v for k, v in rotated.items() if k not in ("rotation", "rotationHead")}, "kind": "COMMITTED", "event": rotated["rotation"], "eventHead": rotated["rotationHead"]}
    assert t.validate_entry(committed) == "kind must be one of REGISTERED, HEAD, ROTATED, EQUIVOCATION, SUPERSEDED"
    assert t.WITNESS_ENTRY_KINDS == ("REGISTERED", "HEAD", "ROTATED", "EQUIVOCATION", "SUPERSEDED")


def test_receipts(V):
    for v in V["receipts"]:
        result = t.verify_witness_receipt(v["receipt"], v["trustedVerifierKeys"])
        if result["ok"]:
            cp = result["checkpoint"]
            actual = {"ok": True, "index": result["index"], "checkpoint": {"origin": cp["origin"], "size": cp["size"], "root": b64(cp["root"])}}
        else:
            actual = {"ok": False, "reason": result["reason"]}
        assert actual == v["expect"], v["desc"]


# ---------------------------------------------------------------- scenario material


WITNESS_SEED = bytes([0x77]) * 32
OTHER_WITNESS_SEED = bytes([0x78]) * 32
OWNER1_SEED = bytes.fromhex(f"{0x3001:064x}")
ORIGIN = "irontrellis-witness/vectors"


@pytest.fixture(scope="module")
def scenario(V):
    receipts = [v for v in V["receipts"] if v["expect"]["ok"] and v["expect"]["checkpoint"]["size"] == 7]
    receipts.sort(key=lambda v: v["expect"]["index"])
    entries = [v["receipt"]["entry"] for v in receipts]
    assert len(entries) == 7
    return {
        "entries": entries,
        "receipts": [v["receipt"] for v in receipts],
        "vkey": receipts[0]["trustedVerifierKeys"][0],
        "leaves": [t.entry_leaf_hash(entry) for entry in entries],
    }


def test_python_signers_reproduce_the_scenario_signatures(V, scenario):
    """Ed25519 is deterministic: the Python signer reproduces the witness checkpoint and the owner statement signatures."""
    witness = t.note_signer_from_seed(ORIGIN, WITNESS_SEED)
    assert t.verifier_key(witness.name, witness.public_key) == scenario["vkey"]
    note = t.sign_note(t.format_checkpoint(ORIGIN, 7, t.root_of(scenario["leaves"])), witness)
    assert note == scenario["receipts"][0]["checkpoint"]
    first = next(v for v in V["statements"] if v["desc"] == "first statement (previous null)")
    digest = t.head_statement_hash(first["signed"]["statement"])
    assert "0x" + ed25519.sign(OWNER1_SEED, bytes.fromhex(digest[2:])).hex() == first["signed"]["signature"]


def test_receipt_proofs_match_the_python_tree(scenario):
    for index, receipt in enumerate(scenario["receipts"]):
        assert [b64(p) for p in t.inclusion_proof(scenario["leaves"], index)] == receipt["inclusionProof"]


# ---------------------------------------------------------------- receipt tampering


def _reason(receipt, keys) -> str:
    result = t.verify_witness_receipt(receipt, keys)
    return "OK" if result["ok"] else result["reason"]


def test_receipt_tamper_cases(scenario):
    vkey = scenario["vkey"]
    good = scenario["receipts"][3]  # HEAD 6 <- 3
    assert _reason(good, [vkey]) == "OK"

    def altered(mutate):
        receipt = copy.deepcopy(good)
        mutate(receipt)
        return receipt

    # Structure (RECEIPT_MALFORMED comes first, before any note work).
    assert _reason(None, [vkey]) == "RECEIPT_MALFORMED"
    assert _reason([], [vkey]) == "RECEIPT_MALFORMED"
    assert _reason(altered(lambda r: r.update(index=True)), [vkey]) == "RECEIPT_MALFORMED"
    assert _reason(altered(lambda r: r.update(index=-1)), [vkey]) == "RECEIPT_MALFORMED"
    assert _reason(altered(lambda r: r.update(index=3.5)), [vkey]) == "RECEIPT_MALFORMED"
    assert _reason(altered(lambda r: r.update(index=2**53)), [vkey]) == "RECEIPT_MALFORMED"
    assert _reason(altered(lambda r: r.update(inclusionProof="abc")), [vkey]) == "RECEIPT_MALFORMED"
    assert _reason(altered(lambda r: r["witness"].pop("verifierKey")), [vkey]) == "RECEIPT_MALFORMED"
    assert _reason(altered(lambda r: r.update(checkpoint=None, index="x")), [vkey]) == "RECEIPT_MALFORMED"
    # A JSON number is a JavaScript number: 3.0 is the index 3.
    assert _reason(altered(lambda r: r.update(index=3.0)), [vkey]) == "OK"

    # Trust comes from the caller's keys only, never from the key the receipt names.
    assert _reason(good, []) == "NOTE_UNVERIFIED"
    assert _reason(good, "not a list") == "NOTE_UNVERIFIED"
    assert _reason(good, ["garbage"]) == "NOTE_UNVERIFIED"
    assert _reason(good, [["unhashable"]]) == "NOTE_UNVERIFIED"
    huge = t.sign_note(f"{ORIGIN}\n{'9' * 5000}\n{b64(bytes(32))}\n", t.note_signer_from_seed(ORIGIN, WITNESS_SEED))
    assert _reason(altered(lambda r: r.update(checkpoint=huge)), [vkey]) == "CHECKPOINT_MALFORMED"
    other = t.note_signer_from_seed(ORIGIN, OTHER_WITNESS_SEED)
    other_vkey = t.verifier_key(other.name, other.public_key)
    assert _reason(good, [other_vkey]) == "NOTE_UNVERIFIED"
    assert _reason(altered(lambda r: r["witness"].update(verifierKey=other_vkey)), [vkey]) == "OK"
    forged = t.sign_note(t.format_checkpoint(ORIGIN, 7, t.root_of(scenario["leaves"])), other)
    assert _reason(altered(lambda r: r.update(checkpoint=forged)), [vkey]) == "NOTE_UNVERIFIED"
    # A cosignature by an unknown key is ignored; a known key's bad signature is not.
    cosigned = good["checkpoint"] + forged.split("\n\n", 1)[1].replace(ORIGIN, "someone-else/log", 1)
    assert _reason(altered(lambda r: r.update(checkpoint=cosigned)), [vkey]) == "OK"
    lines = good["checkpoint"].split("\n")
    signature_line = next(line for line in lines if line.startswith("— "))
    raw = bytearray(base64.b64decode(signature_line.split(" ")[2]))
    raw[10] ^= 1
    bad = good["checkpoint"].replace(signature_line, f"— {ORIGIN} {b64(bytes(raw))}")
    assert _reason(altered(lambda r: r.update(checkpoint=bad)), [vkey]) == "NOTE_UNVERIFIED"

    # A validly signed note that is not a checkpoint; an origin mismatch.
    witness = t.note_signer_from_seed(ORIGIN, WITNESS_SEED)
    assert _reason(altered(lambda r: r.update(checkpoint=t.sign_note("hello\n", witness))), [vkey]) == "CHECKPOINT_MALFORMED"
    assert _reason(altered(lambda r: r["witness"].update(origin="irontrellis-witness/other")), [vkey]) == "ORIGIN_MISMATCH"

    # Entry problems.
    assert _reason(altered(lambda r: r.pop("entry")), [vkey]) == "ENTRY_MALFORMED"
    assert _reason(altered(lambda r: r["entry"].update(extra=1)), [vkey]) == "ENTRY_MALFORMED"
    assert _reason(altered(lambda r: r["entry"]["signedStatement"]["statement"].update(historyId="0x" + "00" * 32)), [vkey]) == "ENTRY_MALFORMED"
    registered = copy.deepcopy(scenario["receipts"][0])
    registered["entry"]["genesis"]["timestamp"] = 1
    assert _reason(registered, [vkey]) == "ENTRY_MALFORMED"

    # Index and proof problems.
    assert _reason(altered(lambda r: r.update(index=7)), [vkey]) == "INDEX_OUT_OF_RANGE"
    assert _reason(altered(lambda r: r.update(index=4)), [vkey]) == "INCLUSION_INVALID"
    assert _reason(altered(lambda r: r["inclusionProof"].append(r["inclusionProof"][0])), [vkey]) == "INCLUSION_INVALID"
    assert _reason(altered(lambda r: r["inclusionProof"].pop()), [vkey]) == "INCLUSION_INVALID"
    assert _reason(altered(lambda r: r["inclusionProof"].reverse()), [vkey]) == "INCLUSION_INVALID"
    assert _reason(altered(lambda r: r["inclusionProof"].__setitem__(0, r["inclusionProof"][0].rstrip("="))), [vkey]) == "INCLUSION_INVALID"
    assert _reason(altered(lambda r: r["inclusionProof"].__setitem__(0, b64(bytes(31)))), [vkey]) == "INCLUSION_INVALID"
    assert _reason(altered(lambda r: r["inclusionProof"].__setitem__(0, 42)), [vkey]) == "INCLUSION_INVALID"
    # Signature bytes of the recorded statement are part of the leaf: changing them breaks inclusion, not the structure.
    flipped = altered(lambda r: r["entry"]["signedStatement"].update(signature="0x" + "11" * 64))
    assert _reason(flipped, [vkey]) == "INCLUSION_INVALID"
    assert _reason(altered(lambda r: r["entry"].update(receivedAt=r["entry"]["receivedAt"] + 1)), [vkey]) == "INCLUSION_INVALID"


def test_receipt_order_of_reasons(scenario):
    """With several faults, the earliest reason in the documented order wins."""
    vkey = scenario["vkey"]
    receipt = copy.deepcopy(scenario["receipts"][1])
    receipt["witness"]["origin"] = "elsewhere"
    receipt["entry"]["kind"] = "NOPE"
    receipt["index"] = 99
    assert _reason(receipt, [vkey]) == "ORIGIN_MISMATCH"
    receipt["witness"]["origin"] = ORIGIN
    assert _reason(receipt, [vkey]) == "ENTRY_MALFORMED"
    receipt["entry"]["kind"] = "HEAD"
    assert _reason(receipt, [vkey]) == "INDEX_OUT_OF_RANGE"
    assert _reason(receipt, []) == "NOTE_UNVERIFIED"


# ---------------------------------------------------------------- notes, keys, base64


def test_strict_base64():
    assert t.decode_base64("AA==") == b"\x00"
    for text in ("AB==", "AA=", "AA", "A===", "AA==\n", " AA==", "AA-_", "AAA=A===", None, 5):
        assert t.decode_base64(text) is None, text
    assert t.decode_base64("") == b""


def test_note_edge_cases(V):
    base = next(v for v in V["notes"] if v["desc"] == "TestSign/TestOpen: one known signer")
    note, keys = base["note"], base["verifierKeys"]
    assert t.open_note(note, keys).verified_by == keys
    assert t.open_note(note, keys + keys).verified_by == keys
    # The same key spelled with an upper-case hash is the same verifier (first spelling reported).
    upper = keys[0].replace("c74f20a3", "C74F20A3")
    assert t.open_note(note, [upper, keys[0]]).verified_by == [upper]

    def code(text, verifier_keys=keys):
        try:
            t.open_note(text, verifier_keys)
        except t.NoteError as error:
            return error.code
        return "OK"

    body, signature = note.split("\n\n")
    line = signature.rstrip("\n")
    assert code(note, ["not a key"]) == "INVALID_KEY"
    assert code(note, "PeterNeumann") == "INVALID_KEY"
    assert code(note, [{"not": "hashable"}]) == "INVALID_KEY"
    assert code(None) == "MALFORMED_NOTE"
    assert code(body + "\ud800\n\n" + signature) == "MALFORMED_NOTE"          # lone surrogate
    assert code(body + "\x7f\n\n" + signature) == "INVALID_SIGNATURE"         # DEL is text; it changes the signed bytes
    assert code(body + "\n\n" + line.replace("—", "-") + "\n") == "MALFORMED_NOTE"
    assert code(body + "\n\n" + line.replace(" ", "  ", 1) + "\n") == "MALFORMED_NOTE"
    assert code(body + "\n\n" + line.replace("PeterNeumann", "Peter Neumann") + "\n") == "MALFORMED_NOTE"
    assert code(body + "\n\n" + line.replace("PeterNeumann", "Peter+Neumann") + "\n") == "MALFORMED_NOTE"
    assert code(body + "\n\n" + "— PeterNeumann AAAA\n") == "MALFORMED_NOTE"  # fewer than 5 bytes
    # 100 signature lines are accepted, 101 are not.
    unknown = "— Unknown " + b64(bytes(68))
    assert code(body + "\n\n" + line + "\n" + "\n".join([unknown] * 99) + "\n") == "OK"
    assert code(body + "\n\n" + line + "\n" + "\n".join([unknown] * 100) + "\n") == "MALFORMED_NOTE"
    # A known key hash with a short signature is a bad signature, not a malformed note.
    raw = base64.b64decode(line.split(" ")[2])
    assert code(body + "\n\n" + f"— PeterNeumann {b64(raw[:40])}\n") == "INVALID_SIGNATURE"
    # Only unknown keys: unverified.
    assert code(body + "\n\n" + unknown + "\n") == "UNVERIFIED_NOTE"


def test_note_key_rules():
    public = ed25519.public_key_from_seed(bytes(32))
    for name in ("", "a b", "a+b", "a　b", "a b", "\ud800"):
        with pytest.raises(t.NoteError) as info:
            t.note_key_hash(name, public)
        assert info.value.code == "INVALID_KEY"
    with pytest.raises(t.NoteError):
        t.note_key_hash("ok", public[:31])
    vkey = t.verifier_key("example.com/log", public)
    parsed = t.parse_verifier_key(vkey)
    assert parsed.public_key == public and parsed.name == "example.com/log"
    other_algorithm = f"example.com/log+{parsed.key_hash.hex()}+{b64(bytes([2]) + public)}"
    for bad in (vkey + "=", vkey.replace("+", "-", 1), other_algorithm, "a+b", 7):
        with pytest.raises(t.NoteError):
            t.parse_verifier_key(bad)
    with pytest.raises(t.NoteError) as info:
        t.sign_note("no newline", t.note_signer_from_seed("k", bytes(32)))
    assert info.value.code == "MALFORMED_NOTE"


def test_checkpoint_edge_cases():
    root = b64(bytes(32))
    assert t.parse_checkpoint(f"o\n0\n{root}\n").size == 0
    for body in (f"o\n{'9' * 5000}\n{root}\n", f"o\n+1\n{root}\n", f"o\n1 \n{root}\n", f"o\n١\n{root}\n", f"o\n1\n{root}\nx\n\n", f"o\r\n1\n{root}\n", 5):
        with pytest.raises(t.NoteError) as info:
            t.parse_checkpoint(body)
        assert info.value.code == "MALFORMED_CHECKPOINT"


# ---------------------------------------------------------------- Merkle properties


def test_merkle_inclusion_and_consistency_properties():
    rng = random.Random(6962)
    leaves = [t.leaf_hash(i.to_bytes(4, "big")) for i in range(64)]
    roots = [t.root_of(leaves[:n]) for n in range(65)]
    assert roots[0] == t.empty_root()
    for size in range(1, 65):
        for index in range(size):
            proof = t.inclusion_proof(leaves[:size], index)
            assert t.verify_inclusion(leaves[index], index, size, proof, roots[size])
            if size > 1:
                assert not t.verify_inclusion(leaves[index], (index + 1) % size, size, proof, roots[size])
            if proof:
                j = rng.randrange(len(proof))
                tampered = [bytes(p) for p in proof]
                tampered[j] = bytes([tampered[j][0] ^ 1]) + tampered[j][1:]
                assert not t.verify_inclusion(leaves[index], index, size, tampered, roots[size])
                assert not t.verify_inclusion(leaves[index], index, size, proof[:-1], roots[size])
    pairs = [(m, n) for n in range(1, 65) for m in range(0, n + 1)]
    for m, n in rng.sample(pairs, 600) + [(m, n) for n in range(1, 17) for m in range(0, n + 1)]:
        proof = t.consistency_proof(leaves[:n], m)
        assert t.verify_consistency(m, n, roots[m], roots[n], proof), (m, n)
        if 0 < m < n:
            assert not t.verify_consistency(m, n, roots[m], roots[n - 1] if n - 1 != m else roots[0], proof), (m, n)
            assert not t.verify_consistency(m, n, roots[n], roots[n], proof), (m, n)
            j = rng.randrange(len(proof))
            tampered = [bytes(p) for p in proof]
            tampered[j] = bytes([tampered[j][0] ^ 1]) + tampered[j][1:]
            assert not t.verify_consistency(m, n, roots[m], roots[n], tampered), (m, n)


def test_latest_notes(V):
    """Witness-signed latest notes (docs/reference/witness-protocol.md §9.8): format, strict parse and verification against the request."""
    for v in V["latestNotes"]["format"]:
        if v["valid"]:
            assert t.format_latest_note(v["fields"]) == v["body"], v["desc"]
        else:
            with pytest.raises(t.NoteError) as raised:
                t.format_latest_note(v["fields"])
            assert raised.value.code == v["error"], v["desc"]
    for v in V["latestNotes"]["parse"]:
        if v["valid"]:
            assert t.parse_latest_note(v["body"]) == v["fields"], v["desc"]
        else:
            with pytest.raises(t.NoteError) as raised:
                t.parse_latest_note(v["body"])
            assert raised.value.code == v["error"], v["desc"]
    for v in V["latestNotes"]["verify"]:
        result = t.verify_latest_note(v["note"], v["trustedVerifierKeys"], v["expect"])
        actual = {"ok": True, "latest": result["latest"]} if result["ok"] else {"ok": False, "reason": result["reason"]}
        assert actual == v["result"], v["desc"]


def test_latest_note_expectation_must_be_a_well_formed_plain_dict(V):
    """Review block 3, L2: an expectation of any other shape used to expect nothing (a replayed answer passed)."""
    import collections
    import types

    v = V["latestNotes"]["verify"][0]
    good = v["expect"]
    wrong = dict(good, nonce="A" * 43)
    assert t.verify_latest_note(v["note"], v["trustedVerifierKeys"], good)["ok"] is True
    assert t.verify_latest_note(v["note"], v["trustedVerifierKeys"], wrong)["reason"] == "NONCE_MISMATCH"
    assert t.verify_latest_note(v["note"], v["trustedVerifierKeys"], {"historyId": good["historyId"], "nonce": good["nonce"]})["ok"] is True

    class Expect(collections.UserDict):
        pass

    class DictSubclass(dict):
        pass

    invalid = {
        # The review's PoC (latest-expect.py): these three carried a wrong nonce and returned ok: True.
        "MappingProxyType": types.MappingProxyType(wrong), "UserDict subclass": Expect(wrong), "list": ["nonce"],
        "MappingProxyType, right nonce": types.MappingProxyType(good), "dict subclass": DictSubclass(good), "OrderedDict": collections.OrderedDict(good),
        "None": None, "a string": "nonce", "a number": 7, "empty dict": {}, "no nonce": {"origin": good["origin"], "historyId": good["historyId"]},
        "no history id": {"origin": good["origin"], "nonce": good["nonce"]}, "nonce None": dict(good, nonce=None), "nonce a number": dict(good, nonce=7),
        "nonce bytes": dict(good, nonce=good["nonce"].encode()), "nonce padded": dict(good, nonce=good["nonce"] + "="),
        "history id uppercase": dict(good, historyId=good["historyId"].upper()), "origin None": dict(good, origin=None), "origin empty": dict(good, origin=""),
        "origin two lines": dict(good, origin=good["origin"] + "\nx"), "origin a version line": dict(good, origin="irontrellis-witness-latest/1"),
        "a misspelt key": dict(good, nonces=good["nonce"]), "a non-string key": {**good, 1: "x"},
    }
    for name, expectation in invalid.items():
        result = t.verify_latest_note(v["note"], v["trustedVerifierKeys"], expectation)
        assert (result["ok"], result.get("reason")) == (False, "EXPECTATION_INVALID"), name
    assert t.verify_latest_note(v["note"], v["trustedVerifierKeys"])["reason"] == "EXPECTATION_INVALID"  # omitted
    assert t.verify_latest_note(7, v["trustedVerifierKeys"], None)["reason"] == "EXPECTATION_INVALID"  # checked first
    assert t.verify_latest_note(7, v["trustedVerifierKeys"], good)["reason"] == "NOTE_UNVERIFIED"


def test_latest_note_nonces_and_domain_separation(V):
    assert t.is_valid_nonce(base64.urlsafe_b64encode(bytes(16)).decode().rstrip("="))
    assert not t.is_valid_nonce(base64.urlsafe_b64encode(bytes(15)).decode().rstrip("="))
    assert not t.is_valid_nonce(base64.urlsafe_b64encode(bytes(65)).decode().rstrip("="))
    assert not t.is_valid_nonce("A" * 21 + "B")  # 22 chars whose last carries non-zero padding bits
    assert not t.is_valid_nonce(7) and not t.is_valid_nonce("")
    # A checkpoint never parses as a latest note and a latest note never parses as a checkpoint.
    body = next(v["body"] for v in V["latestNotes"]["format"] if v["valid"])
    with pytest.raises(t.NoteError):
        t.parse_checkpoint(body)
    with pytest.raises(t.NoteError):
        t.parse_latest_note(next(v["body"] for v in V["checkpoints"] if v["valid"]))


def test_merkle_verifiers_never_raise():
    leaf = t.leaf_hash(b"x")
    junk = [None, "", 1.5, -1, True, b"short", [b"\x00" * 32], object(), 2**64]
    for value in junk:
        assert t.verify_inclusion(value, 0, 1, [], leaf) is False
        assert t.verify_inclusion(leaf, value, 1, [], leaf) is False
        assert t.verify_inclusion(leaf, 0, value, [], leaf) is False
        assert t.verify_inclusion(leaf, 0, 1, value, leaf) is False
        assert t.verify_consistency(value, 1, leaf, leaf, []) is False
        assert t.verify_consistency(1, 2, leaf, leaf, [value]) is False
    assert t.verify_inclusion(leaf, 0, 1, [], leaf) is True
    assert t.verify_inclusion(leaf, 0, 1, [leaf], leaf) is False
    assert t.verify_consistency(0, 5, leaf, t.empty_root(), []) is True
    assert t.verify_consistency(0, 5, leaf, leaf, [leaf]) is False
    assert t.verify_consistency(3, 3, leaf, leaf, []) is True
    assert t.verify_consistency(3, 3, leaf, leaf, [leaf]) is False
    assert t.verify_consistency(4, 3, leaf, leaf, []) is False


# ---------------------------------------------------------------- statements


def test_statement_edge_cases(V):
    good = next(v for v in V["statements"] if v["desc"] == "chained 3 <- 0")
    signed, epochs = good["signed"], good["ownerKeyEpochs"]
    assert t.verify_signed_head_statement(signed, epochs) == {"ok": True}

    def boom(position):
        raise RuntimeError("no keys")

    assert t.verify_signed_head_statement(signed, boom) == {"ok": False, "reason": "UNKNOWN_KEY"}
    assert t.verify_signed_head_statement(signed, lambda p: None) == {"ok": False, "reason": "UNKNOWN_KEY"}
    assert t.verify_signed_head_statement(None, epochs) == {"ok": False, "reason": "MALFORMED"}
    wrong_scheme = [{**key, "scheme": "eip191-personal-sign-keccak256"} for key in epochs[0]["keys"]]
    assert t.verify_signed_head_statement(signed, lambda p: wrong_scheme)["reason"] == "UNKNOWN_KEY"
    bad_credential = [{**key, "credential": "nope"} for key in epochs[0]["keys"]]
    assert t.verify_signed_head_statement(signed, lambda p: bad_credential)["reason"] == "SIGNATURE_INVALID"

    statement = signed["statement"]
    assert t.validate_head_statement(statement) is None
    for mutate in (
        lambda s: s["head"].update(position=True),
        lambda s: s["head"].update(position=-1),
        lambda s: s["head"].update(position=1.5),
        lambda s: s["head"].update(hash=s["head"]["hash"].upper()),
        lambda s: s["domain"].update(version="2"),
        lambda s: s["domain"].update(extra="x"),
        lambda s: s.update(previous={"hash": s["historyId"], "position": 0, "canonicalTime": 0}),
        lambda s: s.update(previous={"hash": "0x" + "ab" * 32, "position": 0}),   # position 0 must be the history id
        lambda s: s["head"].update(position=0),                                      # head at 0 must be the history id
        lambda s: s.update(version="irontrellis-head-statement/2"),
    ):
        changed = copy.deepcopy(statement)
        mutate(changed)
        assert isinstance(t.validate_head_statement(changed), str)
        with pytest.raises(ValueError):
            t.head_statement_hash(changed)
    as_float = copy.deepcopy(statement)
    as_float["head"]["position"] = float(as_float["head"]["position"])
    assert t.head_statement_hash(as_float) == t.head_statement_hash(statement)


# ---------------------------------------------------------------- CLI


def test_cli_verify_receipt(tmp_path, capsys, scenario):
    vkey = scenario["vkey"]
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(scenario["receipts"][3]), encoding="utf-8")
    assert cli_main(["verify-receipt", str(path), "--verifier-key", vkey]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "VALID" and out["index"] == 3 and out["checkpoint"]["size"] == 7
    assert out["entry"]["kind"] == "HEAD" and out["entry"]["head"]["position"] == 6
    path.write_text(json.dumps(scenario["receipts"][4]), encoding="utf-8")
    assert cli_main(["verify-receipt", str(path), "--verifier-key", vkey]) == 0
    rotated = json.loads(capsys.readouterr().out)["entry"]
    assert rotated["kind"] == "ROTATED" and rotated["previousHead"]["position"] == 6 and rotated["rotationHead"]["position"] == 7
    # A server response wrapping the receipt is accepted too.
    path.write_text(json.dumps({"status": "APPENDED", "receipt": scenario["receipts"][0]}), encoding="utf-8")
    assert cli_main(["verify-receipt", str(path), "--verifier-key", vkey]) == 0
    assert json.loads(capsys.readouterr().out)["entry"]["kind"] == "REGISTERED"
    other = t.note_signer_from_seed(ORIGIN, OTHER_WITNESS_SEED)
    assert cli_main(["verify-receipt", str(path), "--verifier-key", t.verifier_key(other.name, other.public_key)]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "INVALID" and out["reason"] == "NOTE_UNVERIFIED"
    path.write_text("{not json", encoding="utf-8")
    assert cli_main(["verify-receipt", str(path), "--verifier-key", vkey]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "ERROR"


def test_receipt_verification_never_raises(scenario):
    """Random structural damage anywhere in a receipt yields a reason, never an exception."""
    rng = random.Random(9162)
    junk = [None, True, -1, 1.5, 2**70, "", "\ud800", "0x" + "00" * 32, [], {}, {"$continuity.bigint": "1"}, {"$continuity.bigint": "x"}, [[[]]]]

    def paths(value, prefix=()):
        yield prefix
        if isinstance(value, dict):
            for key, member in value.items():
                yield from paths(member, (*prefix, key))
        elif isinstance(value, list):
            for index, member in enumerate(value):
                yield from paths(member, (*prefix, index))

    for base in scenario["receipts"]:
        every = list(paths(base))[1:]
        for _ in range(60):
            receipt = copy.deepcopy(base)
            path = rng.choice(every)
            target = receipt
            for step in path[:-1]:
                target = target[step]
            if isinstance(target, dict) and rng.random() < 0.2:
                del target[path[-1]]
            else:
                target[path[-1]] = copy.deepcopy(rng.choice(junk))
            result = t.verify_witness_receipt(receipt, [scenario["vkey"]])
            assert isinstance(result, dict) and (result["ok"] or result["reason"] in {
                "RECEIPT_MALFORMED", "NOTE_UNVERIFIED", "CHECKPOINT_MALFORMED", "ORIGIN_MISMATCH", "ENTRY_MALFORMED", "INDEX_OUT_OF_RANGE", "INCLUSION_INVALID"})


# ---------------------------------------------------------------- differential against the TypeScript core


def _edit_text(rng: random.Random, text: str) -> str:
    alphabet = ["\n", " ", "—", "=", "+", "/", "A", "a", "0", "9", "\x01", "\x7f", " ", "\ud800", " ", "-"]
    chars = list(text)
    for _ in range(rng.randint(1, 3)):
        op = rng.random()
        position = rng.randrange(len(chars) + 1)
        if op < 0.4 and chars:
            del chars[min(position, len(chars) - 1)]
        elif op < 0.8:
            chars.insert(position, rng.choice(alphabet))
        elif chars:
            chars[min(position, len(chars) - 1)] = rng.choice(alphabet)
    return "".join(chars)


def _damage(rng: random.Random, value, junk):
    """A deep copy of ``value`` with one random member replaced or removed."""
    value = copy.deepcopy(value)
    members = []

    def walk(node, prefix):
        if isinstance(node, dict):
            for key, member in node.items():
                members.append((*prefix, key))
                walk(member, (*prefix, key))
        elif isinstance(node, list):
            for index, member in enumerate(node):
                members.append((*prefix, index))
                walk(member, (*prefix, index))

    walk(value, ())
    if not members:
        return rng.choice(junk)
    path = rng.choice(members)
    target = value
    for step in path[:-1]:
        target = target[step]
    current = target[path[-1]]
    if isinstance(target, dict) and rng.random() < 0.15:
        del target[path[-1]]
    elif isinstance(current, str) and current and rng.random() < 0.5:
        target[path[-1]] = _edit_text(rng, current)
    elif isinstance(current, int) and not isinstance(current, bool) and rng.random() < 0.5:
        target[path[-1]] = rng.choice([current + 1, current - 1, float(current), -current, 2**53])
    else:
        target[path[-1]] = copy.deepcopy(rng.choice(junk))
    return value


def test_differential_against_typescript_core(V, scenario):
    """Randomly damaged receipts, notes, checkpoints, statements and entries get the same outcome from both cores."""
    import subprocess

    from conftest import NODE, REPO_ROOT
    helper = REPO_ROOT / "python" / "tests" / "differential_transparency.mjs"
    if NODE is None or not (REPO_ROOT / "packages" / "core" / "dist" / "transparency" / "index.js").exists():
        pytest.skip("node and packages/core/dist/transparency are required for the differential test")
    rng = random.Random(2026)
    junk = [None, True, False, 0, -1, 1.5, 7.0, -0.0, 2**53, "", "\ud800", "0x" + "00" * 32, [], {}, {"$continuity.bigint": "1"}, [[[]]]]
    vkey = scenario["vkey"]
    receipts = [{"receipt": copy.deepcopy(r), "keys": [vkey]} for r in scenario["receipts"]]
    for _ in range(400):
        base = rng.choice(scenario["receipts"])
        if rng.random() < 0.3:
            damaged = copy.deepcopy(base)
            damaged["checkpoint"] = _edit_text(rng, damaged["checkpoint"])
        else:
            damaged = _damage(rng, base, junk)
        receipts.append({"receipt": damaged, "keys": rng.choice([[vkey], [vkey, vkey.upper()], [], [vkey, "bad"]])})
    notes = [{"note": v["note"], "keys": v["verifierKeys"]} for v in V["notes"]]
    for _ in range(400):
        v = rng.choice(V["notes"])
        notes.append({"note": _edit_text(rng, v["note"]), "keys": v["verifierKeys"]})
    checkpoints = [v["body"] for v in V["checkpoints"]] + [_edit_text(rng, rng.choice(V["checkpoints"])["body"]) for _ in range(300)]
    statements = [{"signed": v["signed"], "epochs": v["ownerKeyEpochs"]} for v in V["statements"]]
    for _ in range(300):
        v = rng.choice(V["statements"])
        statements.append({"signed": _damage(rng, v["signed"], junk), "epochs": v["ownerKeyEpochs"]})
    entries = [v["entry"] for v in V["entries"]] + [_damage(rng, rng.choice(V["entries"])["entry"], junk) for _ in range(300)]
    batch = {"receipts": receipts, "notes": notes, "checkpoints": checkpoints, "statements": statements, "entries": entries}
    text = json.dumps(batch)
    batch = json.loads(text)  # evaluate exactly what node parses
    completed = subprocess.run([NODE, str(helper)], input=text, capture_output=True, text=True, encoding="utf-8", timeout=300, check=True)
    expected = json.loads(completed.stdout)

    for case, want in zip(batch["receipts"], expected["receipts"]):
        r = t.verify_witness_receipt(case["receipt"], case["keys"])
        got = {"ok": True, "index": r["index"], "size": r["checkpoint"]["size"], "root": b64(r["checkpoint"]["root"]), "verifiedBy": r["verifiedBy"]} \
            if r["ok"] else {"ok": False, "reason": r["reason"]}
        assert got == want, json.dumps(case)[:400]
    for case, want in zip(batch["notes"], expected["notes"]):
        try:
            opened = t.open_note(case["note"], case["keys"])
            got = {"ok": True, "body": opened.body, "verifiedBy": opened.verified_by}
        except t.NoteError as error:
            got = {"ok": False, "error": error.code}
        assert got == want, json.dumps(case)[:400]
    for body, want in zip(batch["checkpoints"], expected["checkpoints"]):
        try:
            c = t.parse_checkpoint(body)
            got = {"ok": True, "origin": c.origin, "size": c.size, "root": b64(c.root), "extensions": c.extensions}
        except t.NoteError as error:
            got = {"ok": False, "error": error.code}
        assert got == want, json.dumps(body)
    for case, want in zip(batch["statements"], expected["statements"]):
        r = t.verify_signed_head_statement(case["signed"], lambda p, e=case["epochs"]: keys_at(e, p))
        assert ("OK" if r["ok"] else r["reason"]) == want, json.dumps(case)[:400]
    for entry, want in zip(batch["entries"], expected["entries"]):
        reason = t.validate_entry(entry)
        got = {"valid": True, "leafHash": t.entry_leaf_hash(entry).hex()} if reason is None else {"valid": False}
        assert got == want, json.dumps(entry)[:400]
    outcomes = {("OK" if w["ok"] else w["reason"]) for w in expected["receipts"]}
    assert len(outcomes) >= 5, outcomes
