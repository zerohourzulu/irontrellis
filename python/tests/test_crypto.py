"""keccak-256, secp256k1 recovery, EIP-191, Ed25519 and the history hasher against the spec 04 vectors."""
from __future__ import annotations

import hashlib
import os

import pytest

from irontrellis.canonical import canonical_encode, from_plain
from irontrellis.crypto import ed25519, secp256k1
from irontrellis.crypto.keccak import KeccakState, keccak256
from irontrellis.crypto.suites import eip191_digest_hex, is_signature_65, recover_content_hash_signer, suite_for
from irontrellis.hashing import HistoryHasher, hash_canonical, hash_event_history, hash_event_history_prefixes
from irontrellis.authority import create_runtime_authorization_challenge, hash_runtime_authorization_challenge
from irontrellis.events import control_authorization_hash


def test_keccak_vectors(crypto_vectors):
    for vector in crypto_vectors["keccak256"]:
        assert "0x" + keccak256(bytes.fromhex(vector["inputHex"][2:])).hex() == vector["keccak256"]


def test_keccak_incremental_clone_and_finalize(crypto_vectors):
    states: dict[str, KeccakState] = {}
    for step in crypto_vectors["keccakIncremental"]["steps"]:
        if step["op"] == "create":
            states[step["state"]] = KeccakState()
        elif step["op"] == "update":
            states[step["state"]].update(step["inputUtf8"].encode("utf-8"))
        elif step["op"] == "clone":
            states[step["to"]] = states[step["from"]].clone()
        elif step["op"] == "finalize":
            assert "0x" + states[step["state"]].finalize().hex() == step["digest"], step.get("note")


def test_keccak_block_boundaries():
    for length in (0, 1, 135, 136, 137, 271, 272, 273, 1000):
        data = bytes(range(256)) * 4
        data = data[:length]
        state = KeccakState()
        for offset in range(0, length, 7):
            state.update(data[offset:offset + 7])
        assert state.finalize() == keccak256(data)


def test_eip191_recovery_vectors(crypto_vectors):
    for vector in crypto_vectors["eip191"]:
        assert eip191_digest_hex(vector["contentHash"]) == vector["eip191Digest"]
        assert recover_content_hash_signer(vector["contentHash"], vector["signature"]) == vector["recoveredAddress"]
        assert suite_for("eip191-personal-sign-keccak256").verify(vector["contentHash"], vector["signature"], vector.get("expectedAddressChecksummed", vector["recoveredAddress"]))
    for vector in crypto_vectors["eip191Rejections"]:
        assert recover_content_hash_signer(vector["contentHash"], vector["signature"]) == vector["recovered"], vector["why"]


def test_keys_derive_their_addresses(crypto_vectors):
    for key in crypto_vectors["keys"].values():
        point = secp256k1.public_key_from_private(int(key["privateKey"], 16))
        assert secp256k1.address_from_public_key(point) == key["addressLowercase"]


def test_sign_then_recover_round_trip():
    private_key = 0x1001
    digest = hashlib.sha256(b"irontrellis").digest()
    signature = secp256k1.sign_digest(digest, private_key)
    assert is_signature_65("0x" + signature.hex())
    assert secp256k1.recover_address(digest, signature) == secp256k1.address_from_public_key(secp256k1.public_key_from_private(private_key))


def test_eip191_signature_reproduces_spec_vector(crypto_vectors):
    """RFC 6979 signing yields the exact bytes the viem/noble signers produced for the spec vectors."""
    keys = crypto_vectors["keys"]
    for vector in crypto_vectors["eip191"]:
        private_key = vector.get("privateKey") or keys[vector["key"]]["privateKey"]
        signature = secp256k1.sign_digest(bytes.fromhex(vector["eip191Digest"][2:]), int(private_key, 16))
        assert "0x" + signature.hex() == vector["signature"]


def test_runtime_challenge_vectors(crypto_vectors):
    for vector in crypto_vectors["runtimeAuthorizationChallenge"]:
        i = from_plain(vector["input"])
        challenge = create_runtime_authorization_challenge(i["domain"], i["request"], i["evaluationTime"], i["policyVersion"], i["historyHead"], i["binding"])
        assert canonical_encode(challenge) == vector["canonicalText"]
        assert hash_runtime_authorization_challenge(challenge, "keccak256") == vector["challengeHash"]
        assert recover_content_hash_signer(vector["challengeHash"], vector["signature"]) == vector["recoveredAddress"]


def test_administrative_authorization_vectors(crypto_vectors):
    for vector in crypto_vectors["administrativeAuthorization"]:
        assert hash_canonical(from_plain(vector["transitionEffect"]), "keccak256") == vector["transitionEffectHash"]
        assert hash_canonical(from_plain(vector["authorityProof"]), "keccak256") == vector["authorityProofHash"]
        assert hash_canonical(from_plain(vector["challenge"]), "keccak256") == vector["signingHash"]
        assert recover_content_hash_signer(vector["signingHash"], vector["signature"]) == vector["recoveredAddress"]


def test_receipt_vectors(crypto_vectors):
    for vector in crypto_vectors["receipt"]:
        assert hash_canonical(from_plain(vector["payload"]), "keccak256") == vector["contentHash"]
        assert recover_content_hash_signer(vector["contentHash"], vector["signature"]) == vector["recoveredAddress"]


def test_history_prefix_hashes(crypto_vectors):
    vector = crypto_vectors["eventHistoryPrefixHashes"]
    events = from_plain(vector["events"])
    assert hash_event_history_prefixes(events, "continuity-event/0.2") == vector["prefixHashes"]
    assert hash_event_history(events, "continuity-event/0.2") == vector["prefixHashes"][-1]
    hasher = HistoryHasher("continuity-event/0.2")
    clone = None
    for index, event in enumerate(events):
        if index == 1:
            clone = hasher.clone()
        assert hasher.push(event) == vector["prefixHashes"][index]
    assert clone is not None and clone.push(events[1]) == vector["prefixHashes"][1]


def test_sha256_history_hasher_matches_direct_hash():
    events = [{"id": "g", "type": "DEPLOYMENT_INITIALIZED", "timestamp": 0, "data": {"x": 1}}, {"id": "e", "type": "X", "timestamp": 1, "data": {}}]
    assert hash_event_history(events, "irontrellis-event/1") == hash_canonical(["irontrellis-event-history/1", events], "sha256")


# ---------------------------------------------------------------- ed25519 (RFC 8032 vectors)

RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


@pytest.mark.parametrize("seed,public,message,signature", RFC8032)
def test_ed25519_rfc8032_pure(seed, public, message, signature, monkeypatch):
    monkeypatch.setattr(ed25519, "_FastPublicKey", None)
    assert ed25519.public_key_from_seed(bytes.fromhex(seed)).hex() == public
    assert ed25519.sign(bytes.fromhex(seed), bytes.fromhex(message)).hex() == signature
    assert ed25519.verify(bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature))
    assert not ed25519.verify(bytes.fromhex(public), bytes.fromhex(message) + b"x", bytes.fromhex(signature))
    flipped = bytearray(bytes.fromhex(signature))
    flipped[0] ^= 1
    assert not ed25519.verify(bytes.fromhex(public), bytes.fromhex(message), bytes(flipped))


def test_ed25519_rejects_malformed_inputs(monkeypatch):
    monkeypatch.setattr(ed25519, "_FastPublicKey", None)
    public = bytes.fromhex(RFC8032[0][1])
    assert not ed25519.verify(public, b"", b"\x00" * 63)
    assert not ed25519.verify(b"\xff" * 32, b"", b"\x00" * 64)
    high_s = bytes.fromhex(RFC8032[0][3][:64]) + (ed25519.L + 1).to_bytes(32, "little")
    assert not ed25519.verify(public, b"", high_s)


def test_ed25519_suite_over_content_hash(monkeypatch):
    monkeypatch.setattr(ed25519, "_FastPublicKey", None)
    seed = os.urandom(32)
    public = "0x" + ed25519.public_key_from_seed(seed).hex()
    content_hash = "0x" + hashlib.sha256(b"head").hexdigest()
    signature = "0x" + ed25519.sign(seed, bytes.fromhex(content_hash[2:])).hex()
    suite = suite_for("ed25519")
    assert suite.is_signature(signature) and suite.is_credential(public)
    assert suite.verify(content_hash, signature, public.upper().replace("0X", "0x"))
    assert not suite.verify(content_hash.replace("0x", "0x0")[:66], signature, public)


def test_control_authorization_hash_is_canonical():
    domain = {"protocol": "irontrellis", "version": "1", "deploymentId": "d"}
    h = control_authorization_hash(domain, "e", "AGENT_CREATED", 5, None, "0x" + "0" * 64, "sha256")
    assert h == hash_canonical({"version": "irontrellis-control-authorization/1", "domain": domain, "eventId": "e", "eventType": "AGENT_CREATED", "timestamp": 5, "previousHead": None, "effectHash": "0x" + "0" * 64}, "sha256")
