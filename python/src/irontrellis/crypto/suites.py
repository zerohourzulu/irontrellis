"""Signature suites (spec 04 §B–D): the verifier side of the two schemes.

A suite turns "this ContentHash was signed by the holder of this credential"
into a boolean. The hash handed to ``verify`` is already the history's hash of
the signed structure; what the suite does with it is scheme-specific:

* ``eip191-personal-sign-keccak256`` — secp256k1 recovery over
  keccak256(0x19 ‖ "Ethereum Signed Message:\\n32" ‖ hash); credential = address
  (any case, compared lowercase); signature = 0x + 130 lowercase hex, low-s,
  v ∈ {1b, 1c}.
* ``ed25519`` — Ed25519 over the 32 raw hash bytes; credential = 0x + 64 hex
  raw public key; signature = 0x + 128 lowercase hex.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ..canonical import is_content_hash, is_ethereum_address, is_public_key_hex, is_signature_64
from . import ed25519
from .keccak import keccak256
from .secp256k1 import HALF_N, N, eip191_digest, recover_address

SIGNATURE_SCHEMES = ("eip191-personal-sign-keccak256", "ed25519")


def is_signature_65(value: Any) -> bool:
    """Legacy ``Signature65``: lowercase 130 hex, 0 < r < n, 0 < s ≤ (n−1)/2, v ∈ {1b, 1c}."""
    if not isinstance(value, str) or len(value) != 132 or not value.startswith("0x"):
        return False
    body = value[2:]
    if not all(c in "0123456789abcdef" for c in body):
        return False
    r = int(body[:64], 16)
    s = int(body[64:128], 16)
    v = body[128:]
    return 0 < r < N and 0 < s <= HALF_N and v in ("1b", "1c")


def recover_content_hash_signer(content_hash: Any, signature: Any) -> str | None:
    """Lowercase signer address of ``signature`` over ``content_hash``, or None (legacy ``recoverPortableContentHashSigner``)."""
    if not is_content_hash(content_hash) or not is_signature_65(signature):
        return None
    try:
        return recover_address(eip191_digest(bytes.fromhex(content_hash[2:])), bytes.fromhex(signature[2:]))
    except Exception:
        return None


def eip191_digest_hex(content_hash: str) -> str:
    if not is_content_hash(content_hash):
        raise ValueError("eip191Digest expects a lowercase 0x-prefixed 32-byte hash")
    return "0x" + eip191_digest(bytes.fromhex(content_hash[2:])).hex()


@dataclass(frozen=True)
class SignatureSuite:
    scheme: str
    is_signature: Callable[[Any], bool]
    is_credential: Callable[[Any], bool]
    verify: Callable[[str, str, str], bool]

    @staticmethod
    def normalize_credential(credential: str) -> str:
        return credential.lower()


def _verify_eip191(content_hash: str, signature: str, credential: str) -> bool:
    if not is_ethereum_address(credential):
        return False
    signer = recover_content_hash_signer(content_hash, signature)
    return signer is not None and signer == credential.lower()


def _verify_ed25519(content_hash: str, signature: str, credential: str) -> bool:
    if not is_content_hash(content_hash) or not is_signature_64(signature) or not is_public_key_hex(credential):
        return False
    try:
        return ed25519.verify(bytes.fromhex(credential[2:]), bytes.fromhex(content_hash[2:]), bytes.fromhex(signature[2:]))
    except Exception:
        return False


EIP191_SUITE = SignatureSuite("eip191-personal-sign-keccak256", is_signature_65, is_ethereum_address, _verify_eip191)
ED25519_SUITE = SignatureSuite("ed25519", is_signature_64, is_public_key_hex, _verify_ed25519)


def suite_for(scheme: str) -> SignatureSuite:
    if scheme == "eip191-personal-sign-keccak256":
        return EIP191_SUITE
    if scheme == "ed25519":
        return ED25519_SUITE
    raise ValueError(f"unsupported signature scheme: {scheme}")


__all__ = ["SIGNATURE_SCHEMES", "SignatureSuite", "suite_for", "is_signature_65", "recover_content_hash_signer", "eip191_digest_hex", "keccak256"]
