"""secp256k1 public-key recovery and the EIP-191 digest, pure Python (spec 04 §B).

Only what a verifier needs: recover the signer of a 65-byte ``r ‖ s ‖ v``
signature over a 32-byte digest and turn the public key into a lowercase
Ethereum address. Signing (RFC 6979) is provided for the test suite's
round-trip checks; it is not part of the verifier contract. Points are handled
in Jacobian coordinates with Python integers, which is fast enough for a few
thousand recoveries per history.
"""
from __future__ import annotations

import hashlib
import hmac

from .keccak import keccak256

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HALF_N = (N - 1) // 2
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_INFINITY = (0, 1, 0)

EIP191_PREFIX = b"\x19Ethereum Signed Message:\n32"


def _jacobian_double(point: tuple[int, int, int]) -> tuple[int, int, int]:
    x, y, z = point
    if y == 0 or z == 0:
        return _INFINITY
    s = (4 * x * y * y) % P
    m = (3 * x * x) % P
    x3 = (m * m - 2 * s) % P
    y3 = (m * (s - x3) - 8 * y * y * y * y) % P
    z3 = (2 * y * z) % P
    return x3, y3, z3


def _jacobian_add(a: tuple[int, int, int], b: tuple[int, int, int]) -> tuple[int, int, int]:
    if a[2] == 0:
        return b
    if b[2] == 0:
        return a
    x1, y1, z1 = a
    x2, y2, z2 = b
    z1z1 = z1 * z1 % P
    z2z2 = z2 * z2 % P
    u1 = x1 * z2z2 % P
    u2 = x2 * z1z1 % P
    s1 = y1 * z2 * z2z2 % P
    s2 = y2 * z1 * z1z1 % P
    if u1 == u2:
        if s1 != s2:
            return _INFINITY
        return _jacobian_double(a)
    h = (u2 - u1) % P
    r = (s2 - s1) % P
    h2 = h * h % P
    h3 = h2 * h % P
    u1h2 = u1 * h2 % P
    x3 = (r * r - h3 - 2 * u1h2) % P
    y3 = (r * (u1h2 - x3) - s1 * h3) % P
    z3 = h * z1 * z2 % P
    return x3, y3, z3


def _jacobian_multiply(point: tuple[int, int, int], scalar: int) -> tuple[int, int, int]:
    result = _INFINITY
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _jacobian_add(result, addend)
        addend = _jacobian_double(addend)
        scalar >>= 1
    return result


def _to_affine(point: tuple[int, int, int]) -> tuple[int, int] | None:
    x, y, z = point
    if z == 0:
        return None
    inverse = pow(z, -1, P)
    inverse2 = inverse * inverse % P
    return x * inverse2 % P, y * inverse2 * inverse % P


def public_key_from_private(scalar: int) -> tuple[int, int]:
    if not 0 < scalar < N:
        raise ValueError("private key out of range")
    affine = _to_affine(_jacobian_multiply((GX, GY, 1), scalar))
    assert affine is not None
    return affine


def address_from_public_key(point: tuple[int, int]) -> str:
    """Lowercase ``0x`` address: the last 20 bytes of keccak256(x ‖ y)."""
    return "0x" + keccak256(point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big"))[12:].hex()


def eip191_digest(content_hash: bytes) -> bytes:
    """keccak256(0x19 ‖ "Ethereum Signed Message:\\n32" ‖ raw32(hash))."""
    if len(content_hash) != 32:
        raise ValueError("eip191 digest expects 32 hash bytes")
    return keccak256(EIP191_PREFIX + content_hash)


def recover_public_key(digest: bytes, r: int, s: int, recovery: int) -> tuple[int, int] | None:
    """The public key that produced ``(r, s)`` over ``digest`` with the given parity; None if there is none."""
    if not (0 < r < N and 0 < s < N) or recovery not in (0, 1):
        return None
    x = r  # only the low x-candidate is used, as the engine accepts only 0 < r < n
    alpha = (pow(x, 3, P) + 7) % P
    y = pow(alpha, (P + 1) // 4, P)
    if y * y % P != alpha:
        return None
    if (y & 1) != recovery:
        y = P - y
    e = int.from_bytes(digest, "big") % N
    r_inverse = pow(r, -1, N)
    # Q = r^-1 (s R - e G)
    s_r = _jacobian_multiply((x, y, 1), s)
    e_g = _jacobian_multiply((GX, GY, 1), (N - e) % N)
    q = _jacobian_multiply(_jacobian_add(s_r, e_g), r_inverse)
    return _to_affine(q)


def recover_address(digest: bytes, signature: bytes) -> str | None:
    """Lowercase address of a 65-byte ``r ‖ s ‖ v`` signature (v ∈ {27, 28}) over ``digest``."""
    if len(signature) != 65:
        return None
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    v = signature[64]
    if v not in (27, 28):
        return None
    point = recover_public_key(digest, r, s, v - 27)
    return None if point is None else address_from_public_key(point)


# ---------------------------------------------------------------- signing (tests only)


def _rfc6979_nonce(digest: bytes, private_key: int) -> int:
    key = private_key.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + key + digest, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + key + digest, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 0 < candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_digest(digest: bytes, private_key: int) -> bytes:
    """Deterministic low-s signature ``r ‖ s ‖ v`` with v ∈ {27, 28}; used by the tests to exercise recovery."""
    e = int.from_bytes(digest, "big") % N
    while True:
        k = _rfc6979_nonce(digest, private_key)
        point = _to_affine(_jacobian_multiply((GX, GY, 1), k))
        assert point is not None
        r = point[0] % N
        if r == 0:
            digest = hashlib.sha256(digest).digest()
            continue
        s = pow(k, -1, N) * (e + r * private_key) % N
        if s == 0:
            digest = hashlib.sha256(digest).digest()
            continue
        recovery = point[1] & 1
        if s > HALF_N:
            s = N - s
            recovery ^= 1
        return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + recovery])
