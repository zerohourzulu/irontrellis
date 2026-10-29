"""Ed25519 verification (RFC 8032), pure Python, with an optional fast path.

Format-1 control events are signed by owner keys; a long history verifies one
signature per control event, so the pure-Python path uses precomputed tables
(fixed-base windows for B, a 4-bit window for the public key) to keep a verify
around a couple of milliseconds. When the optional ``cryptography`` extra is
installed its OpenSSL-backed verifier is used instead, with identical results.

Signing is implemented for the test suite (round trips and the conformance
generator do not depend on it).
"""
from __future__ import annotations

import hashlib

try:  # optional accelerator
    from cryptography.exceptions import InvalidSignature as _InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as _FastPublicKey
except Exception:  # pragma: no cover - the extra is optional
    _FastPublicKey = None
    _InvalidSignature = Exception

Q = (1 << 255) - 19
L = (1 << 252) + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, -1, Q)) % Q
_SQRT_M1 = pow(2, (Q - 1) // 4, Q)
_BY = 4 * pow(5, -1, Q) % Q


def _recover_x(y: int, sign: int) -> int | None:
    if y >= Q:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, -1, Q) % Q
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (Q + 3) // 8, Q)
    if (x * x - x2) % Q != 0:
        x = x * _SQRT_M1 % Q
    if (x * x - x2) % Q != 0:
        return None
    if (x & 1) != sign:
        x = Q - x
    return x


_BX = _recover_x(_BY, 0)
assert _BX is not None
# Extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, x*y = T/Z.
_B = (_BX, _BY, 1, _BX * _BY % Q)
_IDENTITY = (0, 1, 1, 0)


def _add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % Q
    b = (y1 + x1) * (y2 + x2) % Q
    c = 2 * t1 * t2 * D % Q
    d = 2 * z1 * z2 % Q
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % Q, g * h % Q, f * g % Q, e * h % Q


def _double(p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, _ = p
    a = x1 * x1 % Q
    b = y1 * y1 % Q
    c = 2 * z1 * z1 % Q
    h = a + b
    e = h - (x1 + y1) * (x1 + y1)
    g = a - b
    f = c + g
    return e * f % Q, g * h % Q, f * g % Q, e * h % Q


def _multiply(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    """4-bit fixed-window multiplication (variable-time; verification only)."""
    table = [_IDENTITY, point]
    for i in range(2, 16):
        table.append(_add(table[i - 1], point))
    result = _IDENTITY
    for shift in range(252, -1, -4):
        result = _double(_double(_double(_double(result))))
        window = (scalar >> shift) & 15
        if window:
            result = _add(result, table[window])
    return result


_BASE_TABLE: list[list[tuple[int, int, int, int]]] | None = None


def _base_multiply(scalar: int) -> tuple[int, int, int, int]:
    """Fixed-base multiplication of B with 8-bit windows precomputed once."""
    global _BASE_TABLE
    if _BASE_TABLE is None:
        table = []
        power = _B
        for _ in range(32):
            row = [_IDENTITY, power]
            for i in range(2, 256):
                row.append(_add(row[i - 1], power))
            table.append(row)
            power = row[255]
            power = _add(power, row[1])
        _BASE_TABLE = table
    result = _IDENTITY
    for i in range(32):
        window = (scalar >> (8 * i)) & 255
        if window:
            result = _add(result, _BASE_TABLE[i][window])
    return result


def _encode(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    inverse = pow(z, -1, Q)
    x = x * inverse % Q
    y = y * inverse % Q
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(data: bytes) -> tuple[int, int, int, int] | None:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return x, y, 1, x * y % Q


def _verify_pure(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64 or len(public_key) != 32:
        return False
    a = _decode(public_key)
    r = _decode(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % L
    left = _base_multiply(s)
    right = _add(r, _multiply(a, k))
    return _encode(left) == _encode(right)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff ``signature`` is a valid Ed25519 signature of ``message`` under ``public_key``. Never raises."""
    if _FastPublicKey is not None:
        try:
            _FastPublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        except _InvalidSignature:
            return False
        except Exception:
            return False
    return _verify_pure(public_key, message, signature)


# ---------------------------------------------------------------- signing (tests only)


def public_key_from_seed(seed: bytes) -> bytes:
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return _encode(_base_multiply(scalar))


def sign(seed: bytes, message: bytes) -> bytes:
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    public_key = _encode(_base_multiply(scalar))
    r = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % L
    r_encoded = _encode(_base_multiply(r))
    k = int.from_bytes(hashlib.sha512(r_encoded + public_key + message).digest(), "little") % L
    s = (r + k * scalar) % L
    return r_encoded + s.to_bytes(32, "little")
