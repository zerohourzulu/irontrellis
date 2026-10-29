"""Keccak-256 (the pre-FIPS padding ``0x01``, as Ethereum uses it), pure Python.

The state is exposed as a small class with ``update``/``clone``/``finalize`` so
the history hasher can absorb a growing event list once and finalise a copy
at every prefix (spec 01 §B.3), exactly like the TypeScript engine.
"""
from __future__ import annotations

RATE = 136  # bytes: (1600 - 2 * 256) / 8
_MASK = (1 << 64) - 1
_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_ROTATIONS = (
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
)
# pi step: lane (x, y) moves to (y, 2x + 3y); flattened index = x + 5 * y
_PI = tuple((y + 5 * ((2 * x + 3 * y) % 5)) for y in range(5) for x in range(5))


def _rol(value: int, shift: int) -> int:
    if shift == 0:
        return value
    return ((value << shift) | (value >> (64 - shift))) & _MASK


def _permute(lanes: list[int]) -> None:
    for rc in _ROUND_CONSTANTS:
        # theta
        c = [lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for i in range(25):
            lanes[i] ^= d[i % 5]
        # rho + pi
        moved = [0] * 25
        for i in range(25):
            moved[_PI[i]] = _rol(lanes[i], _ROTATIONS[i])
        # chi
        for y in range(0, 25, 5):
            a0, a1, a2, a3, a4 = moved[y], moved[y + 1], moved[y + 2], moved[y + 3], moved[y + 4]
            lanes[y] = a0 ^ ((~a1) & a2)
            lanes[y + 1] = a1 ^ ((~a2) & a3)
            lanes[y + 2] = a2 ^ ((~a3) & a4)
            lanes[y + 3] = a3 ^ ((~a4) & a0)
            lanes[y + 4] = a4 ^ ((~a0) & a1)
        # iota
        lanes[0] ^= rc


class KeccakState:
    """An absorbing Keccak-256 sponge; ``finalize`` never disturbs the running state."""

    __slots__ = ("_lanes", "_buffer")

    def __init__(self) -> None:
        self._lanes = [0] * 25
        self._buffer = b""

    def clone(self) -> KeccakState:
        copy = KeccakState()
        copy._lanes = list(self._lanes)
        copy._buffer = self._buffer
        return copy

    def _absorb_block(self, block: bytes) -> None:
        lanes = self._lanes
        for i in range(RATE // 8):
            lanes[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _permute(lanes)

    def update(self, data: bytes) -> None:
        buffer = self._buffer + data
        offset = 0
        while len(buffer) - offset >= RATE:
            self._absorb_block(buffer[offset:offset + RATE])
            offset += RATE
        self._buffer = buffer[offset:]

    def finalize(self) -> bytes:
        lanes = list(self._lanes)
        block = bytearray(self._buffer) + bytearray(RATE - len(self._buffer))
        block[len(self._buffer)] ^= 0x01
        block[RATE - 1] ^= 0x80
        for i in range(RATE // 8):
            lanes[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _permute(lanes)
        return b"".join(lanes[i].to_bytes(8, "little") for i in range(4))


def keccak256(data: bytes) -> bytes:
    state = KeccakState()
    state.update(data)
    return state.finalize()
