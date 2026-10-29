"""Witness wire formats (docs/WITNESS.md §9): the verifier side, with the same accept/reject
rules and reason codes as the TypeScript core (``packages/core/src/transparency/*``).

* RFC 6962 / RFC 9162 §2.1 Merkle trees over SHA-256: ``leaf_hash``, ``node_hash``, ``root_of``, and the
  iterative proof verifiers ``verify_inclusion`` (§2.1.3.2) and ``verify_consistency`` (§2.1.4.2), which return
  False for every malformed input and never raise. ``inclusion_proof`` / ``consistency_proof`` build proofs
  over a list of leaf hashes (tests and tooling; a verifier does not need them).
* C2SP signed notes (``golang.org/x/mod/sumdb/note``, Ed25519 only): ``note_key_hash``, ``verifier_key``,
  ``parse_verifier_key``, ``parse_signer_key``, ``sign_note``, ``open_note``; tlog checkpoints:
  ``format_checkpoint``, ``parse_checkpoint``. Base64 is the padded standard alphabet decoded strictly (only the
  canonical spelling of a byte string is accepted).
* Owner-signed head statements: ``validate_head_statement``, ``head_statement_hash``,
  ``validate_signed_head_statement``, ``verify_signed_head_statement``.
* Witness log entries: ``validate_entry``, ``encode_entry``, ``entry_leaf_hash``.
* Witness receipts: ``verify_witness_receipt`` (reasons ``RECEIPT_MALFORMED``, ``NOTE_UNVERIFIED``,
  ``CHECKPOINT_MALFORMED``, ``ORIGIN_MISMATCH``, ``ENTRY_MALFORMED``, ``INDEX_OUT_OF_RANGE``,
  ``INCLUSION_INVALID``, checked in that order).

JSON numbers: the TypeScript side sees every JSON number as a JavaScript ``number``, so an integral float such
as ``7.0`` counts as the integer 7 here too (``bool`` never does). Nothing in this module writes a history.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from .canonical import MAX_SAFE_INTEGER, canonical_encode, is_content_hash, is_identifier
from .crypto import ed25519
from .crypto.suites import SIGNATURE_SCHEMES, suite_for
from .hashing import TRELLIS_FORMAT, HistoryHasher, hash_canonical

MERKLE_HASH_SIZE = 32
ALG_ED25519 = 0x01
MAX_NOTE_SIGNATURES = 100
HEAD_STATEMENT_VERSION = "irontrellis-head-statement/1"
WITNESS_ENTRY_VERSION = "irontrellis-witness-entry/1"
WITNESS_ENTRY_KINDS = ("REGISTERED", "HEAD", "ROTATED", "EQUIVOCATION", "SUPERSEDED")
WITNESS_RECEIPT_VERSION = "irontrellis-witness-receipt/1"

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"
_SIGNATURE_PREFIX = "— "  # EM DASH, space
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_HEX8 = re.compile(r"[0-9a-fA-F]{8}")
_DECIMAL = re.compile(r"0|[1-9][0-9]*")
_SIGNER_KEY = re.compile(r"PRIVATE\+KEY\+([^+]*)\+([^+]*)\+(.*)", re.S)
# Go `unicode.IsSpace`: ASCII whitespace, U+0085, U+00A0 and the Unicode White_Space characters.
_GO_SPACE = frozenset("\t\n\v\f\r \u0085      　" + "".join(chr(c) for c in range(0x2000, 0x200B)))


# ---------------------------------------------------------------- small helpers


def _is_record(value: Any) -> bool:
    return isinstance(value, dict)


def _has_exact_keys(value: dict, keys: Sequence[str]) -> bool:
    return len(value) == len(keys) and all(key in value for key in keys)


def _js_integer(value: Any) -> int | None:
    """The integer a JSON number denotes when it is a JavaScript safe integer (integral floats included), else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER else None
    if isinstance(value, float) and math.isfinite(value) and value.is_integer() and abs(value) <= MAX_SAFE_INTEGER:
        return int(value)
    return None


def _is_u53(value: Any) -> bool:
    """TypeScript ``isU53``: a safe integer ≥ 0 other than negative zero."""
    number = _js_integer(value)
    if number is None or number < 0:
        return False
    return not (isinstance(value, float) and value == 0 and math.copysign(1.0, value) < 0)


def _is_size(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_SAFE_INTEGER


def _is_hash(value: Any) -> bool:
    return isinstance(value, (bytes, bytearray)) and len(value) == MERKLE_HASH_SIZE


def _is_well_formed(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:  # a lone surrogate
        return False
    return True


def encode_base64(data: bytes) -> str:
    """Standard padded base64 (RFC 4648 §4)."""
    return base64.b64encode(bytes(data)).decode("ascii")


def decode_base64(text: Any) -> bytes | None:
    """The decoded bytes, or None when ``text`` is not the canonical padded base64 spelling (alphabet, padding, zero trailing bits)."""
    if not isinstance(text, str) or _BASE64.fullmatch(text) is None:
        return None
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    return data if encode_base64(data) == text else None


# ---------------------------------------------------------------- Merkle (RFC 6962 / RFC 9162 §2.1)


def _sha256(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def empty_root() -> bytes:
    """MTH({}) = SHA-256("")."""
    return _sha256()


def leaf_hash(entry_bytes: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256(0x00 || entry)."""
    return _sha256(_LEAF_PREFIX, bytes(entry_bytes))


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash: SHA-256(0x01 || left || right)."""
    return _sha256(_NODE_PREFIX, bytes(left), bytes(right))


def _split_point(n: int) -> int:
    """Largest power of two strictly less than ``n`` (n ≥ 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _is_power_of_two(n: int) -> bool:
    return n > 0 and n & (n - 1) == 0


def _mth(leaves: Sequence[bytes], start: int, end: int) -> bytes:
    n = end - start
    if n == 1:
        return bytes(leaves[start])
    k = _split_point(n)
    return node_hash(_mth(leaves, start, start + k), _mth(leaves, start + k, end))


def _checked_leaves(leaf_hashes: Iterable[bytes]) -> list[bytes]:
    leaves = [bytes(h) if isinstance(h, (bytes, bytearray)) else h for h in leaf_hashes]
    if not all(_is_hash(h) for h in leaves):
        raise TypeError("leaf hashes are 32-byte values (use leaf_hash(entry_bytes))")
    return leaves


def root_of(leaf_hashes: Iterable[bytes]) -> bytes:
    """MTH over already-hashed leaves (the root of a tree holding exactly these leaves)."""
    leaves = _checked_leaves(leaf_hashes)
    return empty_root() if not leaves else _mth(leaves, 0, len(leaves))


def inclusion_proof(leaf_hashes: Sequence[bytes], index: int) -> list[bytes]:
    """RFC 9162 §2.1.3.1 PATH(index, D[0:n]) over ``leaf_hashes``, leaf to root."""
    leaves = _checked_leaves(leaf_hashes)
    if not _is_size(index) or index >= len(leaves):
        raise ValueError(f"leaf index {index!r} is outside 0..{len(leaves) - 1}")
    proof: list[bytes] = []

    def path(m: int, start: int, end: int) -> None:
        n = end - start
        if n <= 1:
            return
        k = _split_point(n)
        if m - start < k:
            path(m, start, start + k)
            proof.append(_mth(leaves, start + k, end))
        else:
            path(m, start + k, end)
            proof.append(_mth(leaves, start, start + k))

    path(index, 0, len(leaves))
    return proof


def consistency_proof(leaf_hashes: Sequence[bytes], from_size: int) -> list[bytes]:
    """RFC 9162 §2.1.4.1 PROOF(from_size, D[0:n]) over ``leaf_hashes``; empty when from_size is 0 or n."""
    leaves = _checked_leaves(leaf_hashes)
    if not _is_size(from_size) or from_size > len(leaves):
        raise ValueError(f"consistency proof needs 0 <= from_size <= {len(leaves)}, got {from_size!r}")
    proof: list[bytes] = []

    def subproof(m: int, start: int, end: int, complete: bool) -> None:
        n = end - start
        if m == n:
            if not complete:
                proof.append(_mth(leaves, start, end))
            return
        k = _split_point(n)
        if m <= k:
            subproof(m, start, start + k, complete)
            proof.append(_mth(leaves, start + k, end))
        else:
            subproof(m - k, start + k, end, False)
            proof.append(_mth(leaves, start, start + k))

    if 0 < from_size < len(leaves):
        subproof(from_size, 0, len(leaves), True)
    return proof


def verify_inclusion(leaf: Any, index: Any, size: Any, proof: Any, root: Any) -> bool:
    """RFC 9162 §2.1.3.2: True iff ``proof`` shows the leaf hash ``leaf`` at ``index`` in the tree of ``size``
    leaves with root ``root``. Never raises."""
    try:
        if not _is_hash(leaf) or not _is_hash(root) or not _is_size(index) or not _is_size(size) or not isinstance(proof, (list, tuple)):
            return False
        if index >= size:
            return False
        fn, sn = index, size - 1
        r = bytes(leaf)
        for p in proof:
            if not _is_hash(p):
                return False
            if sn == 0:
                return False
            if fn % 2 == 1 or fn == sn:
                r = node_hash(p, r)
                if fn % 2 == 0:
                    while fn % 2 == 0 and fn != 0:
                        fn //= 2
                        sn //= 2
            else:
                r = node_hash(r, p)
            fn //= 2
            sn //= 2
        return sn == 0 and r == bytes(root)
    except Exception:
        return False


def verify_consistency(from_size: Any, to_size: Any, from_root: Any, to_root: Any, proof: Any) -> bool:
    """RFC 9162 §2.1.4.2: True iff ``proof`` shows the tree of ``from_size`` leaves with root ``from_root`` is a
    prefix of the tree of ``to_size`` leaves with root ``to_root``. As in the transparency-dev verifier,
    from_size 0 is consistent with anything given an empty proof, and equal sizes need equal roots and an empty
    proof. Never raises."""
    try:
        if not _is_size(from_size) or not _is_size(to_size) or not _is_hash(from_root) or not _is_hash(to_root) or not isinstance(proof, (list, tuple)):
            return False
        if from_size > to_size:
            return False
        if from_size == to_size:
            return len(proof) == 0 and bytes(from_root) == bytes(to_root)
        if from_size == 0:
            return len(proof) == 0
        if len(proof) == 0:
            return False
        if not all(_is_hash(p) for p in proof):
            return False
        path = [bytes(from_root), *map(bytes, proof)] if _is_power_of_two(from_size) else [bytes(p) for p in proof]
        fn, sn = from_size - 1, to_size - 1
        while fn % 2 == 1:
            fn //= 2
            sn //= 2
        fr = sr = path[0]
        for c in path[1:]:
            if sn == 0:
                return False
            if fn % 2 == 1 or fn == sn:
                fr = node_hash(c, fr)
                sr = node_hash(c, sr)
                if fn % 2 == 0:
                    while fn % 2 == 0 and fn != 0:
                        fn //= 2
                        sn //= 2
            else:
                sr = node_hash(sr, c)
            fn //= 2
            sn //= 2
        return sn == 0 and fr == bytes(from_root) and sr == bytes(to_root)
    except Exception:
        return False


# ---------------------------------------------------------------- signed notes (C2SP signed-note)


class NoteError(ValueError):
    """Every failure of the note and checkpoint functions. ``code`` is stable: MALFORMED_NOTE, UNVERIFIED_NOTE,
    INVALID_SIGNATURE, AMBIGUOUS_KEY, INVALID_KEY, INVALID_SIGNER, MALFORMED_CHECKPOINT, MALFORMED_LATEST_NOTE."""

    def __init__(self, code: str, message: str | None = None) -> None:
        super().__init__(message or code)
        self.code = code


@dataclass(frozen=True)
class VerifierKey:
    name: str
    key_hash: bytes
    public_key: bytes


@dataclass(frozen=True)
class NoteSigner:
    """An Ed25519 note key that can sign (tests and tooling: the verifier never needs one)."""

    name: str
    public_key: bytes
    key_hash: bytes
    seed: bytes

    def sign(self, message: bytes) -> bytes:
        return ed25519.sign(self.seed, message)


@dataclass(frozen=True)
class OpenedNote:
    body: str
    verified_by: list[str]


@dataclass(frozen=True)
class Checkpoint:
    origin: str
    size: int
    root: bytes
    extensions: list[str]


def is_valid_note_key_name(name: Any) -> bool:
    """Non-empty, well-formed, no Unicode space, no "+" (Go ``isValidName``)."""
    return isinstance(name, str) and len(name) > 0 and _is_well_formed(name) and not any(c in _GO_SPACE for c in name) and "+" not in name


def _is_note_text(text: str) -> bool:
    """Well-formed, and no C0 control but newline (DEL is allowed), as Go's ``note.Open``."""
    return _is_well_formed(text) and not any(ord(c) < 0x20 and c != "\n" for c in text)


def _key_hash_of(name: str, encoded_key: bytes) -> bytes:
    return _sha256(name.encode("utf-8"), b"\n", encoded_key)[:4]


def note_key_hash(name: str, public_key: bytes) -> bytes:
    """The 4-byte key hash of an Ed25519 note key: SHA-256(name || "\\n" || 0x01 || public_key)[0:4]."""
    if not is_valid_note_key_name(name):
        raise NoteError("INVALID_KEY", f"invalid note key name {name!r}")
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        raise NoteError("INVALID_KEY", "an Ed25519 note key is 32 bytes")
    return _key_hash_of(name, bytes([ALG_ED25519]) + bytes(public_key))


def verifier_key(name: str, public_key: bytes) -> str:
    """``<name>+<hex8 key hash>+<base64(0x01 || public_key)>``."""
    key_hash = note_key_hash(name, public_key)
    return f"{name}+{key_hash.hex()}+{encode_base64(bytes([ALG_ED25519]) + bytes(public_key))}"


def parse_verifier_key(vkey: Any) -> VerifierKey:
    """Parses and checks a verifier key string (name rules, key hash, algorithm 0x01, 32-byte key). Raises ``NoteError("INVALID_KEY")``."""
    if not isinstance(vkey, str):
        raise NoteError("INVALID_KEY", "a verifier key is a string")
    first = vkey.find("+")
    second = -1 if first < 0 else vkey.find("+", first + 1)
    if second < 0:
        raise NoteError("INVALID_KEY", "malformed verifier key")
    name, hash8 = vkey[:first], vkey[first + 1:second]
    key = decode_base64(vkey[second + 1:])
    if not is_valid_note_key_name(name) or _HEX8.fullmatch(hash8) is None or key is None or len(key) == 0:
        raise NoteError("INVALID_KEY", "malformed verifier key")
    key_hash = bytes.fromhex(hash8)
    if key_hash != _key_hash_of(name, key):
        raise NoteError("INVALID_KEY", "verifier key hash does not match its key")
    if key[0] != ALG_ED25519:
        raise NoteError("INVALID_KEY", "unknown verifier key algorithm")
    if len(key) != 33:
        raise NoteError("INVALID_KEY", "malformed verifier key")
    return VerifierKey(name, key_hash, key[1:])


def note_signer_from_seed(name: str, seed: bytes) -> NoteSigner:
    """A note signer from a 32-byte Ed25519 seed (the RFC 8032 private key)."""
    if not is_valid_note_key_name(name):
        raise NoteError("INVALID_SIGNER", f"invalid note key name {name!r}")
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise NoteError("INVALID_SIGNER", "an Ed25519 seed is 32 bytes")
    public_key = ed25519.public_key_from_seed(bytes(seed))
    return NoteSigner(name, public_key, note_key_hash(name, public_key), bytes(seed))


def parse_signer_key(skey: Any) -> NoteSigner:
    """Parses ``PRIVATE+KEY+<name>+<hex8>+<base64(0x01 || seed32)>`` (the Go ``NewSigner`` format) and checks the key hash."""
    parts = _SIGNER_KEY.fullmatch(skey) if isinstance(skey, str) else None
    key = None if parts is None else decode_base64(parts.group(3))
    if parts is None or not is_valid_note_key_name(parts.group(1)) or _HEX8.fullmatch(parts.group(2)) is None or key is None or len(key) == 0:
        raise NoteError("INVALID_SIGNER", "malformed signer key")
    if key[0] != ALG_ED25519:
        raise NoteError("INVALID_SIGNER", "unknown signer key algorithm")
    if len(key) != 33:
        raise NoteError("INVALID_SIGNER", "malformed signer key")
    signer = note_signer_from_seed(parts.group(1), key[1:])
    if signer.key_hash.hex() != parts.group(2).lower():
        raise NoteError("INVALID_SIGNER", "signer key hash does not match its key")
    return signer


def sign_note(body: str, signer: NoteSigner) -> str:
    """Signs ``body`` (which must end in a newline) with one Ed25519 note key; returns the note text."""
    if not isinstance(body, str) or not body.endswith("\n") or not _is_note_text(body):
        raise NoteError("MALFORMED_NOTE", "note text must be well-formed, end in a newline and contain no control characters but newlines")
    if not isinstance(signer, NoteSigner):
        raise NoteError("INVALID_SIGNER", "invalid note signer")
    signature = signer.sign(body.encode("utf-8"))
    return f"{body}\n{_SIGNATURE_PREFIX}{signer.name} {encode_base64(note_key_hash(signer.name, signer.public_key) + signature)}\n"


def open_note(note: Any, verifier_keys: Any) -> OpenedNote:
    """Opens a signed note: checks its syntax, verifies every signature whose key name and hash match a trusted
    verifier key, and returns the text and the verifier keys that verified it (in note order). Signatures by
    unknown keys are ignored; a known key with a bad signature, a malformed note or no verified signature raises
    :class:`NoteError` (the same rules as the TypeScript ``openNote``)."""
    if not isinstance(verifier_keys, (list, tuple)):
        raise NoteError("INVALID_KEY", "verifier_keys must be a list of verifier key strings")
    known: dict[str, list[tuple[str, bytes]]] = {}
    distinct: list[str] = []  # distinct spellings, first occurrence order
    for vkey in verifier_keys:
        if not isinstance(vkey, str):
            raise NoteError("INVALID_KEY", "a verifier key is a string")
        if vkey not in distinct:
            distinct.append(vkey)
    for vkey in distinct:
        parsed = parse_verifier_key(vkey)
        key_id = f"{parsed.name}+{parsed.key_hash.hex()}"
        candidates = known.setdefault(key_id, [])
        # The same key spelled twice (e.g. hex case) is one verifier; two different keys with one name+hash are ambiguous.
        if not any(public_key == parsed.public_key for _, public_key in candidates):
            candidates.append((vkey, parsed.public_key))
    if not isinstance(note, str) or not _is_note_text(note):
        raise NoteError("MALFORMED_NOTE", "malformed note")
    split = note.rfind("\n\n")
    if split < 0:
        raise NoteError("MALFORMED_NOTE", "malformed note")
    body, block = note[:split + 1], note[split + 2:]
    if len(block) == 0 or not block.endswith("\n"):
        raise NoteError("MALFORMED_NOTE", "malformed note")
    lines = block[:-1].split("\n")
    if len(lines) > MAX_NOTE_SIGNATURES:
        raise NoteError("MALFORMED_NOTE", "malformed note")
    signatures: list[tuple[str, bytes, bytes]] = []
    for line in lines:
        if not line.startswith(_SIGNATURE_PREFIX):
            raise NoteError("MALFORMED_NOTE", "malformed note")
        rest = line[len(_SIGNATURE_PREFIX):]
        space = rest.find(" ")
        name = rest if space < 0 else rest[:space]
        text = "" if space < 0 else rest[space + 1:]
        raw = decode_base64(text)
        if not is_valid_note_key_name(name) or text == "" or raw is None or len(raw) < 5:
            raise NoteError("MALFORMED_NOTE", "malformed note")
        signatures.append((name, raw[:4], raw[4:]))
    body_bytes = body.encode("utf-8")
    verified_by: list[str] = []
    seen: set[str] = set()
    for name, key_hash, signature in signatures:
        key_id = f"{name}+{key_hash.hex()}"
        candidates = known.get(key_id)
        if candidates is None:
            continue
        if len(candidates) > 1:
            raise NoteError("AMBIGUOUS_KEY", f"ambiguous key {key_id}")
        if key_id in seen:
            continue
        seen.add(key_id)
        vkey, public_key = candidates[0]
        try:
            ok = len(signature) == 64 and ed25519.verify(public_key, body_bytes, signature)
        except Exception:
            ok = False
        if not ok:
            raise NoteError("INVALID_SIGNATURE", f"invalid signature for key {key_id}")
        verified_by.append(vkey)
    if not verified_by:
        raise NoteError("UNVERIFIED_NOTE", "note has no verifiable signatures")
    return OpenedNote(body, verified_by)


# ---------------------------------------------------------------- checkpoints (C2SP tlog-checkpoint)


def _is_line(line: Any) -> bool:
    return isinstance(line, str) and len(line) > 0 and "\n" not in line and _is_note_text(line)


def format_checkpoint(origin: str, size: int, root: bytes, extensions: Sequence[str] = ()) -> str:
    """The checkpoint text: origin, decimal size, base64 root, then any extension lines."""
    if not _is_line(origin):
        raise NoteError("MALFORMED_CHECKPOINT", "the origin is one non-empty line")
    if not _is_size(size):
        raise NoteError("MALFORMED_CHECKPOINT", "the size is a safe non-negative integer")
    if not _is_hash(root):
        raise NoteError("MALFORMED_CHECKPOINT", "the root is a 32-byte hash")
    if not all(_is_line(line) for line in extensions):
        raise NoteError("MALFORMED_CHECKPOINT", "extension lines are non-empty single lines")
    return f"{origin}\n{size}\n{encode_base64(root)}\n" + "".join(f"{line}\n" for line in extensions)


def parse_checkpoint(body: Any) -> Checkpoint:
    """Strict parse of a checkpoint body (the text of an opened note). Raises ``NoteError("MALFORMED_CHECKPOINT")``."""
    def fail(why: str) -> NoteError:
        return NoteError("MALFORMED_CHECKPOINT", f"malformed checkpoint: {why}")

    if not isinstance(body, str) or not body.endswith("\n") or not _is_note_text(body):
        raise fail("not newline-terminated note text")
    lines = body[:-1].split("\n")
    if len(lines) < 3:
        raise fail("fewer than three lines")
    origin, size_text, root_text, *extensions = lines
    if len(origin) == 0:
        raise fail("empty origin")
    if _DECIMAL.fullmatch(size_text) is None:
        raise fail("size is not a decimal without leading zeros")
    if len(size_text) > 16 or int(size_text) > MAX_SAFE_INTEGER:  # 2^53 - 1 has 16 digits; never int() a huge string
        raise fail("size exceeds 2^53 - 1")
    size = int(size_text)
    root = decode_base64(root_text)
    if root is None or len(root) != MERKLE_HASH_SIZE:
        raise fail("root is not base64 of 32 bytes")
    if any(len(line) == 0 for line in extensions):
        raise fail("empty extension line")
    return Checkpoint(origin, size, root, extensions)


# ---------------------------------------------------------------- head statements (docs/reference/witness-protocol.md §9.1)


def _is_trellis_domain(value: Any) -> bool:
    return (_is_record(value) and _has_exact_keys(value, ("protocol", "version", "deploymentId")) and value["protocol"] == "irontrellis"
            and value["version"] == "1" and is_identifier(value["deploymentId"]))


def validate_head_statement(statement: Any) -> str | None:
    """None when ``statement`` is a well-formed head statement, else a short reason: exact field sets, version,
    content hashes, U53 positions and time, a format-1 domain, the history id at position 0, and the chaining
    rule (``previous`` is None or at most ``head``, with equal hashes at equal positions)."""
    if not _is_record(statement) or not _has_exact_keys(statement, ("version", "historyId", "domain", "head", "previous")):
        return "statement must have exactly version, historyId, domain, head, previous"
    history_id, head, previous = statement["historyId"], statement["head"], statement["previous"]
    if statement["version"] != HEAD_STATEMENT_VERSION:
        return f"version must be {HEAD_STATEMENT_VERSION}"
    if not is_content_hash(history_id):
        return "historyId must be a lowercase 0x-prefixed sha256 hash"
    if not _is_trellis_domain(statement["domain"]):
        return "domain must be an irontrellis/1 domain"
    if (not _is_record(head) or not _has_exact_keys(head, ("hash", "position", "canonicalTime")) or not is_content_hash(head["hash"])
            or not _is_u53(head["position"]) or not _is_u53(head["canonicalTime"])):
        return "head must be {hash, position, canonicalTime}"
    if head["position"] == 0 and head["hash"] != history_id:
        return "the head at position 0 must be the history id"
    if previous is None:
        return None
    if not _is_record(previous) or not _has_exact_keys(previous, ("hash", "position")) or not is_content_hash(previous["hash"]) or not _is_u53(previous["position"]):
        return "previous must be null or {hash, position}"
    if previous["position"] > head["position"]:
        return "previous.position must not exceed head.position"
    if previous["position"] == head["position"] and previous["hash"] != head["hash"]:
        return "previous and head at the same position must have the same hash"
    if previous["position"] == 0 and previous["hash"] != history_id:
        return "previous at position 0 must be the history id"
    return None


def head_statement_hash(statement: Any) -> str:
    """The hash an owner key signs: ``hash_canonical(statement, "sha256")``. Raises ValueError on a malformed statement."""
    reason = validate_head_statement(statement)
    if reason is not None:
        raise ValueError(f"invalid head statement: {reason}")
    return hash_canonical(statement, "sha256")


def validate_signed_head_statement(signed: Any) -> str | None:
    """None when ``signed`` is ``{statement, keyId, scheme, signature}`` with a valid statement and a well-formed
    signature for the scheme; else a reason. Does not check the signature."""
    if not _is_record(signed) or not _has_exact_keys(signed, ("statement", "keyId", "scheme", "signature")):
        return "signed statement must have exactly statement, keyId, scheme, signature"
    reason = validate_head_statement(signed["statement"])
    if reason is not None:
        return reason
    if not is_identifier(signed["keyId"]):
        return "keyId must be an identifier"
    if not isinstance(signed["scheme"], str) or signed["scheme"] not in SIGNATURE_SCHEMES:
        return "unknown signature scheme"
    if not suite_for(signed["scheme"]).is_signature(signed["signature"]):
        return "malformed signature"
    return None


def verify_signed_head_statement(signed: Any, owner_keys: Any) -> dict[str, Any]:
    """Verifies a signed head statement against the owner keys valid at the statement's head position.

    ``owner_keys`` is a callable ``position -> [owner key, ...]`` (like the TypeScript ``ownerKeysAt``), or
    anything :func:`irontrellis.owner_keys.owner_keys_at` accepts (a replay state or a list of key epochs).
    Returns ``{"ok": True}`` or ``{"ok": False, "reason": "MALFORMED" | "UNKNOWN_KEY" | "SIGNATURE_INVALID"}``.
    Never raises: a raising ``owner_keys`` counts as ``UNKNOWN_KEY``."""
    if validate_signed_head_statement(signed) is not None:
        return {"ok": False, "reason": "MALFORMED"}
    position = int(signed["statement"]["head"]["position"])
    try:
        if callable(owner_keys):
            keys = owner_keys(position)
        else:
            from .owner_keys import owner_keys_at
            keys = owner_keys_at(owner_keys, position)
    except Exception:
        return {"ok": False, "reason": "UNKNOWN_KEY"}
    key = None
    if isinstance(keys, (list, tuple)):
        key = next((c for c in keys if isinstance(c, dict) and c.get("keyId") == signed["keyId"] and c.get("scheme") == signed["scheme"]), None)
    if key is None:
        return {"ok": False, "reason": "UNKNOWN_KEY"}
    try:
        suite = suite_for(key["scheme"])
        if suite.verify(head_statement_hash(signed["statement"]), signed["signature"], suite.normalize_credential(key["credential"])):
            return {"ok": True}
    except Exception:
        pass
    return {"ok": False, "reason": "SIGNATURE_INVALID"}


# ---------------------------------------------------------------- witness log entries (docs/reference/witness-protocol.md §9.3)


def encode_entry(entry: Any) -> bytes:
    """The canonical bytes of an entry (the Merkle leaf data). Raises CanonicalError for values the canonical form rejects."""
    return canonical_encode(entry).encode("utf-8")


def entry_leaf_hash(entry: Any) -> bytes:
    """RFC 6962 leaf hash of the entry's canonical bytes."""
    return leaf_hash(encode_entry(entry))


def _head_refs_failure(entry: dict) -> str | None:
    """``previousHead`` and ``rotationHead`` are ``{hash, position}`` and the rotation head directly follows the previous one."""
    for side in ("previousHead", "rotationHead"):
        head = entry[side]
        if not _is_record(head) or not _has_exact_keys(head, ("hash", "position")) or not is_content_hash(head["hash"]) or not _is_u53(head["position"]):
            return f"{side} must be {{hash, position}}"
    if entry["rotationHead"]["position"] != entry["previousHead"]["position"] + 1:
        return "rotationHead.position must be previousHead.position + 1"
    return None


def validate_entry(entry: Any) -> str | None:
    """None when ``entry`` is a structurally valid witness entry, else a reason: exact fields per kind, version,
    ``historyId``, ``receivedAt`` (U53) and canonical encodability; REGISTERED: ``historyId`` is the position-0
    prefix hash of ``genesis``; HEAD: a well-formed signed statement for the same history; ROTATED: an
    ``OWNER_KEYS_ROTATED`` event record, ``previousHead`` (the head its owner signature binds) and ``rotationHead``
    with ``rotationHead.position == previousHead.position + 1``; EQUIVOCATION: two well-formed signed statements for
    the same history and position with different head hashes; SUPERSEDED: a rotation, ``previousHead`` and ``rotationHead``
    (consecutive), a ``chain`` statement for the same history stating ``rotationHead`` with a non-null ``previous``
    before it, the range ``supersededFromIndex`` < ``supersededLatest.index`` < ``supersededToIndex`` (U53 leaf indexes),
    ``supersededLatest`` ``{position, hash, index}`` after the last good head, and ``supersededCount`` from 1 to the
    number of leaves strictly inside the range (no field grows with the number of superseded heads). Signatures are
    not verified here."""
    if not _is_record(entry):
        return "entry must be a record"
    if entry.get("version") != WITNESS_ENTRY_VERSION:
        return f"version must be {WITNESS_ENTRY_VERSION}"
    common = ("version", "kind", "historyId", "receivedAt")
    history_id = entry.get("historyId")
    if not is_content_hash(history_id):
        return "historyId must be a lowercase 0x-prefixed sha256 hash"
    if not _is_u53(entry.get("receivedAt")):
        return "receivedAt must be a U53 (ms since epoch)"
    kind = entry.get("kind")
    if kind == "REGISTERED":
        if not _has_exact_keys(entry, (*common, "genesis")):
            return "REGISTERED entry fields are version, kind, historyId, genesis, receivedAt"
        if not _is_record(entry["genesis"]):
            return "genesis must be an event record"
        try:
            computed = HistoryHasher(TRELLIS_FORMAT).push(entry["genesis"])
        except Exception as error:
            return f"genesis is not canonically encodable: {error}"
        if computed != history_id:
            return "historyId is not the position-0 hash of genesis"
    elif kind == "HEAD":
        if not _has_exact_keys(entry, (*common, "signedStatement")):
            return "HEAD entry fields are version, kind, historyId, signedStatement, receivedAt"
        reason = validate_signed_head_statement(entry["signedStatement"])
        if reason is not None:
            return f"signedStatement: {reason}"
        if entry["signedStatement"]["statement"]["historyId"] != history_id:
            return "signedStatement is for another history"
    elif kind == "ROTATED":
        if not _has_exact_keys(entry, (*common, "rotation", "previousHead", "rotationHead")):
            return "ROTATED entry fields are version, kind, historyId, rotation, previousHead, rotationHead, receivedAt"
        if not _is_record(entry["rotation"]) or entry["rotation"].get("type") != "OWNER_KEYS_ROTATED":
            return "rotation must be an OWNER_KEYS_ROTATED event"
        refs = _head_refs_failure(entry)
        if refs is not None:
            return refs
    elif kind == "SUPERSEDED":
        if not _has_exact_keys(entry, (*common, "rotation", "previousHead", "rotationHead", "chain", "supersededFromIndex", "supersededToIndex", "supersededLatest", "supersededCount")):
            return ("SUPERSEDED entry fields are version, kind, historyId, rotation, previousHead, rotationHead, chain, supersededFromIndex, "
                    "supersededToIndex, supersededLatest, supersededCount, receivedAt")
        if not _is_record(entry["rotation"]) or entry["rotation"].get("type") != "OWNER_KEYS_ROTATED":
            return "rotation must be an OWNER_KEYS_ROTATED event"
        refs = _head_refs_failure(entry)
        if refs is not None:
            return refs
        reason = validate_signed_head_statement(entry["chain"])
        if reason is not None:
            return f"chain: {reason}"
        chain = entry["chain"]["statement"]
        rotation_head = entry["rotationHead"]
        if chain["historyId"] != history_id:
            return "chain is for another history"
        if chain["head"]["hash"] != rotation_head["hash"] or chain["head"]["position"] != rotation_head["position"]:
            return "chain must state rotationHead"
        previous = chain["previous"]
        if previous is None or previous["position"] >= rotation_head["position"]:
            return "chain.previous (the last good head) must precede rotationHead"
        if not _is_u53(entry["supersededFromIndex"]) or not _is_u53(entry["supersededToIndex"]):
            return "supersededFromIndex and supersededToIndex must be U53 leaf indexes"
        latest = entry["supersededLatest"]
        if (not _is_record(latest) or not _has_exact_keys(latest, ("position", "hash", "index")) or not _is_u53(latest["position"])
                or not is_content_hash(latest["hash"]) or not _is_u53(latest["index"])):
            return "supersededLatest must be {position, hash, index}"
        if latest["position"] <= previous["position"]:
            return "supersededLatest must come after the last good head"
        low, high = entry["supersededFromIndex"], entry["supersededToIndex"]
        if not low < latest["index"] < high:
            return "supersededLatest.index must lie strictly between supersededFromIndex and supersededToIndex"
        count = entry["supersededCount"]
        if not _is_u53(count) or count < 1 or count > high - low - 1:
            return "supersededCount must be from 1 to the number of leaves strictly inside the range"
    elif kind == "EQUIVOCATION":
        if not _has_exact_keys(entry, (*common, "first", "second")):
            return "EQUIVOCATION entry fields are version, kind, historyId, first, second, receivedAt"
        for side in ("first", "second"):
            reason = validate_signed_head_statement(entry[side])
            if reason is not None:
                return f"{side}: {reason}"
            if entry[side]["statement"]["historyId"] != history_id:
                return f"{side} is for another history"
        first, second = entry["first"]["statement"]["head"], entry["second"]["statement"]["head"]
        if first["position"] != second["position"] or first["hash"] == second["hash"]:
            return "an equivocation is two different heads at the same position"
    else:
        return f"kind must be one of {', '.join(WITNESS_ENTRY_KINDS)}"
    try:
        canonical_encode(entry)
    except Exception as error:
        return f"entry is not canonically encodable: {error}"
    return None


# ---------------------------------------------------------------- receipts (docs/reference/witness-protocol.md §9.5)


def _receipt_failure(reason: str, message: str) -> dict[str, Any]:
    return {"ok": False, "reason": reason, "message": message}


def verify_witness_receipt(receipt: Any, trusted_verifier_keys: Any) -> dict[str, Any]:
    """Verifies a witness receipt: opens the checkpoint note with ``trusted_verifier_keys`` (never the key the
    receipt names), parses the checkpoint, checks its origin against ``receipt.witness.origin``, validates the
    entry, recomputes its leaf hash and verifies the inclusion proof.

    Returns ``{"ok": True, "checkpoint": {"origin", "size", "root": bytes}, "index", "verifiedBy"}`` or
    ``{"ok": False, "reason", "message"}`` with the reasons of the TypeScript ``verifyWitnessReceipt``, in its
    order. Never raises."""
    witness = receipt.get("witness") if _is_record(receipt) else None
    index = _js_integer(receipt.get("index")) if _is_record(receipt) else None
    if (not _is_record(receipt) or receipt.get("version") != WITNESS_RECEIPT_VERSION or not _is_record(witness)
            or not isinstance(witness.get("origin"), str) or not isinstance(witness.get("verifierKey"), str)
            or not isinstance(receipt.get("checkpoint"), str) or not isinstance(receipt.get("inclusionProof"), (list, tuple))
            or index is None or index < 0):
        return _receipt_failure("RECEIPT_MALFORMED", "receipt must be {version, witness: {origin, verifierKey}, entry, index, checkpoint, inclusionProof}")
    try:
        opened = open_note(receipt["checkpoint"], trusted_verifier_keys)
    except NoteError as error:
        return _receipt_failure("NOTE_UNVERIFIED", f"{error.code}: {error}")
    except Exception as error:  # pragma: no cover - defensive
        return _receipt_failure("NOTE_UNVERIFIED", str(error))
    try:
        checkpoint = parse_checkpoint(opened.body)
    except Exception as error:
        return _receipt_failure("CHECKPOINT_MALFORMED", str(error))
    if checkpoint.origin != witness["origin"]:
        return _receipt_failure("ORIGIN_MISMATCH", f"checkpoint origin {checkpoint.origin!r} is not the receipt's witness origin")
    entry = receipt.get("entry")
    try:
        problem = validate_entry(entry)
    except Exception as error:  # pragma: no cover - defensive
        problem = str(error)
    if problem is not None:
        return _receipt_failure("ENTRY_MALFORMED", problem)
    if index >= checkpoint.size:
        return _receipt_failure("INDEX_OUT_OF_RANGE", f"leaf index {index} is not below the checkpoint size {checkpoint.size}")
    proof: list[bytes] = []
    for element in receipt["inclusionProof"]:
        data = decode_base64(element)
        if data is None or len(data) != MERKLE_HASH_SIZE:
            return _receipt_failure("INCLUSION_INVALID", "inclusion proof elements are base64 32-byte hashes")
        proof.append(data)
    try:
        leaf = entry_leaf_hash(entry)
    except Exception as error:
        return _receipt_failure("ENTRY_MALFORMED", str(error))
    if not verify_inclusion(leaf, index, checkpoint.size, proof, checkpoint.root):
        return _receipt_failure("INCLUSION_INVALID", "the inclusion proof does not lead to the checkpoint root")
    return {"ok": True, "checkpoint": {"origin": checkpoint.origin, "size": checkpoint.size, "root": checkpoint.root}, "index": index,
            "verifiedBy": opened.verified_by}


# ---------------------------------------------------------------- witness-signed latest notes (docs/reference/witness-protocol.md §9.8)

# The latest-note version line; a witness origin is never equal to it (domain separation from checkpoints).
LATEST_NOTE_VERSION = "irontrellis-witness-latest/1"
MIN_NONCE_BYTES = 16
MAX_NONCE_BYTES = 64
_NONCE = re.compile(r"[A-Za-z0-9_-]+")
_CONTENT_HASH = re.compile(r"0x[0-9a-f]{64}")


def is_valid_nonce(nonce: Any) -> bool:
    """True iff ``nonce`` is canonical unpadded base64url (RFC 4648 §5) of 16..64 bytes."""
    if not isinstance(nonce, str) or not 22 <= len(nonce) <= 86 or _NONCE.fullmatch(nonce) is None:
        return False
    try:
        raw = base64.urlsafe_b64decode(nonce + "=" * (-len(nonce) % 4))
    except Exception:
        return False
    return MIN_NONCE_BYTES <= len(raw) <= MAX_NONCE_BYTES and base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") == nonce


def _latest_fail(why: str) -> NoteError:
    return NoteError("MALFORMED_LATEST_NOTE", f"latest note: {why}")


def _is_count(value: Any) -> bool:
    return _is_size(value)


def format_latest_note(note: Any) -> str:
    """The body of a latest note (``irontrellis-witness-latest/1``, origin, historyId, nonce, latest position, head hash and
    leaf index or three ``none``, tree size, equivocation count, supersede count; one per line). Raises
    ``NoteError("MALFORMED_LATEST_NOTE")``."""
    if not _is_record(note):
        raise _latest_fail("fields must be a record")
    origin = note.get("origin")
    if not _is_line(origin) or origin == LATEST_NOTE_VERSION:
        raise _latest_fail("origin is one line and not a latest-note version")
    if not isinstance(note.get("historyId"), str) or _CONTENT_HASH.fullmatch(note["historyId"]) is None:
        raise _latest_fail("historyId is 0x + 64 lowercase hex")
    if not is_valid_nonce(note.get("nonce")):
        raise _latest_fail("nonce is canonical base64url of 16..64 bytes")
    if not _is_count(note.get("treeSize")):
        raise _latest_fail("treeSize is a safe non-negative integer")
    if not _is_count(note.get("equivocations")):
        raise _latest_fail("equivocations is a safe non-negative integer")
    if not _is_count(note.get("supersedes")):
        raise _latest_fail("supersedes is a safe non-negative integer")
    latest = note.get("latest")
    if latest is not None:
        if (not _is_record(latest) or not _is_count(latest.get("position")) or not _is_count(latest.get("index"))
                or not isinstance(latest.get("hash"), str) or _CONTENT_HASH.fullmatch(latest["hash"]) is None):
            raise _latest_fail("latest is None or {position, hash, index}")
        if latest["index"] >= note["treeSize"]:
            raise _latest_fail("the latest head's leaf index must be below the tree size")
    head = ("none", "none", "none") if latest is None else (str(latest["position"]), latest["hash"], str(latest["index"]))
    lines = (LATEST_NOTE_VERSION, origin, note["historyId"], note["nonce"], *head, str(note["treeSize"]), str(note["equivocations"]), str(note["supersedes"]))
    return "".join(f"{line}\n" for line in lines)


def parse_latest_note(body: Any) -> dict[str, Any]:
    """Strict parse of a latest-note body (the text of an opened note) into ``{origin, historyId, nonce, latest, treeSize,
    equivocations, supersedes}`` (``latest`` is None or ``{position, hash, index}``). Raises ``NoteError("MALFORMED_LATEST_NOTE")``."""
    if not isinstance(body, str) or not body.endswith("\n") or not _is_well_formed(body):
        raise _latest_fail("not newline-terminated text")
    lines = body[:-1].split("\n")
    if len(lines) != 10:
        raise _latest_fail("not ten lines")
    version, origin, history_id, nonce, position_text, head_hash, index_text, size_text, equivocation_text, supersede_text = lines
    if version != LATEST_NOTE_VERSION:
        raise _latest_fail(f"the first line is not {LATEST_NOTE_VERSION}")
    if not _is_line(origin) or origin == LATEST_NOTE_VERSION:
        raise _latest_fail("origin")
    if _CONTENT_HASH.fullmatch(history_id) is None:
        raise _latest_fail("historyId")
    if not is_valid_nonce(nonce):
        raise _latest_fail("nonce")

    def decimal(text: str, what: str) -> int:
        if _DECIMAL.fullmatch(text) is None:
            raise _latest_fail(f"{what} is not a decimal without leading zeros")
        if len(text) > 16 or int(text) > MAX_SAFE_INTEGER:
            raise _latest_fail(f"{what} exceeds 2^53 - 1")
        return int(text)

    tree_size = decimal(size_text, "tree size")
    equivocations = decimal(equivocation_text, "equivocation count")
    supersedes = decimal(supersede_text, "supersede count")
    nones = sum(1 for text in (position_text, head_hash, index_text) if text == "none")
    if nones not in (0, 3):
        raise _latest_fail("position, hash and index are all present or all none")
    latest: dict[str, Any] | None = None
    if nones == 0:
        if _CONTENT_HASH.fullmatch(head_hash) is None:
            raise _latest_fail("head hash")
        position, index = decimal(position_text, "position"), decimal(index_text, "leaf index")
        if index >= tree_size:
            raise _latest_fail("the leaf index is not below the tree size")
        latest = {"position": position, "hash": head_hash, "index": index}
    return {"origin": origin, "historyId": history_id, "nonce": nonce, "latest": latest, "treeSize": tree_size, "equivocations": equivocations, "supersedes": supersedes}


def _expectation_defect(expect: Any) -> str | None:
    """Why ``expect`` is not a well-formed expectation (None when it is), as the TypeScript ``expectationDefect``: a plain
    ``dict`` (exactly; not a ``MappingProxyType``, ``UserDict``, subclass or list) whose keys are ``historyId`` (a content
    hash), ``nonce`` (canonical base64url of 16..64 bytes) and optionally ``origin`` (one line that is not a latest-note
    version line), each a string of that shape, and nothing else. Any other shape is refused rather than read as
    "expect nothing", which would let a replayed answer to another nonce pass."""
    if type(expect) is not dict:
        return "the expectation is not a plain object"
    for key in expect:
        if key not in ("origin", "historyId", "nonce"):
            return f"the expectation has an unknown field {key}"
    history_id, nonce = expect.get("historyId"), expect.get("nonce")
    if not isinstance(history_id, str) or _CONTENT_HASH.fullmatch(history_id) is None:
        return "the expectation needs historyId, a content hash (0x and 64 lowercase hex digits)"
    if not is_valid_nonce(nonce):
        return "the expectation needs nonce, canonical base64url of 16..64 bytes (the nonce of this request)"
    if "origin" in expect and (not _is_line(expect["origin"]) or expect["origin"] == LATEST_NOTE_VERSION):
        return "the expectation's origin is not one line naming a witness"
    return None


def verify_latest_note(note: Any, trusted_verifier_keys: Any, expect: Any = None) -> dict[str, Any]:
    """Opens a signed latest note with ``trusted_verifier_keys`` (never a key the answer names), parses it and checks it
    against what the client asked: ``expect`` is a dict with ``historyId`` and ``nonce`` (required: without them a
    replayed answer would pass) and optionally ``origin``; an expectation of any other shape (``None`` included) fails
    closed with EXPECTATION_INVALID, checked first. Never raises: returns ``{"ok": True, "latest": fields, "verifiedBy":
    [...]}`` or ``{"ok": False, "reason", "message"}`` with reasons EXPECTATION_INVALID, NOTE_UNVERIFIED,
    LATEST_MALFORMED, ORIGIN_MISMATCH, HISTORY_MISMATCH, NONCE_MISMATCH (the TypeScript ``verifyLatestNote``). To read
    an unverified answer, use :func:`open_note` and :func:`parse_latest_note`."""
    def fail(reason: str, message: str) -> dict[str, Any]:
        return {"ok": False, "reason": reason, "message": message}

    defect = _expectation_defect(expect)
    if defect is not None:
        return fail("EXPECTATION_INVALID", defect)
    expect = dict(expect)  # read once, after the check
    if not isinstance(note, str):
        return fail("NOTE_UNVERIFIED", "a latest note is signed note text")
    try:
        opened = open_note(note, trusted_verifier_keys)
    except NoteError as error:
        return fail("NOTE_UNVERIFIED", f"{error.code}: {error}")
    try:
        parsed = parse_latest_note(opened.body)
    except NoteError as error:
        return fail("LATEST_MALFORMED", str(error))
    if "origin" in expect and parsed["origin"] != expect["origin"]:
        return fail("ORIGIN_MISMATCH", f"the note names origin {parsed['origin']!r}, not {expect['origin']!r}")
    if parsed["historyId"] != expect["historyId"]:
        return fail("HISTORY_MISMATCH", f"the note is about history {parsed['historyId']}, not {expect['historyId']}")
    if parsed["nonce"] != expect["nonce"]:
        return fail("NONCE_MISMATCH", "the note answers another nonce (a replayed or relayed answer)")
    return {"ok": True, "latest": parsed, "verifiedBy": opened.verified_by}


# ---------------------------------------------------------------- witness bindings recorded in a history


def bound_witnesses_of(state: Any) -> list[dict[str, Any]]:
    """The remote witnesses a replayed history binds, as the TypeScript core's ``boundWitnessesOf``: replay applies every
    owner-signed ``WITNESSES_BOUND`` / ``WITNESSES_UNBOUND`` event in turn (validated and, for a registration receipt,
    verified with the witness's key); nothing else, an anchor in particular, binds a witness. Each item is
    ``{url, verifierKey[, name][, allowInsecureHttp]}``, in binding order. This package does not speak the witness
    protocol: it reports the bindings, it does not consult the witnesses."""
    out: list[dict[str, Any]] = []
    for b in getattr(state, "bound_witnesses", []):
        item: dict[str, Any] = {"url": b["url"], "verifierKey": b["verifierKey"]}
        if "name" in b:
            item["name"] = b["name"]
        if b.get("allowInsecureHttp") is True:
            item["allowInsecureHttp"] = True
        out.append(item)
    return out


def bound_policy_of(state: Any) -> dict[str, Any] | None:
    """The owner-signed witness policy minimum in force (docs/reference/witness-policy.md §5.3), as the TypeScript core's ``boundPolicyOf``:
    the ``policy`` ``{quorum, requireOnOpen, maxUnwitnessedEvents}`` of the newest binding event, or None."""
    policy = getattr(state, "bound_policy", None)
    return None if policy is None else dict(policy)


__all__ = [
    "MERKLE_HASH_SIZE", "ALG_ED25519", "MAX_NOTE_SIGNATURES", "HEAD_STATEMENT_VERSION", "WITNESS_ENTRY_VERSION", "WITNESS_ENTRY_KINDS", "WITNESS_RECEIPT_VERSION",
    "encode_base64", "decode_base64",
    "empty_root", "leaf_hash", "node_hash", "root_of", "inclusion_proof", "consistency_proof", "verify_inclusion", "verify_consistency",
    "NoteError", "VerifierKey", "NoteSigner", "OpenedNote", "Checkpoint", "is_valid_note_key_name", "note_key_hash", "verifier_key",
    "parse_verifier_key", "note_signer_from_seed", "parse_signer_key", "sign_note", "open_note", "format_checkpoint", "parse_checkpoint",
    "validate_head_statement", "head_statement_hash", "validate_signed_head_statement", "verify_signed_head_statement",
    "encode_entry", "entry_leaf_hash", "validate_entry", "verify_witness_receipt",
    "LATEST_NOTE_VERSION", "MIN_NONCE_BYTES", "MAX_NONCE_BYTES", "is_valid_nonce", "format_latest_note", "parse_latest_note", "verify_latest_note",
    "bound_witnesses_of", "bound_policy_of",
]
