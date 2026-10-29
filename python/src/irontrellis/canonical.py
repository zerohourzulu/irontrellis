"""Canonical encoding (``continuity-canonical/0.2``), shared by both history formats.

The canonical text is compact JSON with record keys sorted in code-point
(= UTF-8 byte) order, integers only, and 256-bit quantities spelled as
``{"$continuity.bigint":"<decimal>"}``. Every hash in the protocol is taken
over this text, so it must be byte-identical to the TypeScript engine's
``canonicalEncode`` for every value that engine accepts, and must reject
exactly the values it rejects (spec 01 §A).

Two JavaScript distinctions have no native Python counterpart and are modelled
explicitly here:

* ``number`` vs ``bigint`` — a protocol quantity (amounts, ceilings, usage) is a
  :class:`BigInt`; a plain ``int`` is always a JavaScript ``number`` and must be a
  safe integer (|n| <= 2^53 - 1). ``bool`` is never a number.
* ``undefined`` — JSON never produces it, so "an undefined-valued field is
  dropped" needs no Python equivalent; ``None`` is JSON ``null``.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any

MAX_STRING_BYTES = 4096
MAX_IDENTIFIER_BYTES = 256
MAX_RECORD_KEYS = 256
MAX_LIST_MEMBERS = 4096
MAX_DEPTH = 32
MAX_TOTAL_BYTES = 16_777_216
MAX_SAFE_INTEGER = 2**53 - 1
MAX_PROTOCOL_BIGINT = (1 << 256) - 1
BIGINT_MARKER_KEY = "$continuity.bigint"
RESERVED_KEY_PREFIX = "$continuity."


@dataclass(frozen=True, order=True)
class BigInt:
    """A JavaScript ``bigint``: distinct from ``int`` (a JavaScript ``number``).

    Ordering and equality compare the wrapped value, so BigInts can be used as
    amounts and ceilings directly; arithmetic with another BigInt yields a BigInt.
    """

    value: int

    def __add__(self, other: BigInt) -> BigInt:
        return BigInt(self.value + other.value)

    def __repr__(self) -> str:
        return f"BigInt({self.value})"


class CanonicalError(ValueError):
    """Raised for every canonical rejection; ``limit`` marks size/depth/count overruns."""

    def __init__(self, reason: str, location: str = "$", limit: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.location = location
        self.limit = limit


# ---------------------------------------------------------------- strings


def utf8_length(value: str, maximum: int) -> int | None:
    """UTF-8 byte length of a well-formed string within ``maximum``; None otherwise."""
    if len(value) > maximum:
        return None
    try:
        length = len(value.encode("utf-8"))
    except UnicodeEncodeError:  # lone surrogate
        return None
    return None if length > maximum else length


# The characters the canonical form escapes: `"`, `\` and U+0000..U+001F (C-speed search instead of a per-character loop).
_ESCAPED = re.compile(r'[\x00-\x1f"\\]')


def _scan_string(value: str, maximum: int, location: Any) -> int:
    """Validates a string and returns the byte length of its escaped canonical spelling (no quotes)."""
    if value.isascii():
        length = len(value)  # ASCII: one byte per character, and no surrogates
    else:
        try:
            length = len(value.encode("utf-8"))
        except UnicodeEncodeError:
            where = location() if callable(location) else location
            raise CanonicalError(f"Canonical string at {where} is not well-formed Unicode.", where) from None
    if length > maximum:
        where = location() if callable(location) else location
        raise CanonicalError(f"Canonical string at {where} exceeds the {maximum}-byte ProtocolString bound.", where, True)
    if _ESCAPED.search(value) is None:
        return length
    extra = 0
    for char in _ESCAPED.findall(value):
        extra += 5 if char < " " else 1
    return length + extra


def _escape(value: str) -> str:
    """Only ``"``, ``\\`` and U+0000..U+001F are escaped (lowercase ``\\u00xx``); everything else is raw."""
    out: list[str] = ['"']
    for char in value:
        code = ord(char)
        if code >= 0x20 and code != 0x22 and code != 0x5C:
            out.append(char)
        elif code == 0x22:
            out.append('\\"')
        elif code == 0x5C:
            out.append("\\\\")
        else:
            out.append(f"\\u00{code:02x}")
    out.append('"')
    return "".join(out)


def _needs_escape(value: str) -> bool:
    return _ESCAPED.search(value) is not None


def compare_protocol_strings(left: str, right: str) -> int:
    """UTF-8 byte order (spec 01 A.1): code-point order, which is Python's native ``str`` order."""
    _scan_string(left, MAX_STRING_BYTES, "$left")
    _scan_string(right, MAX_STRING_BYTES, "$right")
    return -1 if left < right else 1 if left > right else 0


# ---------------------------------------------------------------- walker


class _Context:
    __slots__ = ("bytes", "max_bytes", "max_depth", "path", "depth")

    def __init__(self, max_bytes: int, max_depth: int, ancestors: int) -> None:
        self.bytes = 0
        self.max_bytes = max_bytes
        self.max_depth = max_depth
        self.path: list[Any] = []
        self.depth = ancestors

    def location(self) -> str:
        text = "$"
        for segment in self.path:
            text += f"[{segment}]" if isinstance(segment, int) else f".{segment}"
        return text

    def charge(self, count: int) -> None:
        self.bytes += count
        if self.bytes > self.max_bytes:
            raise CanonicalError(f"Canonical value at $ exceeds the {self.max_bytes}-byte canonical capture bound.", "$", True)

    def depth_error(self) -> CanonicalError:
        location = self.location()
        return CanonicalError(f"Canonical value at {location} exceeds nesting depth {self.max_depth}.", location, True)


def _number(value: Any, ctx: _Context) -> int:
    """A JavaScript number: a finite safe integer other than negative zero. Integral floats are numbers."""
    if isinstance(value, float):
        if not math.isfinite(value):
            location = ctx.location()
            raise CanonicalError(f"Canonical number at {location} must be finite.", location)
        if value != math.floor(value) or (value == 0 and math.copysign(1.0, value) < 0) or abs(value) > MAX_SAFE_INTEGER:
            location = ctx.location()
            raise CanonicalError(f"Canonical number at {location} must be a signed safe integer other than negative zero.", location)
        return int(value)
    if abs(value) > MAX_SAFE_INTEGER:
        location = ctx.location()
        raise CanonicalError(f"Canonical number at {location} must be a signed safe integer other than negative zero.", location)
    return value


def _check_bigint(value: int, ctx: _Context) -> None:
    if value < -MAX_PROTOCOL_BIGINT or value > MAX_PROTOCOL_BIGINT:
        location = ctx.location()
        raise CanonicalError(f"Canonical BigInt at {location} exceeds the 256-bit protocol bound.", location, True)


def _marker_decimal(value: Any, ctx: _Context) -> int:
    if not isinstance(value, str) or len(value) > 79 or not _is_marker_decimal(value):
        location = f"{ctx.location()}.{BIGINT_MARKER_KEY}"
        raise CanonicalError(f"Canonical BigInt marker at {location} has an invalid decimal value.", location)
    parsed = int(value)
    if parsed < -MAX_PROTOCOL_BIGINT or parsed > MAX_PROTOCOL_BIGINT:
        location = f"{ctx.location()}.{BIGINT_MARKER_KEY}"
        raise CanonicalError(f"Canonical BigInt at {location} exceeds the 256-bit protocol bound.", location, True)
    return parsed


def _is_marker_decimal(text: str) -> bool:
    if text == "0":
        return True
    body = text[1:] if text.startswith("-") else text
    return body.isdigit() and body.isascii() and body[0] != "0"


def _record_keys(value: dict, ctx: _Context) -> list[str] | None:
    """Validates a record's shape; returns its keys in canonical order or None for the exact bigint marker."""
    keys = list(value.keys())
    if len(keys) > MAX_RECORD_KEYS:
        location = ctx.location()
        raise CanonicalError(f"Canonical record at {location} exceeds the {MAX_RECORD_KEYS}-field bound.", location, True)
    reserved = False
    for key in keys:
        if not isinstance(key, str):
            location = ctx.location()
            raise CanonicalError(f"Canonical record at {location} has a non-string key.", location)
        # Spec 01 §A.6 step 3, as the reference: every key is a ProtocolString before the reserved-prefix rule, the depth
        # bound and any field (the first error decides the replay code).
        _scan_string(key, MAX_STRING_BYTES, lambda: f"{ctx.location()}.{{key}}")
        if key.startswith(RESERVED_KEY_PREFIX):
            reserved = True
    if reserved:
        if len(keys) != 1 or keys[0] != BIGINT_MARKER_KEY:
            location = ctx.location()
            raise CanonicalError(
                f"Canonical record at {location} uses the reserved {RESERVED_KEY_PREFIX} key prefix outside the exact BigInt marker shape.",
                location,
            )
        return None
    if ctx.depth >= ctx.max_depth:
        raise ctx.depth_error()
    return sorted(keys)


def _walk(value: Any, ctx: _Context) -> tuple[str, Any]:
    """Encodes ``value`` and returns ``(canonical text, captured copy)`` in one pass."""
    if isinstance(value, str):
        ctx.charge(_scan_string(value, MAX_STRING_BYTES, ctx.location) + 2)
        return (_escape(value) if _needs_escape(value) else f'"{value}"'), value
    if isinstance(value, bool):
        ctx.charge(4 if value else 5)
        return ("true" if value else "false"), value
    if isinstance(value, (int, float)):
        number = _number(value, ctx)
        text = str(number)
        ctx.charge(len(text))
        return text, number
    if isinstance(value, BigInt):
        _check_bigint(value.value, ctx)
        text = f'{{"{BIGINT_MARKER_KEY}":"{value.value}"}}'
        ctx.charge(len(text))
        return text, value
    if value is None:
        ctx.charge(4)
        return "null", None
    if isinstance(value, (list, tuple)):
        length = len(value)
        if ctx.depth >= ctx.max_depth:
            raise ctx.depth_error()
        if length > MAX_LIST_MEMBERS:
            location = ctx.location()
            raise CanonicalError(f"Canonical array at {location} exceeds the {MAX_LIST_MEMBERS}-member bound.", location, True)
        ctx.charge(2 if length == 0 else length + 1)
        ctx.depth += 1
        parts: list[str] = []
        copy: list[Any] = []
        for index, entry in enumerate(value):
            ctx.path.append(index)
            text, captured = _walk(entry, ctx)
            ctx.path.pop()
            parts.append(text)
            copy.append(captured)
        ctx.depth -= 1
        return "[" + ",".join(parts) + "]", copy
    if isinstance(value, dict):
        keys = _record_keys(value, ctx)
        if keys is None:
            decimal = _marker_decimal(value[BIGINT_MARKER_KEY], ctx)
            text = f'{{"{BIGINT_MARKER_KEY}":"{decimal}"}}'
            ctx.charge(len(text))
            return text, BigInt(decimal)
        ctx.charge(2)
        ctx.depth += 1
        parts = []
        copy_record: dict[str, Any] = {}
        for index, key in enumerate(keys):
            key_bytes = _scan_string(key, MAX_STRING_BYTES, lambda: f"{ctx.location()}.{{key}}")
            key_text = _escape(key) if _needs_escape(key) else f'"{key}"'
            ctx.charge(key_bytes + (3 if index == 0 else 4))
            ctx.path.append(key)
            text, captured = _walk(value[key], ctx)
            ctx.path.pop()
            parts.append(f"{key_text}:{text}")
            copy_record[key] = captured
        ctx.depth -= 1
        return "{" + ",".join(parts) + "}", copy_record
    location = ctx.location()
    raise CanonicalError(f"Canonical value at {location} has unsupported type {type(value).__name__}.", location)


def _budget(max_total_bytes: int | None) -> int:
    if max_total_bytes is None:
        return MAX_TOTAL_BYTES
    if not isinstance(max_total_bytes, int) or max_total_bytes < 0:
        raise CanonicalError("maxTotalBytes must be a nonnegative safe integer.")
    return min(max_total_bytes, MAX_TOTAL_BYTES)


def canonical_encode(value: Any, *, ancestor_depth: int = 0, max_total_bytes: int | None = None) -> str:
    """Exact ``continuity-canonical/0.2`` text (no whitespace). Raises CanonicalError."""
    ctx = _Context(_budget(max_total_bytes), MAX_DEPTH, ancestor_depth)
    return _walk(value, ctx)[0]


def canonical_bytes(value: Any, **options: Any) -> bytes:
    return canonical_encode(value, **options).encode("utf-8")


def capture_value(value: Any, *, max_depth: int | None = None, max_total_bytes: int | None = None) -> Any:
    """Validates structure and limits and returns a plain deep copy: keys in canonical
    order, bigint markers decoded to :class:`BigInt`, integral floats normalised to int.
    The copy is what the engine keeps; callers treat it as immutable by convention."""
    depth = MAX_DEPTH if max_depth is None else min(max_depth, MAX_DEPTH)
    ctx = _Context(_budget(max_total_bytes), depth, 0)
    return _walk(value, ctx)[1]


# ---------------------------------------------------------------- predicates


def is_number(value: Any) -> bool:
    return type(value) is int


def is_identifier(value: Any) -> bool:
    """1..256 UTF-8 bytes, well-formed, no C0 control and no DEL."""
    if not isinstance(value, str) or len(value) == 0:
        return False
    if utf8_length(value, MAX_IDENTIFIER_BYTES) is None:
        return False
    return not any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)


def is_protocol_string(value: Any) -> bool:
    return isinstance(value, str) and utf8_length(value, MAX_STRING_BYTES) is not None


def is_u53(value: Any) -> bool:
    return type(value) is int and 0 <= value <= MAX_SAFE_INTEGER


def is_amount(value: Any) -> bool:
    return isinstance(value, BigInt) and 0 <= value.value <= MAX_PROTOCOL_BIGINT


def _is_lower_hex(text: str) -> bool:
    return all(c in "0123456789abcdef" for c in text)


def _is_hex(text: str) -> bool:
    return all(c in "0123456789abcdefABCDEF" for c in text)


def is_content_hash(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 66 and value.startswith("0x") and _is_lower_hex(value[2:])


def is_ethereum_address(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 42 and value.startswith("0x") and _is_hex(value[2:])


def is_public_key_hex(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 66 and value.startswith("0x") and _is_hex(value[2:])


def is_signature_64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 130 and value.startswith("0x") and _is_lower_hex(value[2:])


def is_chain_id(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 78 or not value.isdigit() or not value.isascii() or value[0] == "0":
        return False
    return int(value) <= MAX_PROTOCOL_BIGINT


def sorted_identifiers(values: list[str]) -> list[str]:
    for index, member in enumerate(values):
        _scan_string(member, MAX_STRING_BYTES, f"$[{index}]")
    return sorted(values)


# ---------------------------------------------------------------- JSON with bigint markers


def to_plain(value: Any) -> Any:
    """BigInts become marker records; the wire form the adapters and the CLI emit."""
    if isinstance(value, BigInt):
        return {BIGINT_MARKER_KEY: str(value.value)}
    if isinstance(value, dict):
        return {key: to_plain(member) for key, member in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_plain(member) for member in value]
    return value


def from_plain(value: Any) -> Any:
    """Strict reverse of :func:`to_plain`: marker records become BigInts (CanonicalError otherwise)."""
    if isinstance(value, dict):
        if BIGINT_MARKER_KEY in value:
            decimal = value[BIGINT_MARKER_KEY]
            if len(value) != 1 or not isinstance(decimal, str) or len(decimal) > 79 or not _is_marker_decimal(decimal):
                raise CanonicalError("Canonical BigInt marker has an invalid decimal value.")
            parsed = int(decimal)
            if parsed < -MAX_PROTOCOL_BIGINT or parsed > MAX_PROTOCOL_BIGINT:
                raise CanonicalError("Canonical BigInt exceeds the 256-bit protocol bound.", "$", True)
            return BigInt(parsed)
        return {key: from_plain(member) for key, member in value.items()}
    if isinstance(value, list):
        return [from_plain(member) for member in value]
    return value


def json_dumps_with_bigints(value: Any) -> str:
    return json.dumps(to_plain(value), separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _parse_int(text: str) -> Any:
    # JSON `-0` is the JavaScript number -0 (which every protocol check rejects, as JSON.parse keeps it), not the integer 0.
    return -0.0 if text == "-0" else int(text)


def json_loads(text: str) -> Any:
    """``json.loads`` reading protocol JSON as JavaScript's ``JSON.parse`` does: ``-0`` stays negative zero (a float, so the
    canonical layer rejects it like the TypeScript engine), and nesting past the interpreter's recursion limit is a
    :class:`CanonicalError` (a limit) instead of ``RecursionError``. Malformed JSON raises ``ValueError``."""
    try:
        return json.loads(text, parse_int=_parse_int)
    except RecursionError as error:
        raise CanonicalError("JSON text nests deeper than this reader supports.", "$", True) from error


def json_loads_with_bigints(text: str) -> Any:
    """:func:`json_loads`, then :func:`from_plain` (markers become BigInts). Raises ValueError (CanonicalError included)."""
    value = json_loads(text)
    try:
        return from_plain(value)
    except RecursionError as error:
        raise CanonicalError("JSON value nests deeper than this reader supports.", "$", True) from error
