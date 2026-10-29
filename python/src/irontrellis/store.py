"""Readers for the two JSONL history store formats (spec 01 §E), with chain verification.

* ``continuity-portable-file-store/0.2``: legacy lines whose ``event`` uses the
  reference SDK's tagged-tuple encoding and whose ``recordHash`` is keccak-256.
* ``irontrellis-portable-file-store/1``: the event as plain JSON (bigints as
  markers) and a sha256 ``recordHash``.

Both share ``{version, previousHash, event, recordHash}`` per line with
``recordHash = hash(canonical({version, previousHash, event}))`` chained through
``previousHash``. This module never writes: IronTrellis histories are appended
by the TypeScript engine; the Python package verifies and evaluates them.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any

from .canonical import BigInt, CanonicalError, json_loads, json_loads_with_bigints
from .events import hash_algorithm_of
from .hashing import LEGACY_FORMAT, TRELLIS_FORMAT, hash_canonical

LINE_VERSIONS = {LEGACY_FORMAT: "continuity-portable-file-store/0.2", TRELLIS_FORMAT: "irontrellis-portable-file-store/1"}
_RECORD_KEYS = {"event", "previousHash", "recordHash", "version"}


class StoreError(ValueError):
    """The file is not a well-formed history store (chain, encoding or integrity failure).

    ``code`` is ``UNSUPPORTED_VERSION`` when the first line names a store line version this package does not read
    (the format-2 store lines), otherwise ``None`` (``HistoryRejected`` carries the replay code)."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


class HistoryRejected(StoreError):
    """The records are intact, but the history they carry is refused by the replay rules of the file's line format, and
    the reader cannot hand its events out safely: today, a genesis whose event format disagrees with the line format
    (for example an unsigned ``continuity-event/0.2`` history in ``irontrellis-portable-file-store/1`` lines, which
    :func:`~irontrellis.replay.replay` would otherwise replay under the legacy rules). ``code``, ``position`` and
    ``reason`` are the replay rejection the TypeScript store and :func:`replay_history` report for the same file."""

    def __init__(self, code: str, position: int, reason: str) -> None:
        super().__init__(f"line {position + 1}: history rejected at position {position}: {code}: {reason}")
        self.code = code
        self.position = position
        self.reason = reason


@dataclass(frozen=True)
class StoredHistory:
    format: str
    events: list[Any]
    record_hashes: list[str]


# ---------------------------------------------------------------- legacy tagged-tuple encoding (spec 01 §E.2)


def decode_tagged(value: Any, depth: int = 0) -> Any:
    if depth > 128 or not isinstance(value, list):
        raise StoreError("invalid stored encoding")
    if len(value) == 1 and value[0] == "null":
        return None
    if len(value) != 2:
        raise StoreError("invalid stored encoding")
    tag, body = value
    if tag == "bigint" and isinstance(body, str) and len(body) <= 78 and body.isdigit() and body.isascii() and (body == "0" or body[0] != "0"):
        return BigInt(int(body))
    if tag == "string" and isinstance(body, str):
        return body
    if tag == "number" and type(body) is int and 0 <= body <= 2**53 - 1:
        return body
    # An integral JSON number spelled 24.0 / 24E+0 is the JavaScript number 24, which the reference reader (JSON.parse)
    # accepts; -0 (a float here, see canonical.json_loads) stays rejected, as its record can never hash canonically.
    if tag == "number" and type(body) is float and body.is_integer() and 0 <= body <= 2**53 - 1 and math.copysign(1.0, body) > 0:
        return int(body)
    if tag == "boolean" and isinstance(body, bool):
        return body
    if tag == "array" and isinstance(body, list):
        return [decode_tagged(member, depth + 1) for member in body]
    if tag == "object" and isinstance(body, list):
        result: dict[str, Any] = {}
        for entry in body:
            if not isinstance(entry, list) or len(entry) != 2 or not isinstance(entry[0], str) or entry[0] in result:
                raise StoreError("invalid stored object")
            result[entry[0]] = decode_tagged(entry[1], depth + 1)
        return result
    raise StoreError("invalid stored encoding")


def encode_tagged(value: Any) -> Any:
    """Writer-side encoding without key sorting: the reader's round-trip check."""
    if value is None:
        return ["null"]
    if isinstance(value, BigInt):
        return ["bigint", str(value.value)]
    if isinstance(value, bool):
        return ["boolean", value]
    if isinstance(value, list):
        return ["array", [encode_tagged(member) for member in value]]
    if isinstance(value, dict):
        return ["object", [[key, encode_tagged(member)] for key, member in value.items()]]
    if isinstance(value, str):
        return ["string", value]
    if isinstance(value, int):
        return ["number", value]
    raise StoreError("unsupported stored value")


# ---------------------------------------------------------------- lines


def line_format_of(first_line: str) -> str:
    if first_line.startswith("\ufeff"):  # what some Windows editors add when they save UTF-8: refused, but named (as in TS)
        raise StoreError("first record is unparsable: the file starts with a UTF-8 byte order mark (added by an editor?); a history is UTF-8 without one")
    try:
        version = json.loads(first_line).get("version")
    except Exception as error:
        raise StoreError(f"first record is unparsable: {error}") from error
    for history_format, line_version in LINE_VERSIONS.items():
        if line_version == version:
            return history_format
    raise StoreError(f"unknown store format {version!r}", "UNSUPPORTED_VERSION")


def parse_line(line: str, history_format: str, previous_hash: str | None) -> tuple[Any, str]:
    """Every check the reference reader makes (spec 01 §E.4 step 4), for either format: returns (event, recordHash)."""
    legacy = history_format == LEGACY_FORMAT
    try:
        record = json_loads(line) if legacy else json_loads_with_bigints(line)
    except (ValueError, CanonicalError) as error:  # CanonicalError covers nesting past the recursion limit
        raise StoreError(f"unparsable record: {error}") from error
    if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
        raise StoreError("record must carry exactly version, previousHash, event and recordHash")
    if record["version"] != LINE_VERSIONS[history_format]:
        raise StoreError(f"unexpected record version {record['version']!r}")
    if record["previousHash"] != previous_hash:
        raise StoreError("record hash chain mismatch")
    event = record["event"]
    if legacy:
        event = decode_tagged(record["event"])
        if encode_tagged(event) != record["event"]:
            raise StoreError("noncanonical store encoding")
    try:
        record_hash = hash_canonical({"version": record["version"], "previousHash": previous_hash, "event": event}, hash_algorithm_of(history_format))
    except CanonicalError as error:
        raise StoreError(f"record is not canonical: {error.reason}") from error
    if record["recordHash"] != record_hash:
        raise StoreError("record integrity check failed")
    return event, record_hash


def _check_genesis_format(history_format: str, genesis: Any) -> None:
    """Raises :class:`HistoryRejected` when the genesis claims another event format than the file's line format.

    The event list a reader returns is replayed by :func:`~irontrellis.replay.replay`, which picks its rules from the
    genesis. A genesis of the other format would therefore be replayed under rules the file does not declare (a legacy,
    owner-unsigned history accepted from a format-1 file). The TypeScript store replays with the rules of the line
    format and rejects such a file at position 0; the reader refuses it with that same rejection, found by applying the
    genesis to an empty state of the line format. A file whose genesis agrees is untouched."""
    from .replay import apply_event, detect_format
    from .state import ReplayState

    if detect_format([genesis]) == history_format:
        return
    result = apply_event(ReplayState(history_format), genesis)
    if result.ok:  # unreachable: a genesis is validated against the format it declares
        raise HistoryRejected("EVENT_DATA_INVALID", 0, f"the genesis does not declare the line format {history_format}")
    raise HistoryRejected(result.code or "INVALID_INPUT", 0, result.reason or "")


def read_history_text(text: str) -> StoredHistory:
    """Parses a whole store file; strict UTF-8 and a complete trailing newline are required.

    Raises :class:`StoreError` on a record defect and :class:`HistoryRejected` (a ``StoreError``) when the genesis
    declares another event format than the lines (see :func:`_check_genesis_format`), so that ``replay(read_history(p).events)``
    and ``replay(load_events(p))`` never replay a file under rules it does not declare. Defects are reported in file
    order, as the TypeScript store does: a genesis rejection comes before a record defect on a later line."""
    if text == "":
        raise StoreError("empty history file")
    if not text.endswith("\n"):
        raise StoreError("history file does not end with a newline")
    lines = text[:-1].split("\n")
    history_format = line_format_of(lines[0])
    events: list[Any] = []
    record_hashes: list[str] = []
    previous: str | None = None
    for index, line in enumerate(lines):
        if line == "":
            raise StoreError(f"line {index + 1} is empty")
        try:
            event, record_hash = parse_line(line, history_format, previous)
        except StoreError as error:
            raise StoreError(f"line {index + 1}: {error}") from error
        if index == 0:
            _check_genesis_format(history_format, event)
        events.append(event)
        record_hashes.append(record_hash)
        previous = record_hash
    return StoredHistory(history_format, events, record_hashes)


def read_history(path: str) -> StoredHistory:
    with open(path, "rb") as handle:
        data = handle.read()
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise StoreError(f"history file is not UTF-8: {error}") from error
    return read_history_text(text)


def replay_history_bytes(data: bytes) -> tuple[StoredHistory, Any]:
    """Reads and replays a store file exactly as the TypeScript store does (docs/HISTORY-FORMAT.md §3: "a reader verifies,
    line by line: the key set, the version literal, the previousHash chain, the encoding, the recordHash, and then applies
    the event to the replay state"). Each line is decoded (strict UTF-8), checked and its event applied before the next
    line is read, with the replay rules of the file's line format, so the defect reported is the first one in file order:
    a record defect raises :class:`StoreError` (``line N: …``), a replay rejection is returned as the REJECTED
    :class:`~irontrellis.replay.ReplayResult` (with the records checked before it). Returns ``(stored, result)``."""
    from .replay import ReplayResult, apply_event, incomplete_migration
    from .state import ReplayState

    if data == b"":
        raise StoreError("empty history file")
    if not data.endswith(b"\n"):
        raise StoreError("history file does not end with a newline")
    raw_lines = data[:-1].split(b"\n")

    def text_of(index: int) -> str:
        try:
            return raw_lines[index].decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise StoreError(f"line {index + 1}: not valid UTF-8: {error}") from error

    history_format = line_format_of(text_of(0))
    state = ReplayState(history_format)
    events: list[Any] = []
    record_hashes: list[str] = []
    previous: str | None = None
    for index in range(len(raw_lines)):
        line = text_of(index)
        if line == "":
            raise StoreError(f"line {index + 1} is empty")
        try:
            event, record_hash = parse_line(line, history_format, previous)
        except StoreError as error:
            raise StoreError(f"line {index + 1}: {error}") from error
        result = apply_event(state, event)
        if not result.ok:
            return StoredHistory(history_format, events, record_hashes), ReplayResult("REJECTED", code=result.code, position=len(state.events), reason=result.reason)
        events.append(event)
        record_hashes.append(record_hash)
        previous = record_hash
    incomplete = incomplete_migration(state)
    if incomplete is not None:
        return StoredHistory(history_format, events, record_hashes), ReplayResult("REJECTED", code=incomplete[0], position=len(state.events), reason=incomplete[1])
    return StoredHistory(history_format, events, record_hashes), ReplayResult("ACCEPTED", state, state.head, len(state.events))


def replay_history(path: str) -> tuple[StoredHistory, Any]:
    """:func:`replay_history_bytes` over a file."""
    with open(path, "rb") as handle:
        return replay_history_bytes(handle.read())


def load_events(path: str) -> list[Any]:
    """Events of a ``.jsonl`` store (chain verified, genesis format checked against the line format, see
    :func:`read_history_text`) or a plain ``.json`` event array (markers decoded; an array carries no line format, so
    :func:`~irontrellis.replay.replay` reads its format from the genesis, as the TypeScript ``replay`` does)."""
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        try:
            return json_loads_with_bigints(text)
        except (ValueError, CanonicalError) as error:  # malformed JSON, a malformed marker, nesting too deep
            raise StoreError(f"{path} is not a JSON event array: {error}") from error
    return read_history(path).events
