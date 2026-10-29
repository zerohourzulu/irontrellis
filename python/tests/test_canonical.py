"""Canonical encoding: byte-identity with the reference, rejections, and the bigint marker."""
from __future__ import annotations

import json

import pytest
from conftest import load_json, LEGACY_FIXTURES

from irontrellis.canonical import (
    BigInt, CanonicalError, canonical_encode, capture_value, compare_protocol_strings, from_plain, is_amount, is_identifier, is_u53,
    json_dumps_with_bigints, json_loads_with_bigints, to_plain,
)


def test_sorted_compact_and_escaped():
    assert canonical_encode({"b": 1, "a": [True, None, "x\"y\\z\u0001"]}) == '{"a":[true,null,"x\\"y\\\\z\\u0001"],"b":1}'


def test_unicode_is_raw_and_sorted_by_code_point():
    assert canonical_encode({"é": 1, "z": 2, "\U0001F600": 3}) == '{"z":2,"é":1,"\U0001F600":3}'
    assert compare_protocol_strings("￿", "\U00010000") < 0  # astral after the BMP, as UTF-8 byte order demands


def test_bigint_marker_round_trip():
    text = canonical_encode({"amount": BigInt(2500)})
    assert text == '{"amount":{"$continuity.bigint":"2500"}}'
    assert capture_value(json.loads(text)) == {"amount": BigInt(2500)}
    assert canonical_encode(json.loads(text)) == text
    assert to_plain(from_plain({"a": {"$continuity.bigint": "-7"}})) == {"a": {"$continuity.bigint": "-7"}}


@pytest.mark.parametrize("value", [{"$continuity.bigint": "007"}, {"$continuity.bigint": "1", "x": 1}, {"$continuity.other": 1}, {"$continuity.bigint": "1" * 80}])
def test_reserved_marker_shapes_are_rejected(value):
    with pytest.raises(CanonicalError):
        canonical_encode(value)


@pytest.mark.parametrize("value", [1.5, float("nan"), float("inf"), -0.0, 2**53, -(2**53)])
def test_non_integers_and_unsafe_numbers_are_rejected(value):
    with pytest.raises(CanonicalError):
        canonical_encode({"n": value})


def test_integral_float_is_a_number():
    assert canonical_encode({"n": 5.0}) == '{"n":5}'
    assert capture_value(5.0) == 5 and type(capture_value(5.0)) is int


def test_bigint_bound():
    assert canonical_encode(BigInt((1 << 256) - 1)).endswith('"}')
    with pytest.raises(CanonicalError) as error:
        canonical_encode(BigInt(1 << 256))
    assert error.value.limit


def test_lone_surrogate_and_depth_limits():
    with pytest.raises(CanonicalError):
        canonical_encode("\ud800")
    nested = 1
    for _ in range(33):
        nested = [nested]
    with pytest.raises(CanonicalError) as error:
        canonical_encode(nested)
    assert error.value.limit


def test_predicates_distinguish_number_bool_and_bigint():
    assert is_u53(5) and not is_u53(True) and not is_u53(-1) and not is_u53(BigInt(5))
    assert is_amount(BigInt(0)) and not is_amount(5) and not is_amount(BigInt(-1))
    assert is_identifier("a") and not is_identifier("") and not is_identifier("a\u007f") and not is_identifier("x" * 257)


def test_json_helpers():
    text = json_dumps_with_bigints({"a": BigInt(1), "b": [BigInt(2)]})
    assert json_loads_with_bigints(text) == {"a": BigInt(1), "b": [BigInt(2)]}


def test_fixture_canonical_text_matches_spec_vector(crypto_vectors):
    vector = crypto_vectors["eventHistoryPrefixHashes"]
    for event, expected in zip(from_plain(vector["events"]), vector["eventCanonicalText"]):
        assert canonical_encode(event) == expected


def test_capture_sorts_keys_of_fixture_events():
    events = load_json(LEGACY_FIXTURES / "handover-history.json")
    captured = capture_value(from_plain(events))
    for event in captured:
        assert list(event) == sorted(event)
        assert list(event["data"]) == sorted(event["data"])
