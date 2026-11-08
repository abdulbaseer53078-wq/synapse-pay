"""The scheme simulator's checks, without a network: if these are loose, the harness passes broken firmware."""
from datetime import UTC, datetime

import pytest

from harness import chip_data, tlv
from scheme_sim import check, parse_tlv

NOW = datetime(2026, 11, 8, tzinfo=UTC)
CASE = {"scheme": "VISA", "amount": 15000, "currency": "INR"}


def request(tags=None, fields=None):
    req = {2: b"4111111111111111", 3: b"000000", 4: b"000000015000", 14: b"3008", 22: b"051", 49: b"356",
           55: bytes.fromhex(tlv(tags if tags is not None else chip_data(CASE, NOW)))}
    req.update(fields or {})
    return req


def test_good_chip_request_passes():
    assert check(request(), NOW) == (None, "VISA", [])


@pytest.mark.parametrize("data, problem", [
    ("9F2608" + "00" * 7, "runs past the end"),
    ("00" + "9C0100", "padding"),
    ("9C0100" + "9C0100", "repeated"),
    ("9C810100", "non-minimal"),
    ("9C83000001", "unsupported length"),
    ("700300", "constructed"),
    ("9F", "truncated tag"),
])
def test_tlv_parser_is_strict(data, problem):
    with pytest.raises(ValueError, match=problem):
        parse_tlv(bytes.fromhex(data))


def test_each_rule_refuses():
    tags = chip_data(CASE, NOW)
    del tags["9F26"]
    assert check(request(tags), NOW)[0::2] == ("30", ["DE 55: tag 9F26 missing"])
    assert check(request(fields={4: b"000000015001"}), NOW)[2] == ["DE 55: 9F02 differs from DE 4"]
    assert check(request(fields={49: b"840"}), NOW)[2] == ["DE 55: 5F2A differs from DE 49"]
    assert check(request(chip_data({**CASE, "scheme": "RUPAY"}, NOW)), NOW)[2] == ["DE 55: AID is not a VISA application"]
    short = chip_data(CASE, NOW) | {"9F37": "0102"}
    assert check(request(short), NOW)[2] == ["DE 55: tag 9F37 is 2 bytes, expected 4..4"]
    assert check(request(fields={2: b"4111111111111112"}), NOW)[0] == "14"
    assert check(request(fields={14: b"2010"}), NOW)[0] == "54"
    no_chip = request()
    del no_chip[55]
    assert check(no_chip, NOW)[0] == "30"
