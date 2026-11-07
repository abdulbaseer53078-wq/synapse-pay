"""The audit library: event mapping, hash chaining and PAN masking. No database, no Kafka."""
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.audit import GENESIS, AuditEvent, Chain, actor_for, compute_hash, event_type_for, from_dict, sanitize
from app.audit.sanitize import REMOVED, luhn_ok, mask_pan


def _event(**overrides) -> AuditEvent:
    base = dict(event_id=uuid4(), timestamp=datetime(2026, 11, 7, 10, 0, 1, 123000, tzinfo=UTC),
                event_type="TRANSACTION_AUTHORIZED", actor="terminal:abc", entity_id="txn-1",
                correlation_id="txn-1", payload={"amount": 49999})
    return AuditEvent(**{**base, **overrides})


# --- 7.1 event types ------------------------------------------------------------------------------------

@pytest.mark.parametrize("entity, action, to_status, expected", [
    ("terminal", "create", "PENDING", "TERMINAL_CREATED"),
    ("terminal", "revoke", "REVOKED", "TERMINAL_REVOKED"),
    ("terminal", "health_change", "DEGRADED", "TERMINAL_HEALTH_CHANGED"),
    ("terminal", "something_new", "ACTIVE", "TERMINAL_SOMETHING_NEW"),
    ("transaction", "transaction.create", "INITIATED", "TRANSACTION_INITIATED"),
    ("transaction", "transaction.send", "PENDING", "TRANSACTION_SUBMITTED"),
    ("transaction", "transaction.finish", "AUTHORIZED", "TRANSACTION_AUTHORIZED"),
    ("transaction", "transaction.finish", "FAILED", "TRANSACTION_FAILED"),
    ("transaction", "transaction.finish", "PARTIALLY_REFUNDED", "TRANSACTION_REFUNDED"),
    ("transaction", "transaction.finish", "WEIRD", "TRANSACTION_STATUS_CHANGED"),
    ("merchant", "list_terminals", None, "ADMIN_ACCESS"),
])
def test_event_type_for(entity, action, to_status, expected):
    assert event_type_for(entity, action, to_status) == expected


def test_actor_for():
    assert actor_for("SYSTEM", None) == "system"
    assert actor_for("TERMINAL", "t-1") == "terminal:t-1"
    assert actor_for("MERCHANT", "m-1") == "merchant:m-1"
    assert actor_for("ADMIN", "a-1") == "admin:a-1"


def test_event_rejects_naive_timestamp():
    with pytest.raises(ValueError, match="timezone-aware"):
        _event(timestamp=datetime(2026, 11, 7))


def test_event_rejects_lowercase_type_and_bare_actor():
    with pytest.raises(ValueError):
        _event(event_type="transaction_authorized")
    with pytest.raises(ValueError):
        _event(actor="terminal")


def test_timestamp_is_millisecond_precision_utc():
    assert _event().to_dict()["timestamp"] == "2026-11-07T10:00:01.123Z"


# --- 7.3 chaining ---------------------------------------------------------------------------------------

def test_chain_links_each_event_to_the_previous_hash():
    chain = Chain()
    a, b = chain.append(_event()), chain.append(_event())
    assert a.sequence == 1 and a.prev_hash == GENESIS
    assert b.sequence == 2 and b.prev_hash == a.hash
    assert chain.head == b.hash


def test_hash_is_stable_across_key_order():
    event = _event(payload={"b": 1, "a": 2})
    reordered = _event(event_id=event.event_id, timestamp=event.timestamp, payload={"a": 2, "b": 1})
    assert compute_hash(GENESIS, event) == compute_hash(GENESIS, reordered)


def test_changing_one_field_breaks_the_chain_at_that_point():
    chain = Chain()
    first = chain.append(_event(payload={"amount": 49999}))
    second = chain.append(_event())
    tampered = _event(event_id=first.event.event_id, timestamp=first.event.timestamp,
                      payload={"amount": 499900})
    assert compute_hash(first.prev_hash, tampered) != first.hash
    # The link into the second record now points at a hash that no longer describes record one.
    assert second.prev_hash == first.hash != compute_hash(first.prev_hash, tampered)


def test_stored_event_round_trips_through_json():
    stored = Chain().append(_event())
    rebuilt = from_dict(stored.to_dict())
    assert rebuilt.to_dict() == stored.event.to_dict()
    assert compute_hash(stored.prev_hash, rebuilt) == stored.hash


# --- 7.5 masking ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("pan, valid", [
    ("4111111111111111", True), ("5555555555554444", True), ("4012888888881881", True),
    ("4111111111111112", False), ("1234567890123456", False)])
def test_luhn(pan, valid):
    assert luhn_ok(pan) is valid


def test_mask_pan_keeps_last_four():
    assert mask_pan("4111111111111111") == "************1111"


def test_pan_is_masked_inside_free_text():
    clean = sanitize({"note": "customer paid with 4111111111111111 today"})
    assert "4111111111111111" not in clean["note"]
    assert clean["note"].endswith("************1111 today")


def test_secret_keys_are_removed_whatever_they_hold():
    clean = sanitize({"cvv": "123", "pin_block": "0" * 32, "encrypted_card_data": "base64...", "amount": 100})
    assert clean == {"cvv": REMOVED, "pin_block": REMOVED, "encrypted_card_data": REMOVED, "amount": 100}


def test_nested_structures_and_non_pan_numbers_are_untouched():
    payload = {"items": [{"desc": "chai", "qty": 2}], "amount": 49999, "reference": "order-4111"}
    assert sanitize(payload) == payload


def test_non_luhn_digit_runs_survive():
    assert sanitize({"invoice": "1234567890123"}) == {"invoice": "1234567890123"}


def test_sanitize_does_not_mutate_its_input():
    payload = {"pan": "4111111111111111"}
    sanitize(payload)
    assert payload["pan"] == "4111111111111111"
