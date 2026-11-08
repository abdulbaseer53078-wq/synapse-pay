"""The transition rules every status writer obeys (PR 2)."""
import pytest

from app.domain.state_machine import VALID_TRANSITIONS, transition

FINAL = ("FAILED", "VOIDED", "REFUNDED")


@pytest.mark.parametrize("current, new", [
    ("INITIATED", "PENDING"), ("INITIATED", "FAILED"),          # sent / refused before sending
    ("PENDING", "CAPTURED"), ("PENDING", "AUTHORIZED"),         # card
    ("PENDING", "SETTLED"), ("PENDING", "FAILED"),              # UPI / QR, declines
    ("PENDING", "PENDING"),                                     # unknown outcome, async collect
    ("AUTHORIZED", "CAPTURED"), ("AUTHORIZED", "VOIDED"),
    ("CAPTURED", "SETTLED"), ("SETTLED", "PARTIALLY_REFUNDED"), ("PARTIALLY_REFUNDED", "REFUNDED"),
])
def test_the_lifecycle_the_code_uses_is_legal(current, new):
    assert transition(current, new) == "apply"


@pytest.mark.parametrize("current, new", [
    ("SETTLED", "FAILED"),      # the late FAILED webhook
    ("CAPTURED", "FAILED"), ("CAPTURED", "PENDING"), ("FAILED", "CAPTURED"), ("REFUNDED", "SETTLED"),
    ("INITIATED", "CAPTURED"),  # nothing finishes without being sent
    ("VOIDED", "CAPTURED"),
])
def test_overwriting_an_answer_is_rejected(current, new):
    assert transition(current, new) == "reject"


@pytest.mark.parametrize("status", ["SETTLED", "CAPTURED", *FINAL])
def test_the_same_answer_again_is_a_noop(status):
    assert transition(status, status) == "noop"


def test_final_states_go_nowhere_and_every_status_is_known():
    assert all(not VALID_TRANSITIONS[s] for s in FINAL)
    statuses = {"INITIATED", "PENDING", "AUTHORIZED", "CAPTURED", "SETTLED", "VOIDED", "FAILED", "REFUNDED",
                "PARTIALLY_REFUNDED"}  # the CHECK constraint in migration 007
    assert set(VALID_TRANSITIONS) == statuses
    assert all(targets <= statuses for targets in VALID_TRANSITIONS.values())
