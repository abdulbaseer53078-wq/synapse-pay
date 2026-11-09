"""Chargeback accounting (PR 8). Pure rules; see migration 019 for the full picture.

The acquirer takes the money when a chargeback opens, so that's when it leaves the ledger: from the bank if the payment
had settled, from clearing if it hadn't. Winning brings it back to the same account; losing posts nothing more.
"""
from app.domain.ledger import MERCHANT_PAYABLE, PAYMENT_CLEARING, Posting, balanced
from app.domain.reconciliation import SETTLEMENT_BANK

OPEN_STATUSES = frozenset({"PENDING", "UNDER_REVIEW"})


def cash_account(settled: bool) -> str:
    return SETTLEMENT_BANK if settled else PAYMENT_CLEARING


def opened_postings(amount: int, account: str) -> list[Posting]:
    """The merchant is no longer owed it, and the money has left `account`."""
    return balanced([Posting(MERCHANT_PAYABLE, debit=amount), Posting(account, credit=amount)])


def resolution_postings(amount: int, outcome: str, account: str) -> list[Posting]:
    """WON: the acquirer returns it to `account`, and the merchant is owed it again. LOST: nothing, it already left."""
    if outcome == "WON":
        return balanced([Posting(account, debit=amount), Posting(MERCHANT_PAYABLE, credit=amount)])
    if outcome == "LOST":
        return []
    raise ValueError("a chargeback is WON or LOST")
