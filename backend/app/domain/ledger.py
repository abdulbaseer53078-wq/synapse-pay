"""Double-entry rules (PR 1): which accounts a money movement debits and credits. Pure: no database here.

Amounts are integer minor units. Every entry must balance; `balanced()` refuses one that doesn't, and the database
refuses it again at commit (migration 016), so a bug here can't write money that isn't accounted for.
"""
from dataclasses import dataclass

PAYMENT_CLEARING = "1000"  # ASSET: what the acquirer or PSP owes us for captured payments
MERCHANT_PAYABLE = "2000"  # LIABILITY: what we owe the merchant
FEE_REVENUE = "4000"  # REVENUE: our fee

# Statuses where money has really moved. AUTHORIZED is a hold, not money, so it posts nothing.
SALE_STATUSES = frozenset({"CAPTURED", "SETTLED"})


class LedgerImbalance(Exception):
    """An entry whose debits and credits differ. Never recoverable by retrying: it's a bug."""


@dataclass(frozen=True)
class Posting:
    account: str
    debit: int = 0
    credit: int = 0


def balanced(postings: list[Posting]) -> list[Posting]:
    """`postings` unchanged if they form a valid entry; LedgerImbalance otherwise."""
    for p in postings:
        if p.debit < 0 or p.credit < 0 or (p.debit > 0) == (p.credit > 0):
            raise LedgerImbalance(f"posting to {p.account} must be a positive debit or a positive credit")
    debits, credits = sum(p.debit for p in postings), sum(p.credit for p in postings)
    if len(postings) < 2 or debits != credits:
        raise LedgerImbalance(f"debits {debits} != credits {credits} ({len(postings)} postings)")
    return postings


def sale_postings(total: int, fee: int) -> list[Posting]:
    """A captured sale: we're owed `total`; the merchant is owed `total - fee`; we earn `fee`."""
    if total <= 0:
        raise ValueError("a sale's amount must be positive")
    if not 0 <= fee <= total:
        raise ValueError("the fee must be between zero and the sale amount")
    postings = [Posting(PAYMENT_CLEARING, debit=total)]
    if total - fee:  # a zero posting isn't a posting
        postings.append(Posting(MERCHANT_PAYABLE, credit=total - fee))
    if fee:
        postings.append(Posting(FEE_REVENUE, credit=fee))
    return balanced(postings)


def fee_for(amount: int, basis_points: int) -> int:
    """`amount * basis_points / 10000`, rounded down: the merchant never pays a fraction of a paisa extra."""
    if not 0 <= basis_points <= 10_000:
        raise ValueError("basis points must be between 0 and 10000")
    return amount * basis_points // 10_000


def refund_postings(refund: int, total: int, sale_fee: int, fee_already_reversed: int, refunded_before: int) -> list[Posting]:
    """Money flowing back: the merchant's share and our fee leave, and clearing pays the customer.

    Each partial refund reverses its share of the sale's fee, rounded down; the refund that completes the payment
    reverses whatever fee is left, so a fully refunded payment always nets to zero in every account. That remainder
    can exceed the final refund itself (₹33.33 three times then 1 paisa, on a ₹2 fee: 2 paise of fee are left for a
    1 paisa refund); the difference goes back to the merchant, as a credit to its payable.
    """
    if refund <= 0 or refunded_before < 0 or refunded_before + refund > total:
        raise ValueError("a refund must be positive and no more than what is left of the payment")
    if not 0 <= fee_already_reversed <= sale_fee <= total:
        raise ValueError("inconsistent fee history")
    remaining_fee = sale_fee - fee_already_reversed
    fee_back = remaining_fee if refunded_before + refund == total else min(refund * sale_fee // total, remaining_fee)
    postings = []
    if refund > fee_back:
        postings.append(Posting(MERCHANT_PAYABLE, debit=refund - fee_back))
    if fee_back:
        postings.append(Posting(FEE_REVENUE, debit=fee_back))
    postings.append(Posting(PAYMENT_CLEARING, credit=refund))
    if fee_back > refund:  # only on the final refund: the fee left over is the merchant's again
        postings.append(Posting(MERCHANT_PAYABLE, credit=fee_back - refund))
    return balanced(postings)
