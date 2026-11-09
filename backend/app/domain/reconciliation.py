"""Settlement reconciliation rules (PR 7). Pure: parsing a settlement file and judging each line against the ledger.

The file format (CSV, one header row) is the one the mock acquirer and PSP produce; a real acquirer's clearing file
gets its own parser that yields the same SettlementLine:

    record_type,reference,gross_amount,fee_amount,net_amount,currency,settlement_date
    SALE,RRN000123456,100000,1500,98500,INR,2026-11-08

Amounts are integer minor units. `reference` is the network's id: the RRN (DE 37) for cards, the PSP's transaction id
for UPI, which is what `transactions.method_reference` holds.
"""
import csv
import io
from dataclasses import dataclass
from datetime import date

from app.domain.ledger import PAYMENT_CLEARING, Posting, balanced

SETTLEMENT_BANK = "1100"  # ASSET: the money that actually reached our bank account
INTERCHANGE_EXPENSE = "5000"  # EXPENSE: what the acquirer or scheme kept

HEADER = ["record_type", "reference", "gross_amount", "fee_amount", "net_amount", "currency", "settlement_date"]
SUPPORTED_RECORDS = frozenset({"SALE"})  # shortcut: refund and chargeback lines are reported, not posted, until rules exist


class SettlementFileInvalid(Exception):
    """The file can't be trusted line by line: nothing from it is applied."""


@dataclass(frozen=True)
class SettlementLine:
    line: int
    record_type: str
    reference: str
    gross: int
    fee: int
    net: int
    currency: str
    settlement_date: date


def parse(text: str) -> list[SettlementLine]:
    """Every line, or SettlementFileInvalid for the first bad one. All or nothing: half a file is worse than none."""
    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        raise SettlementFileInvalid("empty file") from None
    if [h.strip() for h in header] != HEADER:
        raise SettlementFileInvalid(f"header must be {','.join(HEADER)}")
    lines = []
    for number, row in enumerate(reader, start=2):
        if not any(cell.strip() for cell in row):
            continue
        if len(row) != len(HEADER):
            raise SettlementFileInvalid(f"line {number}: expected {len(HEADER)} fields, got {len(row)}")
        record_type, reference, gross, fee, net, currency, when = (cell.strip() for cell in row)
        try:
            gross_i, fee_i, net_i = int(gross), int(fee), int(net)
            settled = date.fromisoformat(when)
        except ValueError:
            raise SettlementFileInvalid(f"line {number}: amounts must be integers, the date YYYY-MM-DD") from None
        if not reference or len(reference) > 64:
            raise SettlementFileInvalid(f"line {number}: reference is missing or too long")
        if gross_i <= 0 or fee_i < 0 or fee_i > gross_i or net_i != gross_i - fee_i:
            raise SettlementFileInvalid(f"line {number}: need gross > 0, 0 <= fee <= gross and net = gross - fee")
        if len(currency) != 3 or not currency.isalpha():
            raise SettlementFileInvalid(f"line {number}: currency must be a 3-letter code")
        lines.append(SettlementLine(number, record_type.upper(), reference, gross_i, fee_i, net_i, currency.upper(),
                                    settled))
    return lines


def classify(line: SettlementLine, expected_amount: int | None, already_settled: bool) -> str:
    """The outcome for one line, given what the ledger expects for its reference (None: no such payment)."""
    if line.record_type not in SUPPORTED_RECORDS:
        return "UNSUPPORTED_ROW"
    if expected_amount is None:
        return "MISSING_IN_LEDGER"
    if already_settled:
        return "DUPLICATE_IN_SETTLEMENT"
    if line.gross != expected_amount:
        return "AMOUNT_MISMATCH"
    return "FEE_ADJUSTED" if line.fee else "MATCHED"


def settlement_postings(gross: int, fee: int) -> list[Posting]:
    """The acquirer paid `gross - fee` into the bank and kept `fee`: clearing is emptied by the full `gross`."""
    postings = []
    if gross - fee:
        postings.append(Posting(SETTLEMENT_BANK, debit=gross - fee))
    if fee:
        postings.append(Posting(INTERCHANGE_EXPENSE, debit=fee))
    postings.append(Posting(PAYMENT_CLEARING, credit=gross))
    return balanced(postings)
