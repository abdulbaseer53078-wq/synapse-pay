"""What Synapse charges per sale (PR 1). An interface, so per-merchant pricing can replace the config rates later
without touching the ledger or the transaction engine."""
from typing import Protocol
from uuid import UUID

from app.domain.ledger import fee_for


class FeePolicy(Protocol):
    def fee(self, merchant_id: UUID, payment_method: str, amount: int) -> int:
        """The fee in minor units, between 0 and `amount`."""


class ConfigFeePolicy:
    """Basis points per payment method from config (FEE_BPS), 0 when unset.

    The default is 0 everywhere on purpose: no price is invented, and in India MDR on UPI and RuPay debit cards is
    mandated at zero. shortcut: one rate per method for every merchant; add per-merchant pricing when the first
    merchant contract needs it.
    """

    def __init__(self, basis_points: dict[str, int]):
        for bps in basis_points.values():
            fee_for(0, bps)  # validates the range at startup, not on the first payment
        self.basis_points = basis_points

    def fee(self, merchant_id: UUID, payment_method: str, amount: int) -> int:
        return fee_for(amount, self.basis_points.get(payment_method, 0))
