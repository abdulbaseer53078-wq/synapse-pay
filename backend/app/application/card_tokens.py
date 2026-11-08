"""Saved cards (Step 29). The vault is card-service's: this layer only asks it to save or forget a card for the
calling merchant, and never sees the number, its ciphertext or its fingerprint."""
from typing import Protocol
from uuid import UUID

from app.application.registration import NotFound


class CardVault(Protocol):
    def tokenize(self, merchant_id: UUID, encrypted_card_data: str, card_expiry: str, card_network: str,
                 customer_ref: str | None) -> dict: ...

    def revoke_token(self, merchant_id: UUID, token: str) -> bool: ...


class CardTokenService:
    def __init__(self, vault: CardVault):
        self.vault = vault

    def save(self, merchant_id: UUID, encrypted_card_data: str, card_expiry: str, card_network: str,
             customer_ref: str | None) -> dict:
        saved = self.vault.tokenize(merchant_id, encrypted_card_data, card_expiry, card_network, customer_ref)
        return {k: saved[k] for k in ("token", "token_type", "card_bin", "card_last4", "card_network", "card_expiry")
                } | ({"customer_ref": saved["customer_ref"]} if saved.get("customer_ref") else {})

    def delete(self, merchant_id: UUID, token: str) -> None:
        if not self.vault.revoke_token(merchant_id, token):
            raise NotFound("card token not found", code="CARD_TOKEN_NOT_FOUND")
