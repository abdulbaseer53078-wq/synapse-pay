"""Composition root: the only place concrete adapters are chosen.

Run: uvicorn app.main:create_app --factory   (env: see app/config.py)
"""
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from psycopg_pool import ConnectionPool

from app.api import audit, capabilities, errors, gateway, payment_intents, terminals, transactions, upi_webhooks
from app.application.audit import AuditQueryService
from app.application.authorization import AuthorizationService
from app.application.methods import MethodRegistry
from app.application.queries import TerminalQueryService
from app.application.registration import RegistrationService
from app.application.payment_intents import CheckoutCardProcessor, PaymentIntentService
from app.application.transactions import TransactionService
from app.application.upi_webhooks import UpiWebhookHandler
from app.config import Settings
from app.infrastructure.config_certification import ConfigCertificationRegistry
from app.infrastructure.file_ca import FileCertificateAuthority
from app.infrastructure.methods.card import CardMethodAdapter
from app.infrastructure.methods.qr import QrMethodAdapter
from app.infrastructure.methods.upi import UpiMethodAdapter
from app.infrastructure.methods.wallet import HttpWallet, WalletMethodAdapter
from app.infrastructure.upi_client import HttpUpiPsp
from app.infrastructure.card_service_client import HttpCardProcessor
from app.infrastructure.postgres_api_keys import PostgresApiKeys
from app.infrastructure.postgres_audit import PostgresAuditStore
from app.infrastructure.postgres_intents import PostgresIntentRepository
from app.infrastructure.postgres_terminals import PostgresTerminalRepository
from app.infrastructure.postgres_transactions import PostgresTransactionRepository
from app.infrastructure.postgres_webhooks import PostgresWebhookEvents
from app.infrastructure.webhook_outbox import WebhookDispatcher


def create_app(settings: Settings | None = None, cards: CheckoutCardProcessor | None = None) -> FastAPI:
    """`cards` replaces the card service client (tests)."""
    settings = settings or Settings.from_env()
    pool = ConnectionPool(settings.database_url, open=False)

    webhooks = WebhookDispatcher(pool, settings.allow_insecure_webhooks)
    stop = threading.Event()

    def deliver_webhooks():
        while not stop.wait(settings.webhook_interval):
            try:
                webhooks.deliver_due()
            except Exception as e:  # keep delivering; one bad run mustn't stop webhooks for good
                print(f"webhook delivery run failed: {type(e).__name__}")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        pool.open()
        worker = None
        if settings.webhook_interval > 0:
            worker = threading.Thread(target=deliver_webhooks, name="webhooks", daemon=True)
            worker.start()
        yield
        stop.set()
        if worker:
            worker.join(timeout=5)
        pool.close()

    app = FastAPI(title="Synapse Pay", lifespan=lifespan)
    # Customer pages on any merchant's site read their intent's status with its client_secret. No cookies are
    # used, so allowing every origin exposes nothing a request couldn't already carry.
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"],
                       allow_headers=["content-type", "authorization"])
    app.state.jwt_public_key = settings.jwt_public_key
    repo = PostgresTerminalRepository(pool)
    certification = ConfigCertificationRegistry(settings.certified_firmware)
    app.state.registration = RegistrationService(
        repo,
        FileCertificateAuthority(settings.ca_cert_path, settings.ca_key_path, settings.ca_crl_path),
        settings.approved_models,
        certification,
    )
    app.state.authorization = AuthorizationService(repo, certification)
    cards = cards or HttpCardProcessor(settings.card_service_url)
    # Step 8: the one place a rail is chosen. Adding UPI was one line here and a module beside card.py.
    upi = UpiMethodAdapter(HttpUpiPsp(settings.upi_psp_url), webhook_secret=settings.upi_webhook_secret or None)
    # QR is a router: it dispatches to the rails above, so it is registered alongside them rather than instead.
    rails = MethodRegistry([CardMethodAdapter(cards), upi, WalletMethodAdapter(HttpWallet(settings.wallet_url))])
    methods = MethodRegistry([*rails.adapters(), QrMethodAdapter(rails)])
    app.state.methods = methods
    transaction_repo = PostgresTransactionRepository(pool)
    app.state.transactions = TransactionService(transaction_repo, app.state.authorization, methods)
    # Step 10B: the public callback. Same repository the engine uses, so the state change and its audit row
    # are written by the same code path.
    app.state.upi_webhooks = UpiWebhookHandler(upi, transaction_repo, PostgresWebhookEvents(pool))
    app.state.intents = PaymentIntentService(PostgresIntentRepository(pool), cards)
    app.state.api_keys = PostgresApiKeys(pool)
    app.state.webhooks = webhooks
    app.state.allow_insecure_webhooks = settings.allow_insecure_webhooks
    app.state.queries = TerminalQueryService(repo)
    # Read-only: the chain is built by the audit-ingest job, never by a request.
    app.state.audit = AuditQueryService(PostgresAuditStore(pool))
    errors.install(app)
    app.include_router(terminals.router)
    app.include_router(transactions.router)
    app.include_router(capabilities.router)
    app.include_router(payment_intents.router)
    app.include_router(audit.router)
    app.include_router(upi_webhooks.router)
    app.include_router(gateway.router)
    return app
