"""Composition root: the only place concrete adapters are chosen.

Run: uvicorn app.main:create_app --factory   (env: see app/config.py)
"""
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from prometheus_client import start_http_server
from fastapi.middleware.cors import CORSMiddleware
from psycopg_pool import ConnectionPool

from app.api import certification_runs as certification_runs_api
from app.api import card_tokens as card_tokens_api
from app.api import certifications as certifications_api
from app.api import (audit, capabilities, edge, errors, gateway, merchants, payment_intents, region, terminals,
                     transactions, upi_webhooks)
from app.application import observability
from app.application.audit import AuditQueryService
from app.application.card_tokens import CardTokenService
from app.application.certification import CertificationAdmin, CertificationMatrix
from app.application.authorization import AuthorizationService
from app.application.edge import EdgeService
from app.application.hosts import CachedHealth, HealthRegistry
from app.application.methods import MethodRegistry
from app.application.queries import TerminalQueryService
from app.application.region_health import RegionHealth
from app.application.registration import RegistrationService
from app.application.payment_intents import CheckoutCardProcessor, PaymentIntentService
from app.application.routing import InMemoryRules, RoutingEngine, RoutingRule
from app.application.transaction_sync import OfflineSyncService
from app.application.transactions import TransactionService
from app.application.upi_webhooks import WebhookHandler
from app.config import Settings
from app.infrastructure.aws_private_ca import AwsPrivateCertificateAuthority
from app.infrastructure.file_ca import FileCertificateAuthority
from app.infrastructure.methods.card import CardMethodAdapter
from app.infrastructure.methods.offline import OfflineMethodAdapter
from app.infrastructure.methods.qr import QrMethodAdapter
from app.infrastructure.methods.upi import UpiMethodAdapter
from app.infrastructure.methods.wallet import HttpWallet, WalletMethodAdapter
from app.infrastructure.upi_client import HttpUpiPsp
from app.infrastructure.card_service_client import HttpCardProcessor
from app.infrastructure.postgres_api_keys import PostgresApiKeys
from app.infrastructure.postgres_audit import PostgresAuditStore
from app.infrastructure.postgres_certification import PostgresCertifications, listen as listen_certifications
from app.infrastructure.postgres_certification_runs import PostgresCertificationRuns
from app.infrastructure.postgres_health import database_writable
from app.infrastructure.postgres_intents import PostgresIntentRepository
from app.infrastructure.postgres_recovery import PostgresRecoveryStats
from app.infrastructure.postgres_terminals import PostgresTerminalRepository
from app.infrastructure.postgres_edge import PostgresEdgeNodes
from app.infrastructure.rules_signer import EcdsaRulesSigner
from app.infrastructure.postgres_transactions import PostgresTransactionRepository
from app.infrastructure.postgres_webhooks import PostgresWebhookEvents
from app.infrastructure.webhook_outbox import WebhookDispatcher


def _card_health_source(settings):
    """Rust's view of its own sockets (Step 14.6). Until that endpoint exists, this 404s and every card host
    is reported DOWN — fail closed, which is the correct reading of "we cannot see the sockets"."""
    url = settings.card_service_url.rstrip("/") + "/internal/v1/hosts/health"

    def source():
        import httpx

        with httpx.Client(timeout=2.0) as client:
            return client.get(url).raise_for_status().json()

    return source


def create_app(settings: Settings | None = None, cards: CheckoutCardProcessor | None = None) -> FastAPI:
    """`cards` replaces the card service client (tests)."""
    settings = settings or Settings.from_env()
    pool = ConnectionPool(settings.database_url, open=False)

    webhooks = WebhookDispatcher(pool, settings.allow_insecure_webhooks)
    health = CachedHealth(HealthRegistry([], card_source=_card_health_source(settings),
                                         card_host_ids=settings.card_hosts))
    stop = threading.Event()

    def poll_health():
        while not stop.wait(settings.health_poll_seconds):
            try:
                observability.publish_health(health.refresh())
            except Exception as exc:  # a failed poll leaves the previous snapshot; nothing is invented
                print(f"host health poll failed: {type(exc).__name__}")

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
        # One poll before serving traffic. The router reads the cache and nothing else, so an empty cache would
        # fail every payment for the first `health_poll_seconds`; a single refresh closes that cold-start window.
        if settings.metrics_port:
            start_http_server(settings.metrics_port)
        try:
            observability.publish_health(health.refresh())
        except Exception as exc:  # fail closed: the snapshot stays empty, and routing says so
            print(f"host health poll failed: {type(exc).__name__}")
        # The router reads health.snapshot(); the poller is the only thing that talks to card-service.
        health_worker = threading.Thread(target=poll_health, name="host-health", daemon=True)
        health_worker.start()
        # Step 26: load the matrix before serving, then keep it current. Until it loads, nothing is certified.
        try:
            certification.reload()
        except Exception as exc:
            print(f"certification matrix load failed: {type(exc).__name__}; every firmware is uncertified")
        threading.Thread(target=listen_certifications, args=(settings.database_url, certification.reload, stop),
                         name="certifications", daemon=True).start()
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
    certifications = PostgresCertifications(pool)
    certification = CertificationMatrix(certifications)
    if settings.ca_backend == "aws_pca":
        ca = AwsPrivateCertificateAuthority(settings.aws_pca_arn, signing_algorithm=settings.aws_pca_signing_algorithm)
    else:
        ca = FileCertificateAuthority(settings.ca_cert_path, settings.ca_key_path, settings.ca_crl_path)
    app.state.registration = RegistrationService(repo, ca, settings.approved_models, certification)
    app.state.authorization = AuthorizationService(repo, certification)
    app.state.certifications = CertificationAdmin(certifications, PostgresCertificationRuns(pool))
    cards = cards or HttpCardProcessor(settings.card_service_url)
    # Step 8: the one place a rail is chosen. Adding UPI was one line here and a module beside card.py.
    upi = UpiMethodAdapter(HttpUpiPsp(settings.upi_psp_url), webhook_secret=settings.upi_webhook_secret or None)
    wallet = WalletMethodAdapter(HttpWallet(settings.wallet_url),
                                 webhook_secret=settings.wallet_webhook_secret or None)
    # QR is a router: it dispatches to the rails above, so it is registered alongside them rather than instead.
    rails = MethodRegistry([CardMethodAdapter(cards), upi, wallet, OfflineMethodAdapter()])
    methods = MethodRegistry([*rails.adapters(), QrMethodAdapter(rails)])
    app.state.methods = methods
    app.state.health = health
    transaction_repo = PostgresTransactionRepository(pool)
    # Step 15: routing is active only when an operator configured a preference. No rules means the single-attempt
    # path, not "no healthy host": an unconfigured service keeps behaving exactly as it did before.
    routing = None
    if settings.routing_rules:
        rules = [RoutingRule(method, tuple(hosts)) for method, hosts in settings.routing_rules.items()]
        routing = RoutingEngine(InMemoryRules({"*": rules}), health)
    app.state.transactions = TransactionService(transaction_repo, app.state.authorization, methods,
                                                routing=routing)
    # Step 13: offline batch upload. Same engine, same rails; the signature and the age/limit checks are the
    # only things that differ from an online payment.
    app.state.offline_sync = OfflineSyncService(methods, repo, app.state.transactions, ca.verify_signature,
                                                edges=PostgresEdgeNodes(pool))
    # Step 10B: the public callback. Same repository the engine uses, so the state change and its audit row
    # are written by the same code path.
    app.state.upi_webhooks = WebhookHandler(upi, transaction_repo, PostgresWebhookEvents(pool), provider="upi")
    app.state.wallet_webhooks = WebhookHandler(wallet, transaction_repo, PostgresWebhookEvents(pool),
                                               provider="wallet")
    app.state.intents = PaymentIntentService(PostgresIntentRepository(pool), cards)
    app.state.card_tokens = CardTokenService(cards)  # Step 29: the vault is card-service's; this only relays
    app.state.api_keys = PostgresApiKeys(pool)
    app.state.recovery = PostgresRecoveryStats(pool)
    app.state.webhooks = webhooks
    app.state.allow_insecure_webhooks = settings.allow_insecure_webhooks
    app.state.queries = TerminalQueryService(repo)
    # Read-only: the chain is built by the audit-ingest job, never by a request.
    app.state.audit = AuditQueryService(PostgresAuditStore(pool))
    # Step 17: what Route 53 probes. Up only if this region can take a payment: writable DB, a usable acquirer.
    app.state.region_health = RegionHealth(database_writable(pool), health.snapshot)
    app.state.edge = EdgeService(PostgresEdgeNodes(pool), ca,
                                 EcdsaRulesSigner(settings.edge_rules_signing_key) if settings.edge_rules_signing_key else None,
                                 settings.routing_rules)
    errors.install(app)
    app.include_router(terminals.router)
    app.include_router(transactions.router)
    app.include_router(capabilities.router)
    app.include_router(payment_intents.router)
    app.include_router(audit.router)
    app.include_router(upi_webhooks.router)
    app.include_router(gateway.router)
    app.include_router(region.router)
    app.include_router(merchants.router)
    app.include_router(certifications_api.router)
    app.include_router(card_tokens_api.router)
    app.include_router(certification_runs_api.router)
    app.include_router(edge.router)
    return app
