"""Composition root: the only place concrete adapters are chosen.

Run: uvicorn app.main:create_app --factory   (env: see app/config.py)
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from psycopg_pool import ConnectionPool

from app.api import errors, gateway, terminals, transactions
from app.application.authorization import AuthorizationService
from app.application.queries import TerminalQueryService
from app.application.registration import RegistrationService
from app.application.transactions import CardProcessor, TransactionService
from app.config import Settings
from app.infrastructure.config_certification import ConfigCertificationRegistry
from app.infrastructure.file_ca import FileCertificateAuthority
from app.infrastructure.card_service_client import HttpCardProcessor
from app.infrastructure.postgres_terminals import PostgresTerminalRepository
from app.infrastructure.postgres_transactions import PostgresTransactionRepository


def create_app(settings: Settings | None = None, cards: CardProcessor | None = None) -> FastAPI:
    """`cards` replaces the card service client (tests)."""
    settings = settings or Settings.from_env()
    pool = ConnectionPool(settings.database_url, open=False)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        pool.open()
        yield
        pool.close()

    app = FastAPI(title="Synapse Pay", lifespan=lifespan)
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
    app.state.transactions = TransactionService(PostgresTransactionRepository(pool), app.state.authorization,
                                                cards or HttpCardProcessor(settings.card_service_url))
    app.state.queries = TerminalQueryService(repo)
    errors.install(app)
    app.include_router(terminals.router)
    app.include_router(transactions.router)
    app.include_router(gateway.router)
    return app
