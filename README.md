<div align="center">

# ⚡ Synapse Pay

**A multi-acquirer payment orchestration engine with offline-first edge capabilities.**

[![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Envoy](https://img.shields.io/badge/Envoy-AC6199?style=for-the-badge&logo=envoyproxy&logoColor=white)](https://www.envoyproxy.io/)

[Architecture](#️-architecture) • [Core Features](#-core-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation)

</div>

---

## 📖 Overview

Synapse Pay is a reference architecture for a payment gateway. It bridges the gap between modern API orchestration and legacy banking protocols.

> **Status:** sandbox only. All acquirers, banks and the HSM are simulated.

Unlike traditional gateways that fail during network drops, Synapse Pay uses a **distributed edge-node architecture**. Terminals can process cryptographically signed transactions offline and reconcile with the cloud when connectivity is restored.

## 🏗️ Architecture

Synapse Pay is designed with a **zero-trust** perimeter and a strict separation of concerns.

```mermaid
graph TD
    Terminal[POS Terminal / Web SDK] -->|mTLS| Envoy[Envoy Gateway]
    Envoy -->|Strict Auth| Backend[FastAPI Backend]
    Backend -->|Idempotency Check| Postgres[(PostgreSQL)]
    Backend -->|Internal HTTP| CardService[Rust: Card Service]
    CardService -->|HSM / Key Derivation| HSM[Software HSM]
    CardService -->|ISO 8583 Formatting| HostConnector[Rust: Host Connector]
    HostConnector -->|TCP / TLS| Acquirer[Mock Acquirers / Banks]

    Terminal -.->|Offline Sync| EdgeNode[Edge Node: SQLite + Hash Chain]
    EdgeNode -.->|Deferred Sync| Backend
```

### 🦀 Why Multi-Language?
*   **Python (FastAPI):** Chosen for the orchestration layer, rapid API development, and complex routing logic. Handles idempotency, merchant state, and webhook fan-out.
*   **Rust (Card Service & Host Connector):** Chosen for the cryptographic core. Rust ensures memory safety while parsing untrusted binary data, deriving HSM keys (HKDF/AES-GCM), and encoding strict ISO 8583 messages.
*   **Envoy Proxy:** Terminates mTLS for terminals, enforcing certificate revocation and terminal identity pinning before requests ever touch the application layer.

## ✨ Core Features

*   **🔒 Zero-Trust mTLS Perimeter:** Terminals authenticate via mutual TLS. Envoy validates certificates against a registry and injects identity headers, dropping any spoofed copies from outside.
*   **⏱️ Idempotency:** A Postgres-backed locking mechanism (`idempotency_keys`) prevents double-charging on network retries. Handles in-flight requests, hard declines, and soft declines safely.
*   **📴 Offline-First Edge Nodes:** Terminals can process payments locally during ISP outages. Rules are cryptographically signed by the cloud. Local transactions are hash-chained to prevent tampering, then synced idempotently.
*   **🔄 Smart Reversals:** If an acquirer times out, the system does *not* blindly retry on another host (avoiding double charges). It queues a durable reversal to cancel the first request.
*   **📊 Observability:** Prometheus metrics, OpenTelemetry tracing, and a hash-chained audit log for compliance.

## 🚀 Quick Start

Run the sandbox locally: it applies the database migrations, builds the Rust card service and starts the API.

### Prerequisites
*   Docker & Docker Compose (for PostgreSQL), or a local PostgreSQL
*   Rust (`cargo`)
*   Python 3.12+

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/abdulbaseer53078-wq/synapse-pay.git
cd synapse-pay

# 2. Start PostgreSQL
docker compose up -d db

# 3. Start the sandbox (applies migrations, builds the card service, prints test API keys)
cd backend
pip install -r requirements.txt
python -m app.sandbox
```

The API is now live at `http://localhost:8000`. Explore the interactive Swagger UI at `http://localhost:8000/docs`, or [take a test payment in 5 minutes](docs/quickstart.md).

## 🧪 Testing

The codebase includes property-based tests for the ISO 8583 parser and an API contract test suite.

```bash
# Python backend tests
pytest backend/tests

# Rust tests (Card Service & ISO parser)
cargo test --manifest-path card-service/Cargo.toml
cargo test --manifest-path iso8583/Cargo.toml

# Edge node tests (offline engine, signed rules, sync)
pytest edge-node/tests

# API contract tests
./spec/contract-test.sh
```

## 📚 Documentation

Deep-dive into the architecture and design decisions:
*   [API Contract & Idempotency](docs/understanding/01-api-contract.md)
*   [Backend Transaction Flow](docs/understanding/02-backend-transaction-flow.md)
*   [Rust Card Service & HSM](docs/understanding/03-rust-card-service.md)
*   [Host Connector](docs/understanding/04-host-connector.md)
*   [Gateway & mTLS Security](docs/understanding/05-gateway-security.md)
*   [Offline Edge Architecture](docs/understanding/06-edge-node.md)

## 🛡️ Security Posture

Synapse Pay is designed with PCI-DSS in mind (not certified).
*   **No raw PANs** are stored in the primary database (tokenization required).
*   **The public test BDK** (Base Derivation Key) is refused at startup outside the sandbox.
*   **Envoy** drops any external traffic attempting to forge internal identity headers (`x-terminal-id`).
