# 05 — Gateway and network perimeter

Scope:
- `gateway/` (Envoy) and `infra/` (Terraform for ECS)
- `docker-compose.yml`
- the backend lines that decide whether gateway-set headers are trusted, needed to judge the bypass

Every reference is `file:line`, relative to the repo root.

---

## 1. What runs where (production, ECS Fargate)

Every API task runs three containers that **share one network namespace** (`awsvpc`) (`infra/ecs/modules/region/main.tf:3-6`, `:317-358`):

| Container | Listens on | Fronted by | Ref |
| :--- | :--- | :--- | :--- |
| `api` (FastAPI) | `8000` | **public ALB**, HTTPS 443 | `infra/ecs/modules/region/main.tf:328-331`, `:251-281`, `:377-381` |
| `gateway` (Envoy) | `8443` (terminals), `8444` (PSP, not mapped) | **public NLB**, TCP 8443 passthrough | `infra/ecs/modules/region/main.tf:349-352`, `:283-305`, `:383-387` |
| `card-service` (Rust) | `127.0.0.1:7070` (loopback) | nothing | `infra/ecs/modules/region/main.tf:336-347`, `:124`; `card-service/src/main.rs:219` |

Tasks sit in private subnets with no public IP (`infra/ecs/modules/region/main.tf:371-375`). The task security group allows (`infra/ecs/modules/region/main.tf:226-249`):
- **8000 from the ALB's security group only** (`:229-235`)
- **8443 from 0.0.0.0/0**, via the NLB, which keeps client IPs (`:236-242`)
- nothing else inbound

Local development (`docker-compose.yml:1-58`) runs only Postgres, Kafka and observability. Envoy and card-service aren't in it. The Envoy config's backend address `host.docker.internal:8000` (`gateway/envoy.yaml:108`) is rewritten to `127.0.0.1` in the image (`gateway/Dockerfile:9`).

---

## 2. mTLS on the terminal listener

The `terminals_mtls` listener on `0.0.0.0:8443` (`gateway/envoy.yaml:12-13`):

| Control | Setting | Ref |
| :--- | :--- | :--- |
| Client cert required | `require_client_certificate: true`. This is **strict**: a connection without a cert fails the TLS handshake, and no HTTP request is made | `gateway/envoy.yaml:19`, `:2-3` |
| Chain validation | `trusted_ca: /etc/synapse/ca.pem`, rewritten to `/run/app-secrets/GATEWAY_CA` in the image | `gateway/envoy.yaml:24-25`, `gateway/Dockerfile:10` |
| Revocation | `crl: /etc/synapse/crl.pem` → `/run/app-secrets/GATEWAY_CRL`; `only_verify_leaf_cert_crl: true` | `gateway/envoy.yaml:26-27`, `gateway/Dockerfile:11` |
| CRL source | fetched from `GATEWAY_CRL_URL` (AWS Private CA, DER → PEM) at container start; **the container refuses to start without a CRL** | `gateway/entrypoint.sh:6-13`, `infra/ecs/modules/region/main.tf:353` |
| Server cert / key | `/run/app-secrets/GATEWAY_SERVER_CERT` / `GATEWAY_SERVER_KEY`, from Secrets Manager | `gateway/envoy.yaml:21-23`, `gateway/Dockerfile:12-13`, `infra/ecs/modules/region/main.tf:354` |
| Identity forwarding | `forward_client_cert_details: SANITIZE_SET` + `uri: true`: any client-supplied `x-forwarded-client-cert` is dropped and replaced from the verified cert | `gateway/envoy.yaml:33-35` |
| Registry check | `ext_authz` → `POST /internal/gateway/authz` on the backend, 0.5 s timeout, **`failure_mode_allow: false`** (backend down → deny). It sends only XFCC and returns only `x-terminal-id` / `x-edge-node-id` upstream | `gateway/envoy.yaml:53-65` |
| What authz checks | reads the terminal UUID from the URI SAN, requires the path's `terminal_id` to match, requires status `ACTIVE` | `backend/app/api/gateway.py:34-55`, `backend/app/application/authorization.py:63-69` |
| Exception | heartbeats skip ext_authz (a valid cert is still required), so SUSPENDED terminals keep reporting | `gateway/envoy.yaml:6`, `:41-46` |

**Verdict:** mTLS on 8443 is strict, not permissive. A client certificate is validated against the platform CA and the CRL before any byte reaches the backend.

Weaknesses in the mTLS setup:
- **The CRL is loaded once, at startup.** A terminal revoked after the task started keeps passing the TLS handshake until the task is recycled (`gateway/envoy.yaml:8-9`, `gateway/entrypoint.sh:4-5`; both marked `shortcut:`). The `ACTIVE` check in ext_authz still blocks a terminal whose **registry** status is REVOKED (`backend/app/application/authorization.py:68-69`), except on the heartbeat route, where ext_authz is off.
- **No SAN restriction in Envoy.** Any cert chained to the CA passes TLS. The `urn:synapsepay:terminal:` / edge SAN is parsed by the backend, not Envoy (`backend/app/api/gateway.py:37`, `:44-46`).
- **The heartbeat route forwards a client-supplied `x-terminal-id`.** With ext_authz disabled, nothing overwrites that header (`gateway/envoy.yaml:41-46`). The heartbeat handler doesn't read it; it authenticates by `X-Signature` (`backend/app/api/terminals.py:199`). So this is harmless today, but fragile.

---

## 3. Routing: what each entry point reaches

### 3.1 Through Envoy (NLB :8443)

| Route | Upstream | Ref |
| :--- | :--- | :--- |
| `/api/v1/terminals/<id>/heartbeat` (regex) | backend, no ext_authz | `gateway/envoy.yaml:41-46` |
| `/api/` | backend | `gateway/envoy.yaml:47-48` |
| `/internal/v1/edge/` | backend (authz admits only edge certs here) | `gateway/envoy.yaml:49-51`, `backend/app/api/gateway.py:38-43` |
| anything else | 404: "notably the rest of /internal/*" | `gateway/envoy.yaml:52` |

The only upstream cluster is `backend` (`gateway/envoy.yaml:100-108`). **Envoy has no route or cluster for card-service.**

The `psp_webhooks` listener (`gateway/envoy.yaml:75-99`) is server-TLS only and routes `/api/v1/webhooks/`. In ECS, port 8444 is never mapped or exposed (`infra/ecs/modules/region/main.tf:352`; `gateway/Dockerfile:19` exposes 8443 only), so **in production this listener is dead**. PSP webhooks arrive through the ALB instead, authenticated by HMAC in the backend.

### 3.2 Is card-service exposed? **No.**

- It binds to `127.0.0.1:7070` by default (`card-service/src/main.rs:219`). Infra doesn't override `CARD_SERVICE_ADDR` (it isn't in `infra/`; the card environment is only the `card_service_environment` variable, which defaults to empty: `infra/ecs/modules/region/main.tf:90-93`, `:340-344`).
- It has no `portMappings`, no load balancer, and no security-group rule (`infra/ecs/modules/region/main.tf:336-347`, `:226-249`).
- Only containers in the same task (the `api` container at `CARD_SERVICE_URL=http://127.0.0.1:7070`, `infra/ecs/modules/region/main.tf:124`) can reach it. That's the intended design (`infra/ecs/modules/region/main.tf:5`).

So **from the network, card-service can't be reached without going through the backend.** It doesn't go through Envoy either, but Envoy was never meant to front it. Its exposure is decided by whoever can make the backend call it, which is §4.

> **Residual risk:** card-service's whole network protection is its loopback bind. It has no authentication
> (`card-service/src/http.rs:1-4`). If an operator sets `CARD_SERVICE_ADDR=0.0.0.0:7070` through
> `card_service_environment`, it's reachable by anything in the task's network namespace. Nothing in
> Terraform forbids that override.

### 3.3 Through the ALB (HTTPS :443): **no Envoy at all**

The ALB listener forwards **every path** to `api:8000` with a single `default_action` and no listener rules (`infra/ecs/modules/region/main.tf:271-281`). The ALB doesn't strip custom request headers.

---

## 4. The Envoy bypass

> **CRITICAL NETWORK FLAW: the terminal identity header can be forged through the public ALB.**
>
> The backend trusts `x-terminal-id` / `x-edge-node-id` as "set by the gateway from the verified certificate".
> Its own comments state the condition:
> - "Trusting the header is safe only behind the gateway, which strips any client-supplied one" (`backend/app/api/auth.py:52-53`)
> - the same in `backend/app/api/edge.py:53-54` and `backend/app/application/transactions.py:3`
>
> But the public ALB sends requests to the same backend port **without passing through the gateway**
> (`infra/ecs/modules/region/main.tf:271-281`, `:377-381`). Nothing in the backend checks where a request came from:
> - the only middleware is latency metrics and CORS (`backend/app/main.py:159-171`)
> - there's no `TrustedHost`, source-IP or shared-secret check (searched `backend/app/`)
>
> So anyone on the internet can send `x-terminal-id: <uuid>` over HTTPS to the API hostname, and the backend will
> treat the request as mTLS-authenticated.

What that reaches:

| Endpoint (via ALB) | Effect of a forged header | Ref |
| :--- | :--- | :--- |
| `POST /api/v1/transactions` | Authenticated as that terminal. The attacker also needs the terminal's merchant UUID (`backend/app/application/transactions.py:199-200`) and valid encrypted card data. The checkout public key is published (`card-service/src/http.rs:144-150`), so **anyone holding a card number can encrypt it**. The ACTIVE / limits / firmware checks still run (`backend/app/domain/terminal.py:75-76`) | `backend/app/api/transactions.py:87-93` |
| `POST /api/v1/transactions/sync` | Authenticated as a terminal or **edge node**. Each item's signature is still verified, which limits the damage | `backend/app/api/transactions.py:46-57` |
| `GET /api/v1/capabilities/...` and anything else using `with_scope_or_terminal` | **Any** value for the header skips OAuth completely, not even a valid UUID: `if x_terminal_id is not None: return None` | `backend/app/api/auth.py:56-59` |
| Terminal checkout long poll | reads the next payment intent queued for that terminal | `backend/app/api/payment_intents.py:160` |
| `GET /internal/v1/edge/rules` | returns any edge node's rules for a forged `x-edge-node-id` | `backend/app/api/edge.py:51-59` |
| `POST /internal/gateway/authz/...` | Envoy says `/internal/*` is unreachable (`gateway/envoy.yaml:52`), but via the ALB it is reachable. A forged `x-forwarded-client-cert` turns it into an oracle: 200 for an ACTIVE terminal, 403 otherwise | `backend/app/api/gateway.py:16`, `:34-55` |

The impact is limited by the attacker needing real terminal and merchant UUIDs. How hard those are to obtain (receipts, SDK logs, support tickets) wasn't checked. That limit is weak, though; it makes a UUID a bearer secret.

Smallest fixes, any one of which closes it:
- add an ALB listener rule that drops these headers or 403s requests carrying them
- have Envoy add a shared secret header that the backend requires before trusting identity headers
- move the identity headers to a port only Envoy can reach

---

## 5. Rate limiting and DDoS protection: **none configured**

Searched `gateway/`, `infra/` and `backend/app/` for rate-limit, throttle, local_ratelimit, overload_manager, circuit_breakers, max_connections, WAF and Shield. Nothing matched except a comment about a PSP's 429 (`backend/app/infrastructure/upi_client.py:80`).

| Layer | What exists | What's missing | Ref |
| :--- | :--- | :--- | :--- |
| Envoy | `ext_authz` and `router` filters only | No `local_ratelimit` / `ratelimit` filter, no overload manager, no explicit connection or stream limits, no request or idle timeouts (Envoy defaults apply) | `gateway/envoy.yaml:53-68` |
| Envoy → backend | `connect_timeout: 1s` | No `circuit_breakers` block (Envoy's defaults apply) | `gateway/envoy.yaml:100-108` |
| ALB | TLS 1.2/1.3 policy | No WAF (`aws_wafv2_web_acl_association`), no rate-based rules | `infra/ecs/modules/region/main.tf:271-281` |
| NLB | TCP passthrough | No protection beyond AWS Shield Standard (automatic, not configured here) | `infra/ecs/modules/region/main.tf:283-305` |
| Backend | none | no per-merchant or per-IP limiter | `backend/app/main.py:159-171` |

Every terminal request also triggers a synchronous ext_authz database lookup (`gateway/envoy.yaml:59-61`, `backend/app/application/authorization.py:65`). Anyone with **one** valid terminal certificate can therefore hammer the backend's database through Envoy, with nothing to throttle them.

This also doesn't meet the project's own baseline: "Rate limiting on all public-facing endpoints" (`../CLAUDE.md`, Security Baseline).

---

## 6. Summary

| # | Finding | Severity | Ref |
| :--- | :--- | :--- | :--- |
| 1 | Public ALB reaches the backend without Envoy; forged `x-terminal-id` / `x-edge-node-id` / XFCC are trusted | **CRITICAL NETWORK FLAW** | `infra/ecs/modules/region/main.tf:271-281`; `backend/app/api/auth.py:52-59` |
| 2 | `/internal/*` reachable through the ALB, despite the Envoy comment saying it isn't | High (part of #1) | `gateway/envoy.yaml:52`; `backend/app/api/gateway.py:16`; `backend/app/api/edge.py:51` |
| 3 | No rate limiting, WAF, or connection limits at any layer | High | §5 |
| 4 | CRL read only at startup; revoked certs pass TLS until restart | Medium (registry check covers it except on heartbeats) | `gateway/envoy.yaml:8-9`, `gateway/entrypoint.sh:4-5` |
| 5 | Heartbeat route forwards a client-supplied `x-terminal-id` | Low (handler doesn't read it) | `gateway/envoy.yaml:41-46` |
| 6 | card-service protected only by its loopback bind; overridable by env | Low (not exposed today) | `card-service/src/main.rs:219`; `infra/ecs/modules/region/main.tf:90-93` |
| 7 | Envoy's PSP listener (8444) is dead in ECS | Info | `infra/ecs/modules/region/main.tf:352` |

**mTLS is strict, not permissive** (`gateway/envoy.yaml:19`). **card-service isn't reachable from the network** (§3.2). The flaw is that the **backend** can be reached both through Envoy and around it, and it trusts headers that only Envoy is supposed to set.
