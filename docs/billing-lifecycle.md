# Subscription Billing Lifecycle (since 1.17.0)

## Plans

| Tier | Offline payments | How acquired |
| :--- | :--- | :--- |
| FREE | ❌ blocked | default; no row needed |
| PRO | ✅ ACTIVE only | admin upgrade or auto-renewal |
| ENTERPRISE | ✅ ACTIVE only | admin upgrade (manual) |

A paid plan only entitles offline payments while `status = ACTIVE` **and** `current_period_end` is in the
future. `PAST_DUE` and `CANCELED` are not entitled even if the timestamp hasn't passed.

## Period model

Each paid subscription has a **30-day period** (`current_period_end`). The period is set from the upgrade
timestamp (admin upgrade) or extended from `current_period_end` (auto-renewal), so late renewal webhooks
do not cause period drift.

```
 upgrade:  now ──────────────── now + 30d
 renewal:  ...──── period_end ───────────── period_end + 30d
```

`renewal_count` tracks how many times the subscription has been auto-renewed. Audit queries can filter
automatic renewals (`actor_id = "system:renewal_job"`) from admin upgrades.

## Auto-renewal flow

```
1. Renewal job (or billing provider webhook) detects period_end ≤ now + 5d
   (via SubscriptionRepository.list_active_expiring)

2. Billing provider charges the merchant's payment method
   (outside this system: BillingProvider interface, not yet wired)

3. On charge success → POST /api/v1/subscriptions/renew
   Bearer token scope: billing:webhook

4. SubscriptionService.renew_subscription extends period_end by 30d,
   increments renewal_count, writes audit row with actor "system:renewal_job"

5. Edge node syncs rules on next heartbeat and continues offline operations
```

## Idempotency

`renew_subscription` is idempotent by state: if `current_period_end > now + 30d`, the subscription
already has a full period ahead and is returned unchanged with no audit row. This means a duplicate
webhook or a retry by the renewal job does not double-extend the period.

## Status transitions

```
(no row) ──upgrade──→ ACTIVE
ACTIVE   ──period expires──→ PAST_DUE   (the renewal job marks this if charge fails)
PAST_DUE ──renewal succeeds──→ ACTIVE   (renew_subscription starts a fresh period from now)
ACTIVE   ──admin cancel──→ CANCELED
```

**FREE and CANCELED merchants** are returned unchanged by `renew_subscription` without error. The renewal
job is responsible for filtering to paid plans via `list_active_expiring` before calling the endpoint.

## Shortcut: billing provider not yet wired

The `billing:webhook` endpoint exists; the billing provider that calls it does not. Until it is wired:

- PRO plans are still granted by platform admins via `POST /api/v1/subscriptions/upgrade`
- The renewal job can call the renew endpoint internally with `actor_id = "system:renewal_job"` after
  a free mock charge
- When a real `BillingProvider` is added, put it behind the `BillingProvider` interface (not yet defined),
  charge first, then call `renew_subscription` on success; `mark_renewal_failed` on failure (not yet
  implemented — set status to `PAST_DUE` manually until it is)

## API reference

| Endpoint | Scope | Purpose |
| :--- | :--- | :--- |
| `POST /api/v1/subscriptions/upgrade` | `registry:admin` | Admin grants a PRO period |
| `POST /api/v1/subscriptions/renew` | `billing:webhook` | Billing webhook extends an active period |

Both return a `Subscription` object. Since 1.17.0 the response includes `renewal_count`.

## Not done

- **`mark_renewal_failed`** — sets status to `PAST_DUE` and writes audit; needed for the failed-charge path
- **Grace period** — a configurable window before `PAST_DUE` cuts off offline sales
- **`auto_renew` flag** — per-merchant opt-out of auto-renewal
- **`billing_reference` idempotency** — deduplicate on the billing provider's charge ID, not just by state
- **ENTERPRISE auto-renewal** — currently only admin-managed; renewal job skips ENTERPRISE merchants
  (they are excluded from `list_active_expiring` in the fake; infrastructure may differ)
