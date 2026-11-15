-- Grandfathering: merchants already running an edge node keep offline payments when 021's gating ships, so their
-- terminals don't stop on deploy. One 30-day PRO period, like an admin upgrade (SubscriptionService.PERIOD).
-- shortcut: nothing renews it (no billing provider); before it ends, an admin upgrades each merchant again.
-- A merchant who already has a subscription row keeps it: ENTERPRISE is never downgraded, a decision never undone.
-- Not in the audit log: that chain's hashes are computed by the application, so a migration can't append to it.

BEGIN;

INSERT INTO merchant_subscriptions (merchant_id, tier, status, current_period_end)
SELECT DISTINCT merchant_id, 'PRO', 'ACTIVE', now() + interval '30 days'
FROM edge_nodes
WHERE status = 'ACTIVE'
ON CONFLICT (merchant_id) DO NOTHING;

COMMIT;
