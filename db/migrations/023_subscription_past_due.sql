CREATE INDEX IF NOT EXISTS merchant_subscriptions_period_end_idx
ON merchant_subscriptions (status, current_period_end)
WHERE status = 'ACTIVE';
