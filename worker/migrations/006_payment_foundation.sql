-- PALMA ROTAN payment foundation v1
-- Additive only. Existing payment history is preserved.
ALTER TABLE payments ADD COLUMN payment_url TEXT;
ALTER TABLE payments ADD COLUMN expiry_time TEXT;
ALTER TABLE payments ADD COLUMN payment_type TEXT;
ALTER TABLE payments ADD COLUMN fraud_status TEXT;
ALTER TABLE payments ADD COLUMN raw_response TEXT;
ALTER TABLE payments ADD COLUMN updated_at TEXT;

ALTER TABLE payment_webhooks ADD COLUMN raw_payload TEXT;
ALTER TABLE payment_webhooks ADD COLUMN status TEXT;
ALTER TABLE payment_webhooks ADD COLUMN error_message TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_provider_transaction
ON payments(provider,provider_transaction_id)
WHERE provider_transaction_id IS NOT NULL AND provider_transaction_id <> '';

CREATE INDEX IF NOT EXISTS idx_payments_order_status
ON payments(order_id,status);
