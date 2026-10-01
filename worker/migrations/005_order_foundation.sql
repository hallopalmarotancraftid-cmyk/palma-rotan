-- PALMA ROTAN transaction foundation v1
-- Additive only. Do not drop/rename/rebuild existing transaction tables.
ALTER TABLE orders ADD COLUMN customer_snapshot_json TEXT;
ALTER TABLE orders ADD COLUMN idempotency_key TEXT;
ALTER TABLE orders ADD COLUMN idempotency_hash TEXT;

ALTER TABLE order_items ADD COLUMN sku TEXT;
ALTER TABLE order_items ADD COLUMN subtotal REAL;
ALTER TABLE order_items ADD COLUMN weight_grams REAL;
ALTER TABLE order_items ADD COLUMN length_cm REAL;
ALTER TABLE order_items ADD COLUMN width_cm REAL;
ALTER TABLE order_items ADD COLUMN height_cm REAL;

ALTER TABLE order_status_history ADD COLUMN status_type TEXT;
ALTER TABLE order_status_history ADD COLUMN actor TEXT;

UPDATE order_items SET subtotal=total_price WHERE subtotal IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_idempotency_key
ON orders(idempotency_key)
WHERE idempotency_key IS NOT NULL AND idempotency_key <> '';

CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items(order_id);
CREATE INDEX IF NOT EXISTS idx_order_status_history_order_id ON order_status_history(order_id);
