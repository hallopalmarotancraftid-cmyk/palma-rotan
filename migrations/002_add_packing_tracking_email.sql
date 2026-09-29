ALTER TABLE packing_orders ADD COLUMN courier TEXT;
ALTER TABLE packing_orders ADD COLUMN tracking_number TEXT;
ALTER TABLE packing_orders ADD COLUMN tracking_url TEXT;
ALTER TABLE packing_orders ADD COLUMN shipped_at TEXT;
ALTER TABLE packing_orders ADD COLUMN delivered_at TEXT;
ALTER TABLE packing_orders ADD COLUMN auth_code TEXT;
ALTER TABLE packing_orders ADD COLUMN email_sent_at TEXT;
ALTER TABLE packing_orders ADD COLUMN email_error TEXT;