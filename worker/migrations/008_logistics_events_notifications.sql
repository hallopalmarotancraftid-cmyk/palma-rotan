-- PALMA ROTAN logistics events and notification idempotency
CREATE TABLE IF NOT EXISTS tracking_events (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  tracking_number TEXT,
  status TEXT NOT NULL,
  event_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  location TEXT,
  description TEXT,
  source TEXT NOT NULL DEFAULT 'system',
  raw_payload TEXT
);
CREATE INDEX IF NOT EXISTS idx_tracking_events_order_time ON tracking_events(order_id,event_time);

CREATE TABLE IF NOT EXISTS notification_logs (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  notification_type TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL,
  provider_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  sent_at TEXT,
  error_message TEXT
);
CREATE INDEX IF NOT EXISTS idx_notification_logs_order_type ON notification_logs(order_id,notification_type);
