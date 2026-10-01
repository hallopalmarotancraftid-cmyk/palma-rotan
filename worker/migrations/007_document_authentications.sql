-- PALMA ROTAN document authentication
CREATE TABLE IF NOT EXISTS document_authentications (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL,
  document_type TEXT NOT NULL CHECK(document_type IN ('invoice','packing')),
  token_hash TEXT NOT NULL UNIQUE,
  token TEXT NOT NULL UNIQUE,
  verification_url TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT,
  verified_at TEXT,
  UNIQUE(order_id, document_type)
);
CREATE INDEX IF NOT EXISTS idx_document_auth_order ON document_authentications(order_id);
CREATE INDEX IF NOT EXISTS idx_document_auth_type ON document_authentications(document_type);
