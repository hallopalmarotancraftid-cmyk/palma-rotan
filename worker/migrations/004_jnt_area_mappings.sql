-- J&T destination mapping supplied by the J&T integration/mapping process.
CREATE TABLE IF NOT EXISTS jnt_area_mappings (
  id TEXT PRIMARY KEY,
  province TEXT NOT NULL DEFAULT '',
  city TEXT NOT NULL DEFAULT '',
  district TEXT NOT NULL,
  destination_code TEXT NOT NULL,
  receiver_area TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(province, city, district)
);
CREATE INDEX IF NOT EXISTS idx_jnt_area_lookup
  ON jnt_area_mappings(province, city, district);
