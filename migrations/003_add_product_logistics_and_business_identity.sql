-- PALMA ROTAN document and product logistics fields
ALTER TABLE products ADD COLUMN material TEXT;
ALTER TABLE products ADD COLUMN hs_code TEXT;
ALTER TABLE products ADD COLUMN package_type TEXT;
ALTER TABLE products ADD COLUMN units_per_package INTEGER NOT NULL DEFAULT 1;
ALTER TABLE products ADD COLUMN packaging_weight_kg REAL NOT NULL DEFAULT 0;

INSERT INTO site_settings(key,value_json) VALUES
('brand','"PALMA ROTAN"'),
('website','"palmarotancraft.id"'),
('whatsapp','"08978186933"'),
('email','"hallo.palmarotancraft.id@gmail.com"'),
('address','"Jl. Rotan Jaya, Ds. Teluk Wetan, RT 07/RW 01, Kec. Welahan, Kab. Jepara, Prov. Jawa Tengah, Indonesia"'),
('pdfTagline1','"NATURAL CRAFT"'),
('pdfTagline2','"TIMELESS BEAUTY"')
ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=CURRENT_TIMESTAMP;
