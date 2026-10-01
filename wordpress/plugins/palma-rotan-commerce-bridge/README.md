# PALMA ROTAN WooCommerce Commerce Bridge

Tujuan: mempertahankan visitor PALMA ROTAN di Cloudflare Pages, sementara WooCommerce menjadi sumber tunggal untuk cart/checkout/order/payment.

## Flow

Cloudflare visitor -> POST /wp-json/palma/v1/order -> WooCommerce Order -> Midtrans gateway -> paid -> Invoice + Packing List.

## Install

1. Pasang WordPress + WooCommerce.
2. Pasang plugin Midtrans WooCommerce yang digunakan PALMA.
3. Upload folder plugin ini ke wp-content/plugins/palma-rotan-commerce-bridge/.
4. Aktifkan plugin.
5. Di PALMA Orders, set Cloudflare visitor origin dan payment gateway ID sesuai gateway Midtrans yang terpasang.
6. Uji Sandbox sebelum production.

## Catatan

- Produk dicari berdasarkan SKU atau product ID.
- WooCommerce adalah sumber order utama; D1 order tidak dipakai oleh bridge.
- Invoice/Packing dibuat sebagai HTML print-ready setelah order paid. Tombol Print / Save PDF tersedia dari browser.
- Shipping method diteruskan sebagai metadata/order shipping item; tarif shipping final harus dikonfigurasi di WooCommerce/custom shipping integration sebelum production.
