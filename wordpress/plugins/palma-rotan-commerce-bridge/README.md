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
- Setelah order paid, Invoice dan Packing List dibuat otomatis sebagai PDF A4, tersedia sebagai download yang dilindungi order key, dan dikirim sebagai attachment ke email pembeli. Sistem juga menambahkan link download PDF pada email order WooCommerce.
- Shipping method diteruskan sebagai metadata/order shipping item; tarif shipping final harus dikonfigurasi di WooCommerce/custom shipping integration sebelum production.


## Dokumen & email

- Endpoint PDF: `/wp-json/palma/v1/document-pdf/invoice/{order_id}?key={order_key}` dan `/packing/{order_id}`.
- Dokumen hanya dapat diakses dengan order key dan hanya setelah order berstatus paid.
- Nomor Invoice dan Packing List bersifat idempotent; retry hook tidak membuat nomor baru.
- Email dokumen hanya dikirim sekali setelah `wp_mail()` berhasil; jika gagal, sistem dapat mencoba lagi pada hook paid berikutnya.
- PDF dibuat langsung oleh bridge sehingga tidak membutuhkan library PDF eksternal.
- Email pembeli tetap membutuhkan konfigurasi mail server/SMTP WordPress yang benar agar `wp_mail()` benar-benar terkirim.
