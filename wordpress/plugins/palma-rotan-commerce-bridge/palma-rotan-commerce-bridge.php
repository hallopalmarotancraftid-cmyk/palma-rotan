<?php
/**
 * Plugin Name: PALMA ROTAN Commerce Bridge
 * Description: WooCommerce order bridge for the PALMA ROTAN Cloudflare visitor site. Keeps WooCommerce as the single order source and exposes a small REST API for products, checkout, payment redirect, invoice and packing documents.
 * Version: 1.1.0
 * Requires Plugins: woocommerce
 */

if (!defined('ABSPATH')) exit;

final class Palma_Rotan_Commerce_Bridge {
    const REST_NS = 'palma/v1';

    public static function boot() {
        add_action('rest_api_init', [__CLASS__, 'routes']);
        add_action('woocommerce_payment_complete', [__CLASS__, 'documents_on_paid']);
        add_action('woocommerce_payment_complete', [__CLASS__, 'sync_paid_order_to_palma'], 30);
        add_action('woocommerce_order_status_processing', [__CLASS__, 'documents_on_paid']);
        add_action('woocommerce_order_status_completed', [__CLASS__, 'documents_on_paid']);
        add_action('woocommerce_email_order_details', [__CLASS__, 'email_documents_note'], 20, 4);
        add_action('admin_menu', [__CLASS__, 'admin_menu']);
        add_action('admin_post_palma_save_tracking', [__CLASS__, 'save_tracking']);
        add_action('admin_post_palma_sync_order', [__CLASS__, 'manual_sync_order']);
        add_action('admin_init', [__CLASS__, 'register_settings']);
        add_action('palma_sync_paid_order', [__CLASS__, 'run_scheduled_sync'], 10, 1);
        add_filter('rest_pre_serve_request', [__CLASS__, 'serve_cors'], 10, 4);
        add_action('wp_head', [__CLASS__, 'payment_page_styles']);
        add_filter('midtrans_snap_params_main_before_charge', [__CLASS__, 'midtrans_retry_order_id'], 10, 1);
    }

    public static function routes() {
        register_rest_route(self::REST_NS, '/products', [
            'methods' => 'GET',
            'permission_callback' => '__return_true',
            'callback' => [__CLASS__, 'products'],
        ]);
        register_rest_route(self::REST_NS, '/shipping-rates', [
            'methods' => 'POST',
            'permission_callback' => '__return_true',
            'callback' => [__CLASS__, 'shipping_rates'],
        ]);
        register_rest_route(self::REST_NS, '/order', [
            [
                'methods' => 'POST',
                'permission_callback' => '__return_true',
                'callback' => [__CLASS__, 'create_order'],
            ],
            [
                'methods' => 'OPTIONS',
                'permission_callback' => '__return_true',
                'callback' => [__CLASS__, 'cors_options'],
            ],
        ]);
        register_rest_route(self::REST_NS, '/order/(?P<id>\d+)/pay', [
            'methods' => 'GET',
            'permission_callback' => '__return_true',
            'callback' => [__CLASS__, 'pay_order'],
        ]);
        register_rest_route(self::REST_NS, '/order/(?P<id>\d+)', [
            'methods' => 'GET',
            'permission_callback' => '__return_true',
            'callback' => [__CLASS__, 'order'],
        ]);
        register_rest_route(self::REST_NS, '/document/(?P<type>invoice|packing|label)/(?P<id>\d+)', [
            'methods' => 'GET',
            'permission_callback' => '__return_true',
            'callback' => [__CLASS__, 'document'],
        ]);
        register_rest_route(self::REST_NS, '/document-pdf/(?P<type>invoice|packing|label)/(?P<id>\d+)', [
            'methods' => 'GET',
            'permission_callback' => '__return_true',
            'callback' => [__CLASS__, 'document_pdf'],
        ]);
    }

    public static function serve_cors($served, $result, $request, $server) {
        $route = $request->get_route();
        if (strpos($route, '/' . self::REST_NS . '/') !== 0) return $served;
        $allowed = trim((string) get_option('palma_allowed_origin', 'https://palma-rotan.pages.dev'));
        $origin = isset($_SERVER['HTTP_ORIGIN']) ? trim((string) wp_unslash($_SERVER['HTTP_ORIGIN'])) : '';
        if ($allowed && $origin === $allowed) {
            header('Access-Control-Allow-Origin: ' . $allowed);
            header('Vary: Origin');
            header('Access-Control-Allow-Headers: Content-Type, X-Palma-Order-Key');
            header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        }

        // REST normally JSON-encodes scalar response bodies. Documents must be
        // served as their actual HTML/PDF bytes so browsers and email links can
        // download them correctly.
        if (strpos($route, '/' . self::REST_NS . '/document/') === 0 ||
            strpos($route, '/' . self::REST_NS . '/document-pdf/') === 0) {
            if ($result instanceof WP_REST_Response) {
                $data = $result->get_data();
                if (is_string($data)) {
                    $is_pdf = strpos($route, '/' . self::REST_NS . '/document-pdf/') === 0;
                    if ($is_pdf) {
                        // PDF bytes must reach Chrome unchanged. Discard any output
                        // accidentally produced by themes/plugins before this REST
                        // response, then send an explicit length and no-sniff header.
                        while (ob_get_level() > 0) {
                            ob_end_clean();
                        }
                        header('Content-Type: application/pdf');
                        header('Content-Disposition: attachment');
                        header('Content-Length: ' . strlen($data));
                        header('Content-Encoding: identity');
                        header('X-Content-Type-Options: nosniff');
                    } else {
                        header('Content-Type: text/html; charset=utf-8');
                    }
                    echo $data;
                    return true;
                }
            }
        }
        return $served;
    }

    private static function cors($response) {
        $allowed = trim((string) get_option('palma_allowed_origin', 'https://palma-rotan.pages.dev'));
        if ($allowed) $response->header('Access-Control-Allow-Origin', $allowed);
        $response->header('Access-Control-Allow-Headers', 'Content-Type');
        $response->header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        return $response;
    }

    public static function products() {
        if (!class_exists('WooCommerce')) return self::error('WooCommerce belum aktif.', 503);
        $products = wc_get_products(['status'=>'publish','limit'=>-1,'orderby'=>'date','order'=>'DESC']);
        $rate = max(1, (float) get_option('palma_usd_idr_rate', 16000));
        $out = [];
        foreach ($products as $p) {
            $price_usd = (float) $p->get_regular_price();
            $stored_idr = (float) get_post_meta($p->get_id(), '_palma_price_idr', true);
            $price_idr = $stored_idr > 0 ? $stored_idr : ($price_usd > 0 ? $price_usd * $rate : 0);
            $out[] = [
                'id' => (string) $p->get_id(),
                'sku' => (string) $p->get_sku(),
                'name' => $p->get_name(),
                'price_idr' => $price_idr,
                'price_usd' => $price_usd,
                'stock' => $p->managing_stock() ? (int) $p->get_stock_quantity() : null,
                'weight_kg' => (float) $p->get_weight(),
                'dimensions_cm' => trim($p->get_length().' × '.$p->get_width().' × '.$p->get_height(), ' ×'),
                'image' => wp_get_attachment_image_url($p->get_image_id(), 'full') ?: '',
                'type' => (string) get_post_meta($p->get_id(), '_palma_type', true) ?: 'retail',
                'moq' => max(1, (int) get_post_meta($p->get_id(), '_palma_moq', true)),
            ];
        }
        return self::cors(new WP_REST_Response(['products'=>$out], 200));
    }

    public static function create_order(WP_REST_Request $request) {
        if (!class_exists('WooCommerce')) return self::error('WooCommerce belum aktif.', 503);
        $body = $request->get_json_params();
        $items = is_array($body['items'] ?? null) ? $body['items'] : [];
        $customer = is_array($body['customer'] ?? null) ? $body['customer'] : [];
        $shipping = is_array($body['shippingAddress'] ?? null) ? $body['shippingAddress'] : [];
        if (!$items) return self::error('Produk wajib diisi.', 400);
        if (empty($customer['email']) || !is_email($customer['email'])) return self::error('Email customer tidak valid.', 400);

        // Public checkout guard: limit repeated order creation attempts per email/IP.
        // This is intentionally small so normal customers can retry a failed payment.
        $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : 'unknown';
        $fingerprint = 'palma_checkout_' . md5(strtolower(trim((string)$customer['email'])) . '|' . $ip);
        $attempts = (int) get_transient($fingerprint);
        if ($attempts >= 8) return self::error('Terlalu banyak percobaan checkout. Silakan coba lagi beberapa menit kemudian.', 429);
        set_transient($fingerprint, $attempts + 1, 5 * MINUTE_IN_SECONDS);

        $payment_method = strtolower(trim(sanitize_text_field($body['paymentMethod'] ?? $body['paymentGateway'] ?? 'gateway')));
        if (!in_array($payment_method, ['gateway', 'payment gateway', 'midtrans'], true)) {
            return self::error('Checkout WooCommerce hanya menggunakan Payment Gateway.', 400);
        }

        try {
            $order = wc_create_order();
            $order->set_created_via('palma-cloudflare');
            $order->set_billing_first_name(sanitize_text_field($customer['firstName'] ?? ''));
            $order->set_billing_last_name(sanitize_text_field($customer['lastName'] ?? ''));
            $order->set_billing_email(sanitize_email($customer['email']));
            $order->set_billing_phone(sanitize_text_field($customer['phone'] ?? ''));
            $order->set_billing_country(sanitize_text_field($customer['country'] ?? ''));
            $order->set_billing_address_1(sanitize_text_field($shipping['address'] ?? ''));
            $order->set_billing_city(sanitize_text_field($shipping['city'] ?? ''));
            $order->set_billing_state(sanitize_text_field($shipping['province'] ?? ''));
            $order->set_billing_postcode(sanitize_text_field($shipping['postalCode'] ?? ''));
            $order->set_shipping_first_name(sanitize_text_field($customer['firstName'] ?? ''));
            $order->set_shipping_last_name(sanitize_text_field($customer['lastName'] ?? ''));
            $order->set_shipping_country(sanitize_text_field($shipping['country'] ?? $customer['country'] ?? ''));
            $order->set_shipping_address_1(sanitize_text_field($shipping['address'] ?? ''));
            $order->set_shipping_city(sanitize_text_field($shipping['city'] ?? ''));
            $order->set_shipping_state(sanitize_text_field($shipping['province'] ?? ''));
            $order->set_shipping_postcode(sanitize_text_field($shipping['postalCode'] ?? ''));

            $shipping_method_input = strtolower(trim(sanitize_text_field($body['shippingMethod'] ?? 'standard')));
            $shipping_methods = [
                'standard' => 'Standard',
                'express' => 'Express',
            ];
            if (!isset($shipping_methods[$shipping_method_input])) {
                throw new Exception('Metode pengiriman tidak valid. Pilih Standard atau Express.');
            }
            $shipping_method = $shipping_methods[$shipping_method_input];
            $country = strtoupper(sanitize_text_field($shipping['country'] ?? $customer['country'] ?? ''));
            if (!preg_match('/^[A-Z]{2}$/', $country)) {
                throw new Exception('Negara pengiriman tidak valid.');
            }
            $currency = strtoupper(sanitize_text_field($body['currency'] ?? 'USD')) === 'IDR' ? 'IDR' : 'USD';
            $order->set_currency('IDR');

            $rate = max(1, (float) get_option('palma_usd_idr_rate', 16000));
            $requested = [];
            foreach ($items as $row) {
                $lookup = sanitize_text_field($row['sku'] ?? '');
                if ($lookup === '') throw new Exception('SKU produk wajib tersedia untuk checkout WooCommerce.');
                $qty = (int) ($row['quantity'] ?? 0);
                if ($qty < 1) throw new Exception('Quantity produk harus minimal 1.');
                $requested[$lookup] = ($requested[$lookup] ?? 0) + $qty;
            }
            foreach ($requested as $lookup => $qty) {
                $ids = wc_get_products(['sku'=>$lookup,'status'=>'publish','limit'=>1,'return'=>'ids']);
                $product = $ids ? wc_get_product($ids[0]) : false;
                if (!$product || !$product->is_purchasable()) throw new Exception('Produk tidak tersedia untuk dibeli: '.$lookup);
                if ($product->managing_stock() && $product->get_stock_quantity() < $qty) throw new Exception('Stok tidak mencukupi untuk '.$product->get_name());
                $type = (string) get_post_meta($product->get_id(), '_palma_type', true);
                $moq = max(1, (int) get_post_meta($product->get_id(), '_palma_moq', true));
                if ($type === 'custom' && $qty < $moq) throw new Exception('MOQ untuk '.$product->get_name().' adalah '.$moq.'.');
                $price_idr = (float) get_post_meta($product->get_id(), '_palma_price_idr', true);
                $base_price = (float) $product->get_regular_price();
                $unit_idr = $price_idr > 0 ? $price_idr : ($base_price * $rate);
                if ($unit_idr <= 0) throw new Exception('Harga produk tidak valid: '.$product->get_name());
                $line = new WC_Order_Item_Product();
                $line->set_product($product);
                $line->set_quantity($qty);
                $line->set_subtotal(round($unit_idr * $qty, 2));
                $line->set_total(round($unit_idr * $qty, 2));
                $order->add_item($line);
            }

            $base = ['ID'=>6,'US'=>45,'CA'=>48,'GB'=>42,'AU'=>38,'SG'=>18,'DE'=>44,'FR'=>44,'NL'=>44];
            $usd = $base[$country] ?? 55;
            if ($shipping_method_input === 'express') $usd *= 1.7;
            $shipping_total = round($usd * $rate);
            $item = new WC_Order_Item_Shipping();
            $item->set_method_title($shipping_method . ' · ' . ($country === 'ID' ? 'J&T' : 'DHL'));
            $item->set_method_id('palma_' . sanitize_key($shipping_method));
            $item->set_total($shipping_total);
            $order->add_item($item);

            $order->update_meta_data('_palma_currency', $currency);
            $order->update_meta_data('_palma_shipping_carrier', $country === 'ID' ? 'J&T' : 'DHL');
            $order->update_meta_data('_palma_shipping_method', $shipping_method);
            $order->calculate_totals();
            $order->update_meta_data('_palma_admin_total_idr', (string) round($order->get_total()));
            $order->save();

            // Create the order first. The gateway redirect is performed by a normal
            // browser navigation below, not inside the cross-origin fetch.
            $order->update_status('pending', 'PALMA checkout created; awaiting payment.');
            $gateway_id = sanitize_text_field(get_option('palma_payment_gateway_id', 'midtrans'));
            $gateways = WC()->payment_gateways()->payment_gateways();
            // WooCommerce's order-pay page decides which receipt/payment UI to render
            // from the order's saved payment method. The PALMA checkout calls the
            // gateway directly, so persist that method explicitly before redirecting.
            if (!$order->get_payment_method() || $order->get_payment_method() !== $gateway_id) {
                $order->set_payment_method($gateway_id);
                if (isset($gateways[$gateway_id]) && $gateways[$gateway_id] instanceof WC_Payment_Gateway) {
                    $order->set_payment_method_title($gateways[$gateway_id]->get_title());
                }
                $order->save();
            }
            $payment_url = add_query_arg(['key'=>$order->get_order_key()], rest_url(self::REST_NS . '/order/' . $order->get_id() . '/pay'));

            return self::cors(new WP_REST_Response([
                'ok'=>true,
                'orderId'=>$order->get_id(),
                'orderNumber'=>$order->get_order_number(),
                'status'=>$order->get_status(),
                'currency'=>$currency,
                'paymentCurrency'=>'IDR',
                'subtotal'=>(float) ($currency === 'USD' ? $order->get_subtotal() / $rate : $order->get_subtotal()),
                'subtotalIdr'=>(float) $order->get_subtotal(),
                'shippingAmount'=>(float) ($currency === 'USD' ? $order->get_shipping_total() / $rate : $order->get_shipping_total()),
                'shippingAmountIdr'=>(float) $order->get_shipping_total(),
                'total'=>(float) ($currency === 'USD' ? $order->get_total() / $rate : $order->get_total()),
                'totalIdr'=>(float) $order->get_total(),
                'paymentUrl'=>$payment_url,
                'paymentGateway'=>$gateway_id,
                'orderKey'=>$order->get_order_key(),
            ], 201));
        } catch (Throwable $e) {
            return self::error($e->getMessage(), 400);
        }
    }

    public static function pay_order(WP_REST_Request $request) {
        $order = wc_get_order((int)$request['id']);
        if (!$order) return self::error('Order tidak ditemukan.', 404);
        if (!self::authorize_order($order, $request)) return self::error('Order key tidak valid.', 403);
        if ($order->is_paid()) { wp_safe_redirect(home_url('/')); exit; }
        $gateway_id = sanitize_text_field(get_option('palma_payment_gateway_id', 'midtrans'));
        $gateways = WC()->payment_gateways()->payment_gateways();
        if (!isset($gateways[$gateway_id])) wp_die('Payment gateway WooCommerce tidak ditemukan.');
        if (!$gateways[$gateway_id]->is_available()) wp_die('Payment gateway WooCommerce tidak tersedia.');
        // Keep the order's payment method aligned with the gateway used to create
        // the Snap transaction. WooCommerce uses this value on /checkout/order-pay/
        // to fire the matching woocommerce_receipt_{gateway_id} hook.
        if ($order->get_payment_method() !== $gateway_id) {
            $order->set_payment_method($gateway_id);
            $order->set_payment_method_title($gateways[$gateway_id]->get_title());
            $order->save();
        }
        try {
            // Midtrans' WooCommerce gateway expects a live WooCommerce cart/session
            // and calls WC()->cart->empty_cart() during process_payment(). This
            // endpoint is reached directly by browser navigation, outside the normal
            // WooCommerce checkout request, so initialize the cart/session first.
            if (function_exists('wc_load_cart')) {
                wc_load_cart();
            }
            if (!WC()->cart) {
                wp_die('WooCommerce cart/session gagal diinisialisasi.');
            }
            $result = $gateways[$gateway_id]->process_payment($order->get_id());
            if (!is_array($result) || ($result['result'] ?? '') !== 'success' || empty($result['redirect'])) wp_die('Payment gateway gagal membuat pembayaran.');
            wp_safe_redirect(esc_url_raw($result['redirect']));
            exit;
        } catch (Throwable $e) {
            wp_die(esc_html($e->getMessage()));
        }
    }

    /**
     * Midtrans requires each Snap transaction to use a unique order_id.
     * WooCommerce reuses the same order ID when a customer retries payment.
     * The Midtrans plugin normally handles this, but some plugin versions only
     * recognize the Indonesian duplicate-error text. This compatibility filter
     * uses the same -wc-mdtrs- suffix format so Midtrans notifications can still
     * restore the original WooCommerce order ID.
     */
    public static function midtrans_retry_order_id($params) {
        if (!isset($params['transaction_details']['order_id'])) return $params;
        $base_order_id = sanitize_text_field((string) $params['transaction_details']['order_id']);
        if ($base_order_id === '' || strpos($base_order_id, '-wc-mdtrs-') !== false) return $params;

        $order = wc_get_order((int) $base_order_id);
        if (!$order || $order->is_paid()) return $params;

        // If a Snap token already exists, this is a retry of the same WC order.
        $previous_token = (string) $order->get_meta('_mt_payment_snap_token');
        if ($previous_token === '') return $params;

        $retry_id = $base_order_id . '-wc-mdtrs-' . gmdate('YmdHis') . '-' . wp_rand(1000, 9999);
        $params['transaction_details']['order_id'] = $retry_id;
        $order->update_meta_data('_mt_suffixed_midtrans_order_id', $retry_id);
        $order->save();
        return $params;
    }

    public static function payment_page_styles() {
        if (!function_exists('is_wc_endpoint_url') || !is_wc_endpoint_url('order-pay')) return;
        echo '<style id="palma-payment-page-cleanup">
        /* Payment page is a dedicated transaction screen; the theme cart icon is not needed here. */
        body.woocommerce-order-pay .site-header-cart,
        body.woocommerce-order-pay .cart-contents,
        body.woocommerce-order-pay .woocommerce-cart-link,
        body.woocommerce-order-pay .header-cart,
        body.woocommerce-order-pay .header-cart-icon,
        body.woocommerce-order-pay .wc-block-mini-cart,
        body.woocommerce-order-pay a[href*="/cart/"] { display:none !important; }
        </style>';
    }

    private static function authorize_order($order, WP_REST_Request $request) {
        if (!$order) return false;
        $key = sanitize_text_field($request->get_param('key'));
        if (!$key) $key = sanitize_text_field($request->get_header('X-Palma-Order-Key'));
        return $key && hash_equals((string) $order->get_order_key(), (string) $key);
    }

    public static function order(WP_REST_Request $request) {
        $order = wc_get_order((int) $request['id']);
        if (!$order) return self::error('Order tidak ditemukan.', 404);
        if (!self::authorize_order($order, $request)) return self::error('Order key tidak valid.', 403);
        return self::cors(new WP_REST_Response(self::order_data($order), 200));
    }

    private static function order_data($order) {
        $items=[];
        foreach ($order->get_items() as $item) {
            $p=$item->get_product();
            $items[]=[
                'productId'=>$p ? (string)$p->get_id() : '',
                'sku'=>$p ? (string)$p->get_sku() : '',
                'name'=>$item->get_name(),
                'quantity'=>(int)$item->get_quantity(),
                'total'=>(float)$item->get_total(),
            ];
        }
        $currency = strtoupper((string) $order->get_meta('_palma_currency')) === 'IDR' ? 'IDR' : 'USD';
        $rate = max(1, (float) get_option('palma_usd_idr_rate', 16000));
        $subtotal_idr = (float) $order->get_subtotal();
        $shipping_idr = (float) $order->get_shipping_total();
        $total_idr = (float) $order->get_total();
        return [
            'orderId'=>$order->get_id(),
            'orderNumber'=>$order->get_order_number(),
            'status'=>$order->get_status(),
            'paymentStatus'=>$order->is_paid() ? 'PAID' : 'PENDING',
            'currency'=>$currency,
            'paymentCurrency'=>'IDR',
            'subtotalIdr'=>$subtotal_idr,
            'shippingAmountIdr'=>$shipping_idr,
            'totalIdr'=>$total_idr,
            'customer'=>[
                'firstName'=>$order->get_billing_first_name(),
                'email'=>$order->get_billing_email(),
                'phone'=>$order->get_billing_phone(),
                'country'=>$order->get_billing_country(),
            ],
            'items'=>$items,
            'subtotal'=>(float) ($currency === 'USD' ? $subtotal_idr / $rate : $subtotal_idr),
            'shippingAmount'=>(float) ($currency === 'USD' ? $shipping_idr / $rate : $shipping_idr),
            'total'=>(float) ($currency === 'USD' ? $total_idr / $rate : $total_idr),
            'shippingMethod'=>(string)$order->get_shipping_method(),
            'shippingCarrier'=>(string)$order->get_meta('_palma_shipping_carrier'),
            'trackingNumber'=>(string)$order->get_meta('_palma_tracking_number'),
            'trackingUrl'=>(string)$order->get_meta('_palma_tracking_url'),
            'invoiceUrl'=>$order->is_paid() ? rest_url(self::REST_NS.'/document-pdf/invoice/'.$order->get_id()).'?key='.rawurlencode($order->get_order_key()) : '',
            'packingUrl'=>$order->is_paid() ? rest_url(self::REST_NS.'/document-pdf/packing/'.$order->get_id()).'?key='.rawurlencode($order->get_order_key()) : '',
        ];
    }

    public static function sync_paid_order_to_palma($order_id) {
        $order = wc_get_order((int) $order_id);
        if (!$order || !$order->is_paid()) return;
        self::send_order_to_palma($order, false);
    }

    public static function run_scheduled_sync($order_id) {
        $order = wc_get_order((int) $order_id);
        if (!$order || !$order->is_paid()) return;
        self::send_order_to_palma($order, true);
    }

    private static function palma_hmac($secret, $body) {
        return hash_hmac('sha256', $body, $secret);
    }

    private static function send_order_to_palma($order, $from_retry = false) {
        if (!$order || !$order->is_paid()) return false;
        $url = trim((string) get_option('palma_worker_sync_url', 'https://palma-rotan-api-staging.hallo-palmarotancraft-id.workers.dev/api/integrations/woocommerce/order'));
        $secret = trim((string) get_option('palma_worker_sync_secret', ''));
        if ($url === '' || $secret === '') {
            $message = 'PALMA sync belum dikonfigurasi: Worker Sync URL/Secret kosong.';
            $order->update_meta_data('_palma_sync_status', 'RETRY');
            $order->update_meta_data('_palma_sync_last_error', $message);
            $order->add_order_note($message);
            $order->save();
            return false;
        }
        if ((string) $order->get_meta('_palma_sync_status') === 'SYNCED') return true;
        $idempotency = (string) $order->get_meta('_palma_sync_idempotency');
        if ($idempotency === '') {
            $idempotency = 'wc-' . $order->get_id() . '-' . substr(hash('sha256', $order->get_order_key()), 0, 16);
            $order->update_meta_data('_palma_sync_idempotency', $idempotency);
            $order->save();
        }

        $items = [];
        foreach ($order->get_items() as $item_id => $item) {
            $product = $item->get_product();
            $items[] = [
                'sourceItemId' => (string) $item_id,
                'sourceProductId' => $product ? (string) $product->get_id() : '',
                'sku' => $product ? (string) $product->get_sku() : '',
                'name' => (string) $item->get_name(),
                'quantity' => (int) $item->get_quantity(),
                'unitPrice' => (float) $order->get_item_total($item, false, false),
                'lineTotal' => (float) $item->get_total(),
                'weightKg' => $product ? (float) $product->get_weight() : 0,
                'dimensionsCm' => $product ? trim($product->get_length().' × '.$product->get_width().' × '.$product->get_height(), ' ×') : '',
            ];
        }

        $shipping_country = (string) $order->get_shipping_country();
        $shipping_method = (string) $order->get_shipping_method();
        $shipping_carrier = (string) $order->get_meta('_palma_shipping_carrier');
        if ($shipping_carrier === '') $shipping_carrier = strtoupper($shipping_country) === 'ID' ? 'J&T' : 'DHL';

        $payload = [
            'source' => 'woocommerce',
            'sourceOrderId' => (string) $order->get_id(),
            'sourceOrderNumber' => (string) $order->get_order_number(),
            'idempotencyKey' => $idempotency,
            'createdAt' => $order->get_date_created() ? $order->get_date_created()->date('c') : gmdate('c'),
            'currency' => (string) $order->get_currency(),
            'subtotal' => (float) $order->get_subtotal(),
            'shippingAmount' => (float) $order->get_shipping_total(),
            'total' => (float) $order->get_total(),
            'paymentStatus' => 'PAID',
            'payment' => [
                'provider' => 'woocommerce',
                'method' => (string) ($order->get_payment_method() ?: 'gateway'),
                'transactionId' => (string) $order->get_transaction_id(),
                'paidAt' => $order->get_date_paid() ? $order->get_date_paid()->date('c') : gmdate('c'),
                'amount' => (float) $order->get_total(),
                'currency' => (string) $order->get_currency(),
            ],
            'customer' => [
                'firstName' => (string) $order->get_billing_first_name(),
                'lastName' => (string) $order->get_billing_last_name(),
                'email' => (string) $order->get_billing_email(),
                'phone' => (string) $order->get_billing_phone(),
                'country' => (string) $order->get_billing_country(),
            ],
            'shippingAddress' => [
                'firstName' => (string) $order->get_shipping_first_name(),
                'lastName' => (string) $order->get_shipping_last_name(),
                'address' => (string) $order->get_shipping_address_1(),
                'address2' => (string) $order->get_shipping_address_2(),
                'city' => (string) $order->get_shipping_city(),
                'province' => (string) $order->get_shipping_state(),
                'postalCode' => (string) $order->get_shipping_postcode(),
                'country' => $shipping_country,
            ],
            'shipping' => [
                'carrier' => $shipping_carrier,
                'method' => $shipping_method,
                'amount' => (float) $order->get_shipping_total(),
            ],
            'items' => $items,
            'documents' => [
                'invoiceNumber' => (string) $order->get_meta('_palma_invoice_number'),
                'packingNumber' => (string) $order->get_meta('_palma_packing_number'),
                'invoiceUrl' => self::document_pdf_url($order, 'invoice'),
                'packingUrl' => self::document_pdf_url($order, 'packing'),
                'labelUrl' => self::document_pdf_url($order, 'label'),
            ],
            'meta' => [
                'orderKey' => (string) $order->get_order_key(),
                'sourceSite' => home_url('/'),
            ],
        ];

        $body = wp_json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($body)) {
            $order->update_meta_data('_palma_sync_status', 'FAILED');
            $order->update_meta_data('_palma_sync_last_error', 'Gagal encode payload WooCommerce.');
            $order->save();
            return false;
        }

        $response = wp_remote_post(rtrim($url, '/'), [
            'timeout' => 20,
            'blocking' => true,
            'headers' => [
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
                'X-Palma-Signature' => self::palma_hmac($secret, $body),
                'X-Palma-Idempotency-Key' => $idempotency,
                'X-Palma-Source' => 'woocommerce',
                'User-Agent' => 'PALMA-ROTAN-Commerce-Bridge/1.1.0',
            ],
            'body' => $body,
            'data_format' => 'body',
        ]);

        if (is_wp_error($response)) {
            $message = $response->get_error_message();
            $order->update_meta_data('_palma_sync_status', 'RETRY');
            $order->update_meta_data('_palma_sync_last_error', $message);
            $order->save();
            if (!$from_retry && !wp_next_scheduled('palma_sync_paid_order', [$order->get_id()])) {
                wp_schedule_single_event(time() + 60, 'palma_sync_paid_order', [$order->get_id()]);
            }
            return false;
        }

        $code = (int) wp_remote_retrieve_response_code($response);
        $data = json_decode((string) wp_remote_retrieve_body($response), true);
        if ($code >= 200 && $code < 300 && is_array($data) && !empty($data['ok'])) {
            $order->update_meta_data('_palma_sync_status', 'SYNCED');
            $order->update_meta_data('_palma_sync_at', gmdate('c'));
            $order->update_meta_data('_palma_sync_last_error', '');
            if (!empty($data['palmaOrderId'])) $order->update_meta_data('_palma_order_id', sanitize_text_field($data['palmaOrderId']));
            $order->add_order_note('Order PAID berhasil disinkronkan otomatis ke PALMA ROTAN.');
            $order->save();
            return true;
        }

        $raw_response = trim((string) wp_remote_retrieve_body($response));
        if (is_array($data) && !empty($data['error'])) {
            $message = (string) $data['error'];
        } elseif ($raw_response !== '') {
            $message = 'PALMA sync HTTP '.$code.': '.substr(preg_replace('/\\s+/', ' ', wp_strip_all_tags($raw_response)), 0, 450);
        } else {
            $message = 'PALMA sync HTTP '.$code.' tanpa response body.';
        }
        $order->update_meta_data('_palma_sync_status', 'RETRY');
        $order->update_meta_data('_palma_sync_last_error', substr($message, 0, 500));
        $order->save();
        if (!$from_retry && !wp_next_scheduled('palma_sync_paid_order', [$order->get_id()])) {
            wp_schedule_single_event(time() + 60, 'palma_sync_paid_order', [$order->get_id()]);
        }
        return false;
    }

    public static function documents_on_paid($order_id) {
        $order=wc_get_order($order_id);
        if (!$order || !$order->is_paid()) return;
        self::ensure_documents($order);
        self::send_documents_email($order);
    }

    public static function email_documents_note($order, $sent_to_admin, $plain_text, $email) {
        if ($sent_to_admin || !$order || !$order->is_paid()) return;
        $invoice=self::document_pdf_url($order,'invoice');
        $packing=self::document_pdf_url($order,'packing');
        if ($plain_text) {
            echo "\nPALMA ROTAN documents:\nInvoice: ".$invoice."\nPacking List: ".$packing."\n";
        } else {
            echo '<p><strong>PALMA ROTAN documents:</strong> <a href="'.esc_url($invoice).'">Download Invoice PDF</a> · <a href="'.esc_url($packing).'">Download Packing List PDF</a></p>';
        }
    }

    private static function document_pdf_url($order,$type) {
        return rest_url(self::REST_NS.'/document-pdf/'.$type.'/'.$order->get_id()).'?key='.rawurlencode($order->get_order_key());
    }

    private static function send_documents_email($order) {
        if (!$order || !$order->is_paid()) return false;
        if (get_post_meta($order->get_id(),'_palma_documents_email_sent',true)) return true;
        $email=$order->get_billing_email();
        if (!$email || !is_email($email)) return false;
        self::ensure_documents($order);

        $tmp=[];
        try {
            foreach (['invoice','packing'] as $type) {
                $pdf=self::build_pdf($order,$type);
                $file=wp_tempnam('palma-'.$type.'-'.$order->get_order_number().'.pdf');
                if (!$file || file_put_contents($file,$pdf)===false) throw new Exception('Gagal membuat file PDF.');
                $tmp[$type]=$file;
            }
            $subject='PALMA ROTAN — Order #'.$order->get_order_number().' — Invoice & Packing List';
            $message='Terima kasih telah berbelanja di PALMA ROTAN.\n\nPembayaran pesanan #'.$order->get_order_number().' telah berhasil. Invoice dan Packing List terlampir dalam email ini.\n\nInvoice: '.self::document_pdf_url($order,'invoice').'\nPacking List: '.self::document_pdf_url($order,'packing').'\n';
            $headers=['Content-Type: text/plain; charset=UTF-8'];
            $attachments=[$tmp['invoice'],$tmp['packing']];
            $sent=wp_mail($email,$subject,$message,$headers,$attachments);
            if ($sent) update_post_meta($order->get_id(),'_palma_documents_email_sent',gmdate('c'));
            foreach ($tmp as $file) if (is_string($file) && file_exists($file)) @unlink($file);
            return (bool)$sent;
        } catch (Throwable $e) {
            foreach ($tmp as $file) if (is_string($file) && file_exists($file)) @unlink($file);
            $order->add_order_note('PALMA document email gagal: '.$e->getMessage());
            return false;
        }
    }

    private static function pdf_escape($text) {
        $text=wp_strip_all_tags((string)$text);
        $text=iconv('UTF-8','ASCII//TRANSLIT//IGNORE',$text);
        if ($text===false) $text='';
        return str_replace(['\\','(',')'],['\\\\','\\(','\\)'],$text);
    }

    private static function pdf_qr_commands($value,$x,$y,$moduleSize=3,$pageWidth=595) {
        if ($value === '') return '';
        $lib=__DIR__.'/lib/phpqrcode.php';
        if (!file_exists($lib)) return '';
        try {
            require_once $lib;
            if (!class_exists('QRcode')) return '';
            $matrix=QRcode::text((string)$value,false,QR_ECLEVEL_M,1,0);
            if (!is_array($matrix) || !$matrix) return '';
            $rows=count($matrix);
            $cols=strlen((string)$matrix[0]);
            $quiet=4;
            $total=($cols+(2*$quiet))*$moduleSize;
            $x=max(20,($pageWidth-$total)/2);
            $cmd=$x.' '.$y.' '.$total.' '.$total.' re f ';
            for($row=0;$row<$rows;$row++){
                $line=(string)$matrix[$row];
                for($col=0;$col<$cols;$col++){
                    if(isset($line[$col]) && $line[$col]==='1'){
                        $rx=$x+($quiet+$col)*$moduleSize;
                        $ry=$y+($rows-1-$row+$quiet)*$moduleSize;
                        $cmd.=$rx.' '.$ry.' '.$moduleSize.' '.$moduleSize.' re f ';
                    }
                }
            }
            return $cmd;
        } catch (Throwable $e) {
            return '';
        }
    }

    private static function pdf_barcode_commands($value,&$x,&$y,$pageWidth=595) {
        $patterns=[
            '0'=>'101001101101','1'=>'110100101011','2'=>'101100101011','3'=>'110110010101','4'=>'101001101011','5'=>'110100110101','6'=>'101100110101','7'=>'101001011011','8'=>'110100101101','9'=>'101100101101',
            'A'=>'110101001011','B'=>'101101001011','C'=>'110110100101','D'=>'101011001011','E'=>'110101100101','F'=>'101101100101','G'=>'101010011011','H'=>'110101001101','I'=>'101101001101','J'=>'101011001101',
            'K'=>'110101010011','L'=>'101101010011','M'=>'110110101001','N'=>'101011010011','O'=>'110101101001','P'=>'101101101001','Q'=>'101010110011','R'=>'110101011001','S'=>'101101011001','T'=>'101011011001',
            'U'=>'110010101011','V'=>'100110101011','W'=>'110011010101','X'=>'100101101011','Y'=>'110010110101','Z'=>'100110110101','-'=>'100101011011','.'=>'110010101101',' '=>'100110101101','/'=>'100100101001','+'=>'100101001001','%'=>'101001001001','*'=>'100101101101'
        ];
        $order=wc_get_order($order_id);
        if (!$order || !$order->is_paid()) return;
        self::ensure_documents($order);
    }

    private static function ensure_documents($order) {
        if (!$order) return;
        // Documents are rendered dynamically through the protected REST endpoint.
        // Do not write public HTML files into wp-content/uploads.
        // Numbers are idempotent: repeated WooCommerce paid/status hooks must not
        // generate a different invoice or packing number for the same order.
        $id = (string) $order->get_id();
        $invoice = (string) get_post_meta($order->get_id(), '_palma_invoice_number', true);
        $packing = (string) get_post_meta($order->get_id(), '_palma_packing_number', true);
        $year = gmdate('Y');
        if ($invoice === '') {
            $invoice = 'INV-PR-'.$year.'-'.str_pad($id, 8, '0', STR_PAD_LEFT);
            update_post_meta($order->get_id(), '_palma_invoice_number', $invoice);
        }
        if ($packing === '') {
            $packing = 'PK-PR-'.$year.'-'.str_pad($id, 8, '0', STR_PAD_LEFT);
            update_post_meta($order->get_id(), '_palma_packing_number', $packing);
        }
    }

    private static function document_html($order,$type) {
        $invoice=$type==='invoice';
        $title=$invoice?'INVOICE':'PACKING LIST';
        self::ensure_documents($order);
        $number=$invoice?get_post_meta($order->get_id(),'_palma_invoice_number',true):get_post_meta($order->get_id(),'_palma_packing_number',true);
        $company_address='Jl. Rotan Jaya Ds. Teluk Wetan RT07/RW01 Kec. Welahan Kab. Jepara Prov. Jawa Tengah Indonesia';
        $company_phone='08978186933';
        $company_email='hallo.palmarotancraft.id@gmail.com';
        $currency=$order->get_currency();
        $html='<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'.esc_html($title.' '.$number).'</title><style>
        *{box-sizing:border-box}body{font-family:Arial,sans-serif;color:#211a15;margin:0;background:#fff}.page{max-width:900px;margin:0 auto;padding:42px}.head{display:flex;justify-content:space-between;gap:30px;border-bottom:1px solid #d8cbbd;padding-bottom:22px}.brand{font-size:25px;font-weight:700;letter-spacing:.12em}.company{font-size:12px;line-height:1.55;color:#6f6257;max-width:420px}.title{text-align:right}.title h1{margin:0;font-size:28px;letter-spacing:.08em}.title p{margin:7px 0 0;color:#6f6257;font-size:12px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-top:26px}.box h3{font-size:11px;letter-spacing:.12em;margin:0 0 8px}.box p{font-size:13px;line-height:1.55;margin:0}.shipping{margin-top:22px;padding:13px 15px;background:#f8f2e9;border:1px solid #e6dccf;font-size:13px}.shipping b{margin-right:12px}table{width:100%;border-collapse:collapse;margin-top:24px;font-size:12px}th{background:#f5eee4;text-align:left;letter-spacing:.05em}th,td{padding:10px;border-bottom:1px solid #ddd}td.num,th.num{text-align:right}.total{margin-left:auto;width:300px;margin-top:20px}.total div{display:flex;justify-content:space-between;padding:7px 0}.total .grand{font-size:17px;font-weight:700;border-top:1px solid #211a15;margin-top:5px;padding-top:11px}.meta{margin-top:24px;font-size:12px;color:#6f6257}.barcode{margin:28px 0 8px;text-align:center;font-family:monospace;font-size:22px;letter-spacing:3px;border:1px solid #ddd;padding:15px}.footer{margin-top:30px;font-size:11px;color:#6f6257;border-top:1px solid #ddd;padding-top:14px}@media print{body{background:#fff}.page{padding:20px}button{display:none}}@media(max-width:650px){.page{padding:22px}.head,.grid{display:block}.title{text-align:left;margin-top:20px}.total{width:100%}}</style></head><body><main class="page">';
        $html.='<section class="head"><div><div class="brand">PALMA ROTAN</div><div class="company">'.esc_html($company_address).'<br>Phone: '.esc_html($company_phone).' · Email: '.esc_html($company_email).'</div></div><div class="title"><h1>'.esc_html($title).'</h1><p>'.esc_html($number).' · Order #'.esc_html($order->get_order_number()).'</p></div></section>';
        $tracking=(string)$order->get_meta('_palma_tracking_number');
        $trackingUrl=(string)$order->get_meta('_palma_tracking_url');
        $carrier=(string)$order->get_meta('_palma_shipping_carrier');
        if($carrier==='') $carrier=strtoupper($order->get_shipping_country())==='ID'?'J&T':'DHL';
        $trackingLabel=$tracking!==''?esc_html($tracking):'Pending';
        $trackingHtml=$tracking!==''&&$trackingUrl?'<a href="'.esc_url($trackingUrl).'" target="_blank" rel="noopener noreferrer">'.esc_html($tracking).'</a>':$trackingLabel;
        $html.='<section class="grid"><div class="box"><h3>BILL TO</h3><p>'.esc_html($order->get_formatted_billing_full_name()).'<br>'.esc_html($order->get_billing_email()).'<br>'.esc_html($order->get_billing_phone()).'<br>'.esc_html($order->get_billing_address_1()).'<br>'.esc_html($order->get_billing_city()).' '.esc_html($order->get_billing_state()).' '.esc_html($order->get_billing_postcode()).'<br>'.esc_html($order->get_billing_country()).'</p></div><div class="box"><h3>SHIPPING INFORMATION</h3><p>Courier: '.esc_html($carrier).'<br>Method: '.esc_html($order->get_shipping_method()).'<br>Country: '.esc_html($order->get_shipping_country()).'<br>Tracking: '.$trackingHtml.'</p></div></section>';
        $html.='<table><tr><th>PRODUCT</th><th>SKU</th><th class="num">QTY</th><th class="num">'.($invoice?'TOTAL':'WEIGHT').'</th></tr>';
        $gross=0;
        foreach($order->get_items() as $item){
            $p=$item->get_product();
            $qty=(int)$item->get_quantity();
            $weight=(float)($p?$p->get_weight():0)*$qty;
            $gross+=$weight;
            $cell=$invoice?wp_kses_post(wc_price($item->get_total(),['currency'=>$currency])):esc_html(number_format($weight,2).' kg');
            $html.='<tr><td>'.esc_html($item->get_name()).'</td><td>'.esc_html($p?$p->get_sku():'').'</td><td class="num">'.$qty.'</td><td class="num">'.$cell.'</td></tr>';
        }
        $html.='</table>';
        $html.='<div class="shipping"><b>Package Weight</b> Gross Weight: '.esc_html(number_format($gross,2)).' kg · Net Weight: '.esc_html(number_format(max(0,$gross*0.9),2)).' kg</div>';
        $barcodeData=strtoupper($order->get_order_number().'-'.$number.'-'.$order->get_order_key());
        $barcodeData=preg_replace('/[^A-Z0-9 .\\-\\$\\/\\+%]/','',$barcodeData);
        $barcodeJson=wp_json_encode($barcodeData);
        $barcodeScript='';
        $html.='<div class="meta">Order authentication barcode: '.esc_html($barcodeData).'</div>';
        if($invoice){$html.='<div class="total"><div><span>Subtotal</span><span>'.wp_kses_post(wc_price($order->get_subtotal(),['currency'=>$currency])).'</span></div><div><span>Shipping</span><span>'.wp_kses_post(wc_price($order->get_shipping_total(),['currency'=>$currency])).'</span></div><div class="grand"><span>TOTAL</span><span>'.wp_kses_post($order->get_formatted_order_total()).'</span></div></div>';}
        $html.='<div class="footer">PALMA ROTAN · Handcrafted in Indonesia · Print / Save PDF from your browser.</div><p><button onclick="window.print()">Print / Save PDF</button></p></main></body></html>';
        return $html;
    }

    public static function document_pdf(WP_REST_Request $request) {
        $order=wc_get_order((int)$request['id']);
        if(!$order) return self::error('Order tidak ditemukan.',404);
        if(!self::authorize_order($order,$request)) return self::error('Order key tidak valid.',403);
        if(!$order->is_paid()) return self::error('Dokumen tersedia setelah pembayaran berhasil.',403);
        $type=$request['type'];
        $pdf=self::build_pdf($order,$type);
        $number=(string)($type==='invoice'?get_post_meta($order->get_id(),'_palma_invoice_number',true):get_post_meta($order->get_id(),'_palma_packing_number',true));
        $prefix=$type==='invoice'?'PALMA-ROTAN-Invoice-':($type==='packing'?'PALMA-ROTAN-Packing-':'PALMA-ROTAN-Shipping-Label-');
        $name=sanitize_file_name($prefix.$number.'.pdf');
        $response=new WP_REST_Response($pdf,200);
        $response->header('Content-Type','application/pdf');
        $response->header('Content-Disposition','attachment; filename="'.$name.'"');
        $response->header('Cache-Control','private, no-store, max-age=0');
        return self::cors($response);
    }

    public static function document(WP_REST_Request $request) {
        $order=wc_get_order((int)$request['id']);
        if(!$order) return self::error('Order tidak ditemukan.',404);
        if(!self::authorize_order($order, $request)) return self::error('Order key tidak valid.',403);
        if(!$order->is_paid()) return self::error('Dokumen tersedia setelah pembayaran berhasil.',403);
        $type=$request['type'];
        self::ensure_documents($order);
        $html=self::document_html($order,$type);
        $response=new WP_REST_Response($html,200);
        $response->header('Content-Type','text/html; charset=utf-8');
        return self::cors($response);
    }

    public static function admin_menu() {
        add_menu_page('PALMA ROTAN Orders','PALMA Orders','manage_woocommerce','palma-orders',[__CLASS__,'admin_page'],'dashicons-store',56);
    }

    public static function manual_sync_order() {
        if (!current_user_can('manage_woocommerce')) wp_die('Forbidden', '', ['response'=>403]);
        $order_id = absint($_GET['order_id'] ?? 0);
        check_admin_referer('palma_sync_order_'.$order_id);
        $order = wc_get_order($order_id);
        if (!$order) wp_die('Order tidak ditemukan.', '', ['response'=>404]);
        if (!$order->is_paid()) wp_die('Hanya order PAID yang dapat disinkronkan ke PALMA.', '', ['response'=>400]);

        $ok = self::send_order_to_palma($order, false);
        $status = (string) $order->get_meta('_palma_sync_status');
        $flag = $ok && $status === 'SYNCED' ? '1' : '0';
        wp_safe_redirect(admin_url('admin.php?page=palma-orders&sync_order='.$order_id.'&sync_ok='.$flag));
        exit;
    }

    public static function save_tracking() {
        if (!current_user_can('manage_woocommerce')) wp_die('Forbidden', '', ['response'=>403]);
        $order_id=absint($_GET['order_id'] ?? 0);
        check_admin_referer('palma_save_tracking_'.$order_id);
        $order=wc_get_order($order_id);
        if(!$order) wp_die('Order tidak ditemukan.', '', ['response'=>404]);
        $tracking=sanitize_text_field(wp_unslash($_POST['tracking_number'] ?? ''));
        $url=esc_url_raw(wp_unslash($_POST['tracking_url'] ?? ''));
        $carrier=(string)$order->get_meta('_palma_shipping_carrier');
        if($carrier==='') $carrier=strtoupper($order->get_shipping_country())==='ID'?'J&T':'DHL';
        if($tracking!=='' && $url==='' && strtoupper($carrier)==='J&T') $url='https://www.jet.co.id/track?bills='.rawurlencode($tracking);
        $order->update_meta_data('_palma_tracking_number',$tracking);
        $order->update_meta_data('_palma_tracking_url',$url);
        $order->update_meta_data('_palma_shipping_carrier',$carrier);
        $order->save();
        wp_safe_redirect(admin_url('admin.php?page=palma-orders&tracking_saved=1'));
        exit;
    }

    public static function register_settings() {
        register_setting('palma_bridge','palma_allowed_origin',['sanitize_callback'=>'esc_url_raw']);
        register_setting('palma_bridge','palma_payment_gateway_id',['sanitize_callback'=>'sanitize_text_field']);
        register_setting('palma_bridge','palma_usd_idr_rate',['sanitize_callback'=>'floatval']);
        register_setting('palma_bridge','palma_worker_sync_url',['sanitize_callback'=>'esc_url_raw']);
        register_setting('palma_bridge','palma_worker_sync_secret',['sanitize_callback'=>'sanitize_text_field']);
        register_setting('palma_bridge','palma_biteship_api_key',['sanitize_callback'=>'sanitize_text_field']);
        register_setting('palma_bridge','palma_biteship_origin_postal',['sanitize_callback'=>'sanitize_text_field']);
        register_setting('palma_bridge','palma_biteship_domestic_couriers',['sanitize_callback'=>'sanitize_text_field']);
        register_setting('palma_bridge','palma_biteship_export_couriers',['sanitize_callback'=>'sanitize_text_field']);
    }

    public static function admin_page() {
        if (!current_user_can('manage_woocommerce')) return;
        $orders=wc_get_orders(['limit'=>30,'orderby'=>'date','order'=>'DESC']);
        $sync_order_id = absint($_GET['sync_order'] ?? 0);
        $sync_ok = isset($_GET['sync_ok']) ? (string) $_GET['sync_ok'] : '';
        echo '<div class="wrap"><h1>PALMA ROTAN — Orders</h1><p>WooCommerce adalah sumber order utama. Invoice dan Packing List dibuat otomatis setelah pembayaran berhasil.</p>';
        if ($sync_order_id && $sync_ok !== '') {
            $sync_order = wc_get_order($sync_order_id);
            if ($sync_ok === '1') {
                echo '<div class="notice notice-success is-dismissible"><p><strong>PALMA Sync berhasil.</strong> Order #'.esc_html($sync_order_id).' sudah diterima PALMA.</p></div>';
            } else {
                $sync_error = $sync_order ? (string) $sync_order->get_meta('_palma_sync_last_error') : '';
                echo '<div class="notice notice-error"><p><strong>PALMA Sync gagal.</strong> Order #'.esc_html($sync_order_id).' belum masuk PALMA.</p>';
                if ($sync_error !== '') echo '<p><code>'.esc_html($sync_error).'</code></p>';
                echo '</div>';
            }
        }
        echo '<table class="widefat striped"><thead><tr><th>Order</th><th>Customer</th><th>Status</th><th>Payment</th><th>PALMA Sync</th><th>Courier</th><th>Tracking</th><th>Documents</th></tr></thead><tbody>';
        foreach($orders as $o){
            if($o->is_paid())self::ensure_documents($o);
            $key=rawurlencode($o->get_order_key());
            $inv=$o->is_paid()?esc_url(rest_url(self::REST_NS.'/document/invoice/'.$o->get_id()).'?key='.$key):'';
            $pack=$o->is_paid()?esc_url(rest_url(self::REST_NS.'/document/packing/'.$o->get_id()).'?key='.$key):'';
            $tracking=(string)$o->get_meta('_palma_tracking_number');
            $carrier=(string)$o->get_meta('_palma_shipping_carrier');
            $trackUrl=(string)$o->get_meta('_palma_tracking_url');
            $saveUrl=wp_nonce_url(admin_url('admin-post.php?action=palma_save_tracking&order_id='.$o->get_id()),'palma_save_tracking_'.$o->get_id());
            $syncUrl=wp_nonce_url(admin_url('admin-post.php?action=palma_sync_order&order_id='.$o->get_id()),'palma_sync_order_'.$o->get_id());
            $syncStatus=(string)$o->get_meta('_palma_sync_status');
            $label=$o->is_paid() && $tracking!=='' ? esc_url(rest_url(self::REST_NS.'/document-pdf/label/'.$o->get_id()).'?key='.$key) : '';
            $syncError = (string) $o->get_meta('_palma_sync_last_error');
            $syncCell = $o->is_paid() ? ($syncStatus === 'SYNCED' ? '<span style="color:#087f23;font-weight:600">SYNCED</span>' : '<a class="button button-small" href="'.esc_url($syncUrl).'">Sync PALMA</a>'.($syncError !== '' ? '<br><small style="color:#b32d2e">'.esc_html($syncError).'</small>' : '')) : '<span style="color:#777">—</span>';
            echo '<tr><td>#'.esc_html($o->get_order_number()).'</td><td>'.esc_html($o->get_billing_email()).'</td><td>'.esc_html($o->get_status()).'</td><td>'.($o->is_paid()?'PAID':'PENDING').'</td><td>'.$syncCell.'</td><td>'.esc_html($carrier?:'—').'</td><td><form method="post" action="'.esc_url($saveUrl).'"><input type="text" name="tracking_number" value="'.esc_attr($tracking).'" placeholder="Nomor resi" style="width:150px"><input type="url" name="tracking_url" value="'.esc_attr($trackUrl).'" placeholder="URL tracking (opsional untuk J&T)" style="width:180px"><button class="button button-small">Save</button></form></td><td>'.($inv?'<a target="_blank" href="'.$inv.'">Invoice</a> ':'').($pack?'<a target="_blank" href="'.$pack.'">Packing</a> ':'').($label?'<a target="_blank" href="'.$label.'">Label</a>':'').'</td></tr>';
        }
        echo '</tbody></table><h2>Integration</h2><form method="post" action="options.php">';
        settings_fields('palma_bridge');
        echo '<table class="form-table"><tr><th>Cloudflare visitor origin</th><td><input class="regular-text" name="palma_allowed_origin" value="'.esc_attr(get_option('palma_allowed_origin','https://palma-rotan.pages.dev')).'"></td></tr><tr><th>Payment gateway ID</th><td><input class="regular-text" name="palma_payment_gateway_id" value="'.esc_attr(get_option('palma_payment_gateway_id','midtrans')).'"><p class="description">Gunakan ID gateway Midtrans yang benar setelah plugin payment terpasang.</p></td></tr><tr><th>PALMA Worker Sync URL</th><td><input class="regular-text" type="url" name="palma_worker_sync_url" value="'.esc_attr(get_option('palma_worker_sync_url','https://palma-rotan-api-staging.hallo-palmarotancraft-id.workers.dev/api/integrations/woocommerce/order')).'" placeholder="https://palma-rotan-api-staging.hallo-palmarotancraft-id.workers.dev/api/integrations/woocommerce/order"><p class="description">Endpoint Worker untuk menerima order PAID dari WooCommerce.</p></td></tr><tr><th>PALMA Worker Sync Secret</th><td><input class="regular-text" type="password" name="palma_worker_sync_secret" value="'.esc_attr(get_option('palma_worker_sync_secret','')).'" autocomplete="new-password"><p class="description">Harus sama dengan secret Worker. Jangan dibagikan.</p></td></tr><tr><th>USD → IDR rate</th><td><input class="regular-text" type="number" step="0.01" name="palma_usd_idr_rate" value="'.esc_attr(get_option('palma_usd_idr_rate',16000)).'"></td></tr></table>';
        submit_button('Save Settings'); echo '</form></div>';
    }

    private static function error($message,$status) { return self::cors(new WP_Error('palma_error',$message,['status'=>$status])); }
}
add_action('plugins_loaded',['Palma_Rotan_Commerce_Bridge','boot']);
