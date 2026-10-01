<?php
/**
 * Plugin Name: PALMA ROTAN Commerce Bridge
 * Description: WooCommerce order bridge for the PALMA ROTAN Cloudflare visitor site. Keeps WooCommerce as the single order source and exposes a small REST API for products, checkout, payment redirect, invoice and packing documents.
 * Version: 1.0.0
 * Requires Plugins: woocommerce
 */

if (!defined('ABSPATH')) exit;

final class Palma_Rotan_Commerce_Bridge {
    const REST_NS = 'palma/v1';

    public static function boot() {
        add_action('rest_api_init', [__CLASS__, 'routes']);
        add_action('woocommerce_payment_complete', [__CLASS__, 'documents_on_paid']);
        add_action('woocommerce_order_status_processing', [__CLASS__, 'documents_on_paid']);
        add_action('woocommerce_order_status_completed', [__CLASS__, 'documents_on_paid']);
        add_action('admin_menu', [__CLASS__, 'admin_menu']);
        add_action('admin_init', [__CLASS__, 'register_settings']);
    }

    public static function routes() {
        register_rest_route(self::REST_NS, '/products', [
            'methods' => 'GET',
            'permission_callback' => '__return_true',
            'callback' => [__CLASS__, 'products'],
        ]);
        register_rest_route(self::REST_NS, '/order', [
            'methods' => 'POST',
            'permission_callback' => '__return_true',
            'callback' => [__CLASS__, 'create_order'],
        ]);
        register_rest_route(self::REST_NS, '/order/(?P<id>\d+)', [
            'methods' => 'GET',
            'permission_callback' => '__return_true',
            'callback' => [__CLASS__, 'order'],
        ]);
        register_rest_route(self::REST_NS, '/document/(?P<type>invoice|packing)/(?P<id>\d+)', [
            'methods' => 'GET',
            'permission_callback' => '__return_true',
            'callback' => [__CLASS__, 'document'],
        ]);
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
        $out = [];
        foreach ($products as $p) {
            $out[] = [
                'id' => (string) $p->get_id(),
                'sku' => (string) $p->get_sku(),
                'name' => $p->get_name(),
                'price_idr' => (float) get_post_meta($p->get_id(), '_palma_price_idr', true),
                'price_usd' => (float) $p->get_regular_price(),
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

            $shipping_method = sanitize_text_field($body['shippingMethod'] ?? 'Standard');
            $country = strtoupper(sanitize_text_field($shipping['country'] ?? $customer['country'] ?? ''));
            $currency = strtoupper(sanitize_text_field($body['currency'] ?? 'USD')) === 'IDR' ? 'IDR' : 'USD';
            $order->set_currency('IDR');

            foreach ($items as $row) {
                $lookup = sanitize_text_field($row['sku'] ?? $row['productId'] ?? '');
                $product = wc_get_product($lookup);
                if (!$product && $lookup) {
                    $ids = wc_get_products(['sku'=>$lookup,'limit'=>1,'return'=>'ids']);
                    $product = $ids ? wc_get_product($ids[0]) : false;
                }
                if (!$product) throw new Exception('Produk tidak ditemukan: '.$lookup);
                $qty = max(1, (int) ($row['quantity'] ?? 1));
                if ($product->managing_stock() && $product->get_stock_quantity() < $qty) throw new Exception('Stok tidak mencukupi untuk '.$product->get_name());
                $price_idr = (float) get_post_meta($product->get_id(), '_palma_price_idr', true);
                $base_price = (float) $product->get_regular_price();
                $unit_idr = $price_idr > 0 ? $price_idr : ($currency === 'USD' ? $base_price * $rate : $base_price);
                if ($unit_idr <= 0) throw new Exception('Harga produk tidak valid: '.$product->get_name());
                $line = new WC_Order_Item_Product();
                $line->set_product($product);
                $line->set_quantity($qty);
                $line->set_subtotal(round($unit_idr * $qty, 2));
                $line->set_total(round($unit_idr * $qty, 2));
                $order->add_item($line);
            }

            $rate = max(1, (float) get_option('palma_usd_idr_rate', 16000));
            $base = ['ID'=>6,'US'=>45,'CA'=>48,'GB'=>42,'AU'=>38,'SG'=>18,'DE'=>44,'FR'=>44,'NL'=>44];
            $usd = $base[$country] ?? 55;
            if (strtolower($shipping_method) === 'express') $usd *= 1.7;
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
            $order->update_meta_data('_palma_admin_total_idr', (string) round($order->get_total() * ($currency === 'USD' ? $rate : 1)));
            $order->save();

            $gateway_id = sanitize_text_field(get_option('palma_payment_gateway_id', 'midtrans'));
            $payment_url = '';
            $payment_token = '';
            $gateways = WC()->payment_gateways()->payment_gateways();
            if (isset($gateways[$gateway_id]) && $gateways[$gateway_id]->is_available()) {
                $result = $gateways[$gateway_id]->process_payment($order->get_id());
                if (is_array($result)) {
                    $payment_url = esc_url_raw($result['redirect'] ?? '');
                }
            }
            if (!$payment_url) $payment_url = $order->get_checkout_payment_url();

            return self::cors(new WP_REST_Response([
                'ok'=>true,
                'orderId'=>$order->get_id(),
                'orderNumber'=>$order->get_order_number(),
                'status'=>$order->get_status(),
                'currency'=>$currency,
                'paymentCurrency'=>'IDR',
                'subtotal'=>(float) $order->get_subtotal(),
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
        return [
            'orderId'=>$order->get_id(),
            'orderNumber'=>$order->get_order_number(),
            'status'=>$order->get_status(),
            'paymentStatus'=>$order->is_paid() ? 'PAID' : 'PENDING',
            'customer'=>[
                'firstName'=>$order->get_billing_first_name(),
                'email'=>$order->get_billing_email(),
                'phone'=>$order->get_billing_phone(),
                'country'=>$order->get_billing_country(),
            ],
            'items'=>$items,
            'subtotal'=>(float)$order->get_subtotal(),
            'shippingAmount'=>(float)$order->get_shipping_total(),
            'total'=>(float)$order->get_total(),
            'invoiceUrl'=>$order->is_paid() ? rest_url(self::REST_NS.'/document/invoice/'.$order->get_id()).'?key='.rawurlencode($order->get_order_key()) : '',
            'packingUrl'=>$order->is_paid() ? rest_url(self::REST_NS.'/document/packing/'.$order->get_id()).'?key='.rawurlencode($order->get_order_key()) : '',
        ];
    }

    public static function documents_on_paid($order_id) {
        $order=wc_get_order($order_id);
        if (!$order || !$order->is_paid()) return;
        self::ensure_documents($order);
    }

    private static function ensure_documents($order) {
        if (!$order) return;
        // Documents are rendered dynamically through the protected REST endpoint.
        // Do not write public HTML files into wp-content/uploads.
        update_post_meta($order->get_id(),'_palma_invoice_number','INV-PR-'.gmdate('Y').'-'.str_pad((string)$order->get_id(),8,'0',STR_PAD_LEFT));
        update_post_meta($order->get_id(),'_palma_packing_number','PK-PR-'.gmdate('Y').'-'.str_pad((string)$order->get_id(),8,'0',STR_PAD_LEFT));
    }

    private static function document_html($order,$type) {
        $invoice=$type==='invoice';
        $title=$invoice?'INVOICE':'PACKING LIST';
        $number=$invoice?get_post_meta($order->get_id(),'_palma_invoice_number',true):get_post_meta($order->get_id(),'_palma_packing_number',true);
        if (!$number) $number=($invoice?'INV-PR-':'PK-PR-').gmdate('Y').'-'.str_pad((string)$order->get_id(),8,'0',STR_PAD_LEFT);
        $html='<!doctype html><html><head><meta charset="utf-8"><title>'.esc_html($title.' '.$number).'</title><style>body{font-family:Arial,sans-serif;color:#211a15;margin:40px}h1{letter-spacing:.08em}table{width:100%;border-collapse:collapse;margin-top:24px}th,td{padding:9px;border-bottom:1px solid #ddd;text-align:left}.total{text-align:right;font-size:18px;font-weight:700}.muted{color:#6f6257}@media print{button{display:none}}</style></head><body>';
        $html.='<h1>PALMA ROTAN</h1><p class="muted">'.$title.'<br>'.esc_html($number).'<br>Order #'.esc_html($order->get_order_number()).'</p>';
        $html.='<h3>BILL TO</h3><p>'.esc_html($order->get_formatted_billing_full_name()).'<br>'.esc_html($order->get_billing_email()).'<br>'.esc_html($order->get_billing_address_1()).'<br>'.esc_html($order->get_billing_city()).' '.esc_html($order->get_billing_postcode()).'<br>'.esc_html($order->get_billing_country()).'</p>';
        $html.='<table><tr><th>PRODUCT</th><th>SKU</th><th>QTY</th><th>'.($invoice?'TOTAL':'WEIGHT').'</th></tr>';
        foreach($order->get_items() as $item){$p=$item->get_product();$html.='<tr><td>'.esc_html($item->get_name()).'</td><td>'.esc_html($p?$p->get_sku():'').'</td><td>'.(int)$item->get_quantity().'</td><td>'.($invoice?wp_kses_post(wc_price($item->get_total(),['currency'=>$order->get_currency()])):esc_html(($p?$p->get_weight():0).' kg').'</td></tr>'; }
        $html.='</table>';
        if($invoice)$html.='<p class="total">TOTAL: '.wp_kses_post($order->get_formatted_order_total()).'</p>';
        $html.='<p class="muted">Shipping: '.esc_html($order->get_shipping_method()).'</p><p><button onclick="window.print()">Print / Save PDF</button></p></body></html>';
        return $html;
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

    public static function register_settings() {
        register_setting('palma_bridge','palma_allowed_origin',['sanitize_callback'=>'esc_url_raw']);
        register_setting('palma_bridge','palma_payment_gateway_id',['sanitize_callback'=>'sanitize_text_field']);
        register_setting('palma_bridge','palma_usd_idr_rate',['sanitize_callback'=>'floatval']);
    }

    public static function admin_page() {
        if (!current_user_can('manage_woocommerce')) return;
        $orders=wc_get_orders(['limit'=>30,'orderby'=>'date','order'=>'DESC']);
        echo '<div class="wrap"><h1>PALMA ROTAN — Orders</h1><p>WooCommerce adalah sumber order utama. Invoice dan Packing List dibuat otomatis setelah pembayaran berhasil.</p>';
        echo '<table class="widefat striped"><thead><tr><th>Order</th><th>Customer</th><th>Status</th><th>Payment</th><th>Documents</th></tr></thead><tbody>';
        foreach($orders as $o){if($o->is_paid())self::ensure_documents($o);$key=rawurlencode($o->get_order_key());$inv=$o->is_paid()?esc_url(rest_url(self::REST_NS.'/document/invoice/'.$o->get_id()).'?key='.$key):'';$pack=$o->is_paid()?esc_url(rest_url(self::REST_NS.'/document/packing/'.$o->get_id()).'?key='.$key):'';echo '<tr><td>#'.esc_html($o->get_order_number()).'</td><td>'.esc_html($o->get_billing_email()).'</td><td>'.esc_html($o->get_status()).'</td><td>'.($o->is_paid()?'PAID':'PENDING').'</td><td>'.($inv?'<a target="_blank" href="'.$inv.'">Invoice</a> ':'').($pack?'<a target="_blank" href="'.$pack.'">Packing</a>':'').'</td></tr>'; }
        echo '</tbody></table><h2>Integration</h2><form method="post" action="options.php">';
        settings_fields('palma_bridge');
        echo '<table class="form-table"><tr><th>Cloudflare visitor origin</th><td><input class="regular-text" name="palma_allowed_origin" value="'.esc_attr(get_option('palma_allowed_origin','https://palma-rotan.pages.dev')).'"></td></tr><tr><th>Payment gateway ID</th><td><input class="regular-text" name="palma_payment_gateway_id" value="'.esc_attr(get_option('palma_payment_gateway_id','midtrans')).'"><p class="description">Gunakan ID gateway Midtrans yang benar setelah plugin payment terpasang.</p></td></tr><tr><th>USD → IDR rate</th><td><input class="regular-text" type="number" step="0.01" name="palma_usd_idr_rate" value="'.esc_attr(get_option('palma_usd_idr_rate',16000)).'"></td></tr></table>';
        submit_button('Save Settings'); echo '</form></div>';
    }

    private static function error($message,$status) { return self::cors(new WP_Error('palma_error',$message,['status'=>$status])); }
}
add_action('plugins_loaded',['Palma_Rotan_Commerce_Bridge','boot']);
