var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.js
var cors = /* @__PURE__ */ __name((env) => env.ALLOWED_ORIGIN || "*", "cors");
var json = /* @__PURE__ */ __name((data, status = 200, origin = "*") => new Response(JSON.stringify(data), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "access-control-allow-origin": origin,
    "access-control-allow-headers": "content-type, authorization, x-bootstrap-secret",
    "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS"
  }
}), "json");
var id = /* @__PURE__ */ __name((prefix = "id") => `${prefix}_${crypto.randomUUID()}`, "id");
var tokenFrom = /* @__PURE__ */ __name((request) => (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim(), "tokenFrom");
var hex = /* @__PURE__ */ __name((bytes) => [...new Uint8Array(bytes)].map((x) => x.toString(16).padStart(2, "0")).join(""), "hex");
var fromHex = /* @__PURE__ */ __name((s) => new Uint8Array((s.match(/.{1,2}/g) || []).map((x) => parseInt(x, 16))), "fromHex");
async function sha256(value) {
  return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}
__name(sha256, "sha256");
async function pbkdf2(password, saltHex, iterations = 1e5) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: fromHex(saltHex), iterations, hash: "SHA-256" }, key, 256);
  return hex(bits);
}
__name(pbkdf2, "pbkdf2");
async function passwordHash(password, pepper) {
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
  const iterations = 1e5;
  const digest = await pbkdf2(`${pepper}:${password}`, salt, iterations);
  return `pbkdf2$${iterations}$${salt}$${digest}`;
}
__name(passwordHash, "passwordHash");
async function passwordVerify(password, stored, pepper) {
  const [kind, it, salt, digest] = String(stored || "").split("$");
  if (kind !== "pbkdf2" || !it || !salt || !digest) return false;
  const actual = await pbkdf2(`${pepper}:${password}`, salt, Number(it));
  return actual === digest;
}
__name(passwordVerify, "passwordVerify");
function base64(value) {
  return btoa(value);
}
__name(base64, "base64");
async function sha512(value) {
  return hex(await crypto.subtle.digest("SHA-512", new TextEncoder().encode(value)));
}
__name(sha512, "sha512");
function midtransAuth(serverKey) {
  return `Basic ${base64(`${serverKey}:`)}`;
}
__name(midtransAuth, "midtransAuth");
function parseSettingNumber(value, fallback) {
  try {
    const parsed = JSON.parse(String(value ?? ""));
    const n = Number(parsed);
    return Number.isFinite(n) ? n : fallback;
  } catch {
    const n = Number(value);
    return Number.isFinite(n) ? n : fallback;
  }
}
__name(parseSettingNumber, "parseSettingNumber");
async function createMidtransSnap(order, customer, env) {
  const serverKey = String(env.MIDTRANS_SERVER_KEY || "").trim();
  if (!serverKey) {
    const error = new Error("MIDTRANS_SERVER_KEY belum dikonfigurasi");
    error.code = "MIDTRANS_CONFIG";
    throw error;
  }
  const production = String(env.MIDTRANS_IS_PRODUCTION || "false").toLowerCase() === "true";
  const endpoint = production
    ? "https://app.midtrans.com/snap/v1/transactions"
    : "https://app.sandbox.midtrans.com/snap/v1/transactions";
  const grossAmount = Math.round(Number(order.admin_total_idr));
  if (!Number.isInteger(grossAmount) || grossAmount <= 0) {
    const error = new Error("Total IDR untuk Midtrans tidak valid");
    error.code = "MIDTRANS_AMOUNT";
    throw error;
  }
  const payload = {
    transaction_details: { order_id: order.order_number, gross_amount: grossAmount },
    customer_details: {
      first_name: String(customer?.firstName || ""),
      last_name: String(customer?.lastName || ""),
      email: String(customer?.email || ""),
      phone: String(customer?.phone || "")
    }
  };
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "accept": "application/json",
      "content-type": "application/json",
      "authorization": midtransAuth(serverKey)
    },
    body: JSON.stringify(payload)
  });
  const raw = await response.text();
  let data = {};
  try { data = raw ? JSON.parse(raw) : {}; } catch { data = { raw: raw.slice(0, 500) }; }
  if (!response.ok) {
    const messages = Array.isArray(data.error_messages) ? data.error_messages.join("; ") : "";
    const error = new Error(messages || `Midtrans HTTP ${response.status}`);
    error.code = "MIDTRANS_API";
    error.providerStatus = response.status;
    error.providerBody = data;
    throw error;
  }
  if (!data.redirect_url || !data.token) {
    const error = new Error("Midtrans tidak mengembalikan token/redirect_url");
    error.code = "MIDTRANS_RESPONSE";
    error.providerStatus = response.status;
    throw error;
  }
  return { token: data.token, redirect_url: data.redirect_url };
}
__name(createMidtransSnap, "createMidtransSnap");
async function requireAdmin(request, env) {
  const token = tokenFrom(request);
  if (!token) return null;
  const tokenHash = await sha256(token);
  return env.DB.prepare(`SELECT a.id,a.email,a.role FROM admin_sessions s JOIN admin_users a ON a.id=s.admin_id WHERE s.token_hash=? AND a.active=1 AND s.expires_at > datetime('now')`).bind(tokenHash).first();
}
__name(requireAdmin, "requireAdmin");
async function login(request, env) {
  const body = await request.json();
  if (!body.email || !body.password) return json({ error: "Email dan password wajib diisi" }, 400, cors(env));
  const user = await env.DB.prepare("SELECT * FROM admin_users WHERE email=? AND active=1").bind(body.email.toLowerCase().trim()).first();
  if (!user || !await passwordVerify(body.password, user.password_hash, env.AUTH_PEPPER || "")) return json({ error: "Kredensial tidak valid" }, 401, cors(env));
  const rawToken = `${crypto.randomUUID()}${crypto.randomUUID()}`;
  await env.DB.prepare(`INSERT INTO admin_sessions(id,admin_id,token_hash,expires_at) VALUES(?,?,?,datetime('now','+8 hours'))`).bind(id("sess"), user.id, await sha256(rawToken)).run();
  return json({ token: rawToken, admin: { id: user.id, email: user.email, role: user.role } }, 200, cors(env));
}
__name(login, "login");
async function bootstrap(request, env) {
  if (!env.BOOTSTRAP_SECRET || request.headers.get("x-bootstrap-secret") !== env.BOOTSTRAP_SECRET) return json({ error: "Unauthorized" }, 401, cors(env));
  const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM admin_users").first();
  if (Number(count?.n) > 0) return json({ error: "Admin sudah pernah dibuat" }, 409, cors(env));
  const body = await request.json();
  if (!body.email || !body.password || String(body.password).length < 12) return json({ error: "Email dan password minimal 12 karakter wajib diisi" }, 400, cors(env));
  const adminId = id("adm");
  await env.DB.prepare("INSERT INTO admin_users(id,email,password_hash,role) VALUES(?,?,?,?)").bind(adminId, body.email.toLowerCase().trim(), await passwordHash(body.password, env.AUTH_PEPPER || ""), body.role || "super_admin").run();
  return json({ ok: true, id: adminId, email: body.email.toLowerCase().trim() }, 201, cors(env));
}
__name(bootstrap, "bootstrap");
async function products(request, env) {
  const rows = await env.DB.prepare(`SELECT p.*,MAX(CASE WHEN pp.currency='IDR' THEN pp.amount END) price_idr,MAX(CASE WHEN pp.currency='USD' THEN pp.amount END) price_usd,MAX(CASE WHEN pt.language='en' THEN pt.name END) name_en,MAX(CASE WHEN pt.language='id' THEN pt.name END) name_id,MAX(CASE WHEN pt.language='en' THEN pt.description END) description_en,MAX(CASE WHEN pt.language='id' THEN pt.description END) description_id FROM products p LEFT JOIN product_prices pp ON pp.product_id=p.id LEFT JOIN product_translations pt ON pt.product_id=p.id WHERE p.active=1 GROUP BY p.id ORDER BY p.created_at DESC`).all();
  return json({ products: rows.results || [] }, 200, cors(env));
}
__name(products, "products");
async function adminProducts(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, cors(env));
  if (request.method === "GET") return products(request, env);
  const body = await request.json();
  const productId = body.id || id("prd");
  const type = ["retail", "custom", "wholesale", "oem"].includes(body.type) ? body.type : "retail";
  const moq = type === "retail" ? 1 : Math.max(1, Number(body.moq) || 1);
  const stock = Math.max(0, Number(body.stock) || 0);
  await env.DB.prepare(`INSERT INTO products(id,sku,type,category,stock,moq,weight_kg,dimensions_cm,image_key,active) VALUES(?,?,?,?,?,?,?,?,?,1)
    ON CONFLICT(id) DO UPDATE SET sku=excluded.sku,type=excluded.type,category=excluded.category,stock=excluded.stock,moq=excluded.moq,weight_kg=excluded.weight_kg,dimensions_cm=excluded.dimensions_cm,image_key=excluded.image_key,active=1,updated_at=CURRENT_TIMESTAMP`).bind(productId, body.sku || productId, type, body.category || "home", stock, moq, Number(body.weight) || 0, body.dimensions || "", body.image || null).run();
  for (const lang of ["en", "id"]) {
    const name = lang === "en" ? body.nameEN || body.name || "Untitled Product" : body.nameID || body.name || "Produk Tanpa Nama";
    const desc = lang === "en" ? body.descriptionEN || body.description || "" : body.descriptionID || body.description || "";
    await env.DB.prepare(`INSERT INTO product_translations(product_id,language,name,description) VALUES(?,?,?,?) ON CONFLICT(product_id,language) DO UPDATE SET name=excluded.name,description=excluded.description`).bind(productId, lang, name, desc).run();
  }
  for (const [currency, amount] of [["IDR", body.priceIDR], ["USD", body.priceUSD]]) {
    if (amount !== null && amount !== void 0 && amount !== "") await env.DB.prepare(`INSERT INTO product_prices(product_id,currency,amount) VALUES(?,?,?) ON CONFLICT(product_id,currency) DO UPDATE SET amount=excluded.amount`).bind(productId, currency, Math.max(0, Number(amount) || 0)).run();
  }
  await env.DB.prepare("INSERT INTO audit_logs(id,admin_id,action,entity_type,entity_id,metadata_json) VALUES(?,?,?,?,?,?)").bind(id("audit"), admin.id, request.method === "POST" ? "CREATE" : "UPDATE", "product", productId, JSON.stringify({ type, stock })).run();
  return json({ ok: true, id: productId }, 200, cors(env));
}
__name(adminProducts, "adminProducts");
async function createOrder(request, env) {
  const body = await request.json();
  if (!Array.isArray(body.items) || !body.items.length) return json({ error: "Keranjang kosong" }, 400, cors(env));
  const currency = body.currency === "IDR" ? "IDR" : "USD";
  const ids = body.items.map((x) => x.productId);
  if (ids.some((x) => !x)) return json({ error: "Product ID tidak valid" }, 400, cors(env));
  const placeholders = ids.map(() => "?").join(",");
  const result = await env.DB.prepare(`SELECT p.id,p.stock,p.type,p.moq,pt.name,pp.amount FROM products p JOIN product_translations pt ON pt.product_id=p.id AND pt.language=? JOIN product_prices pp ON pp.product_id=p.id AND pp.currency=? WHERE p.id IN (${placeholders}) AND p.active=1`).bind(currency === "IDR" ? "id" : "en", currency, ...ids).all();
  const byId = new Map((result.results || []).map((x) => [x.id, x]));
  let subtotal = 0;
  const items = [];
  for (const item of body.items) {
    const p = byId.get(item.productId), qty = Number(item.quantity);
    if (!p || !Number.isInteger(qty) || qty < 1) return json({ error: "Produk atau quantity tidak valid" }, 400, cors(env));
    if (p.type !== "retail" && qty < Number(p.moq || 1)) return json({ error: `MOQ produk ${p.name} adalah ${p.moq}` }, 400, cors(env));
    if (qty > Number(p.stock)) return json({ error: `Stok ${p.name} tidak mencukupi` }, 409, cors(env));
    const unitPrice = Number(p.amount);
    if (!Number.isFinite(unitPrice) || unitPrice < 0) return json({ error: `Harga produk ${p.name} tidak valid` }, 500, cors(env));
    const lineTotal = unitPrice * qty;
    subtotal += lineTotal;
    items.push({ p, qty, total: lineTotal });
  }
  const shipping = Math.max(0, Number(body.shippingAmount) || 0);
  const orderId = id("ord");
  const orderNumber = `PR-${new Date().getFullYear()}-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const customerEmail = String(body.customer?.email || "").trim().toLowerCase() || null;
  let customerId = null;
  let isNewCustomer = false;
  if (customerEmail) {
    const existingCustomer = await env.DB.prepare("SELECT id FROM customers WHERE lower(email)=? LIMIT 1").bind(customerEmail).first();
    customerId = existingCustomer?.id || null;
  }
  if (!customerId) {
    customerId = id("cus");
    isNewCustomer = true;
  }
  const setting = await env.DB.prepare(`SELECT value_json FROM site_settings WHERE key='usdToIdrRate'`).first();
  const rate = parseSettingNumber(setting?.value_json, 16000);
  const total = subtotal + shipping;
  const adminTotalIdr = Math.round(currency === "USD" ? total * rate : total);
  if (!Number.isFinite(adminTotalIdr) || adminTotalIdr <= 0) return json({ error: "Total order tidak valid" }, 500, cors(env));

  const statements = [];
  if (isNewCustomer) {
    statements.push(
      env.DB.prepare(`INSERT INTO customers(id,email,first_name,last_name,phone,country) VALUES(?,?,?,?,?,?)`).bind(
        customerId, customerEmail, body.customer?.firstName || "", body.customer?.lastName || "",
        body.customer?.phone || "", body.customer?.country || ""
      )
    );
  } else {
    statements.push(
      env.DB.prepare(`UPDATE customers SET first_name=?,last_name=?,phone=?,country=? WHERE id=?`).bind(
        body.customer?.firstName || "", body.customer?.lastName || "",
        body.customer?.phone || "", body.customer?.country || "", customerId
      )
    );
  }
  statements.push(
    env.DB.prepare(`INSERT INTO orders(id,order_number,customer_id,original_currency,original_amount,shipping_amount,total_amount,admin_exchange_rate,admin_total_idr,shipping_method,shipping_address_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(
      orderId, orderNumber, customerId, currency, subtotal, shipping, total, rate, adminTotalIdr,
      body.shippingMethod || "", JSON.stringify(body.shippingAddress || {})
    ),
    ...items.map((i) => env.DB.prepare(`INSERT INTO order_items(id,order_id,product_id,product_name,quantity,unit_price,currency,total_price) VALUES(?,?,?,?,?,?,?,?)`).bind(
      id("item"), orderId, i.p.id, i.p.name, i.qty, i.p.amount, currency, i.total
    )),
    env.DB.prepare(`INSERT INTO order_status_history(id,order_id,status,note) VALUES(?,?,?,?)`).bind(
      id("hist"), orderId, "NEW", "Order dibuat melalui checkout"
    )
  );
  await env.DB.batch(statements);

  const requestedGateway = String(body.paymentGateway || body.paymentMethod || "").toLowerCase();
  const useMidtrans = ["gateway", "midtrans", "snap", "payment gateway"].includes(requestedGateway);
  if (useMidtrans) {
    try {
      const snap = await createMidtransSnap(
        { order_number: orderNumber, admin_total_idr: adminTotalIdr },
        body.customer || {},
        env
      );
      await env.DB.prepare(`UPDATE orders SET payment_url=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(snap.redirect_url, orderId).run();
      return json({
        orderId, orderNumber, currency, subtotal, total, adminTotalIdr,
        paymentUrl: snap.redirect_url, paymentToken: snap.token
      }, 201, cors(env));
    } catch (error) {
      console.error("MIDTRANS_CREATE_ERROR", {
        code: error?.code || "UNKNOWN",
        message: error?.message || String(error),
        providerStatus: error?.providerStatus || null,
        providerBody: error?.providerBody || null,
        orderId, orderNumber
      });
      return json({
        error: error?.message || "Gagal membuat halaman pembayaran Midtrans",
        orderId, orderNumber, paymentStatus: "PENDING"
      }, 502, cors(env));
    }
  }
  return json({ orderId, orderNumber, currency, subtotal, total, adminTotalIdr }, 201, cors(env));
}
__name(createOrder, "createOrder");
async function adminOrders(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, cors(env));
  const rows = await env.DB.prepare(`SELECT o.*,c.email,c.first_name,c.last_name FROM orders o LEFT JOIN customers c ON c.id=o.customer_id ORDER BY o.created_at DESC`).all();
  return json({ orders: rows.results || [] }, 200, cors(env));
}
__name(adminOrders, "adminOrders");
async function hmacHex(secret, value) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}
__name(hmacHex, "hmacHex");
function timingSafeEqualHex(a, b) {
  a = String(a || "").toLowerCase();
  b = String(b || "").toLowerCase();
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
__name(timingSafeEqualHex, "timingSafeEqualHex");
async function markOrderPaid(orderId, payment, env, actor = "system") {
  const order = await env.DB.prepare(`SELECT * FROM orders WHERE id=?`).bind(orderId).first();
  if (!order) return { ok: false, status: 404, error: "Order tidak ditemukan" };
  if (order.payment_status === "PAID") return { ok: true, alreadyPaid: true, order };
  const items = (await env.DB.prepare(`SELECT oi.*,p.stock,p.active FROM order_items oi JOIN products p ON p.id=oi.product_id WHERE oi.order_id=?`).bind(orderId).all()).results || [];
  if (!items.length) return { ok: false, status: 400, error: "Order tidak memiliki item" };

  const provider = String(payment.provider || "manual").toLowerCase();
  const isMidtrans = provider === "midtrans";
  const expectedAmount = isMidtrans ? Math.round(Number(order.admin_total_idr)) : Number(order.total_amount);
  const paymentAmount = Number(payment.amount);
  const paymentCurrency = isMidtrans ? "IDR" : (payment.currency === "IDR" ? "IDR" : "USD");
  if (!Number.isFinite(expectedAmount) || !Number.isFinite(paymentAmount) || Math.round(paymentAmount) !== Math.round(expectedAmount)) {
    return { ok: false, status: 400, error: "Jumlah pembayaran tidak sesuai total order" };
  }
  if (!isMidtrans && paymentCurrency !== order.original_currency) {
    return { ok: false, status: 400, error: "Mata uang pembayaran tidak sesuai order" };
  }

  const paymentId = payment.id || id("pay");
  const invoiceNo = `INV-PR-${new Date().getFullYear()}-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const packingNo = `PK-PR-${new Date().getFullYear()}-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const statements = [
    env.DB.prepare(`INSERT INTO payments(id,order_id,provider,method,provider_transaction_id,amount,currency,status,verified_at) VALUES(?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)`).bind(
      paymentId, orderId, isMidtrans ? "midtrans" : "manual",
      payment.method || (isMidtrans ? "snap" : "bank_transfer"), payment.providerTransactionId || null,
      paymentAmount, paymentCurrency, "PAID"
    ),
    env.DB.prepare(`INSERT INTO products(id,sku,type,stock,moq,active)
      SELECT p.id,p.sku,p.type,p.stock,p.moq,p.active
      FROM products p
      WHERE EXISTS (
        SELECT 1 FROM order_items oi
        JOIN products px ON px.id=oi.product_id
        WHERE oi.order_id=? AND px.stock < oi.quantity
      )
      AND p.id IN (SELECT product_id FROM order_items WHERE order_id=? LIMIT 1)`).bind(orderId, orderId)
  ];
  for (const item of items) {
    statements.push(env.DB.prepare(`UPDATE products SET stock=stock-?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND stock>=?`).bind(item.quantity, item.product_id, item.quantity));
    statements.push(env.DB.prepare(`INSERT INTO stock_movements(id,product_id,order_id,quantity_before,quantity_change,quantity_after,reason,created_at) VALUES(?,?,?,?,?,?,?,CURRENT_TIMESTAMP)`).bind(
      id("mov"), item.product_id, orderId, item.stock, -item.quantity, item.stock - item.quantity, "PAID_ORDER"
    ));
  }
  statements.push(
    env.DB.prepare(`UPDATE orders SET payment_status='PAID',order_status='PROCESSING',updated_at=CURRENT_TIMESTAMP WHERE id=? AND payment_status<>'PAID'`).bind(orderId),
    env.DB.prepare(`INSERT INTO order_status_history(id,order_id,status,note) VALUES(?,?,?,?)`).bind(id("hist"), orderId, "PROCESSING", "Pembayaran terverifikasi; stok dikurangi otomatis"),
    env.DB.prepare(`INSERT INTO invoices(id,order_id,invoice_number,status,created_at) VALUES(?,?,?,'READY',CURRENT_TIMESTAMP)`).bind(id("inv"), orderId, invoiceNo),
    env.DB.prepare(`INSERT INTO packing_orders(id,order_id,packing_number,status,created_at) VALUES(?,?,?,'PENDING',CURRENT_TIMESTAMP)`).bind(id("pack"), orderId, packingNo),
    env.DB.prepare(`INSERT INTO payment_audit(id,order_id,payment_id,actor,action,metadata_json) VALUES(?,?,?,?,?,?)`).bind(
      id("pa"), orderId, paymentId, actor, "PAYMENT_VERIFIED",
      JSON.stringify({ provider: isMidtrans ? "midtrans" : "manual", method: payment.method || null, providerTransactionId: payment.providerTransactionId || null })
    )
  );
  try {
    await env.DB.batch(statements);
  } catch (error) {
    console.error("PAYMENT_BATCH_ROLLBACK", { orderId, message: error?.message || String(error) });
    return { ok: false, status: 409, error: "Stok berubah atau transaksi pembayaran tidak dapat diproses" };
  }
  return { ok: true, alreadyPaid: false, invoiceNo, packingNo };
}
__name(markOrderPaid, "markOrderPaid");
async function adminVerifyPayment(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, cors(env));
  const body = await request.json();
  if (!body.orderId) return json({ error: "orderId wajib diisi" }, 400, cors(env));
  const order = await env.DB.prepare(`SELECT id,payment_status,order_status FROM orders WHERE id=?`).bind(body.orderId).first();
  if (!order) return json({ error: "Order tidak ditemukan" }, 404, cors(env));

  if (String(body.status || "").toUpperCase() === "REJECTED") {
    if (order.payment_status === "PAID") return json({ error: "Pembayaran yang sudah PAID tidak dapat ditolak" }, 409, cors(env));
    const reason = String(body.reason || "Pembayaran ditolak");
    await env.DB.batch([
      env.DB.prepare(`UPDATE orders SET payment_status='REJECTED',updated_at=CURRENT_TIMESTAMP WHERE id=? AND payment_status<>'PAID'`).bind(body.orderId),
      env.DB.prepare(`INSERT INTO order_status_history(id,order_id,status,note) VALUES(?,?,?,?)`).bind(id("hist"), body.orderId, "REJECTED", reason),
      env.DB.prepare(`INSERT INTO audit_logs(id,admin_id,action,entity_type,entity_id,metadata_json) VALUES(?,?,?,?,?,?)`).bind(
        id("audit"), admin.id, "REJECT_PAYMENT", "order", body.orderId, JSON.stringify({ reason })
      )
    ]);
    return json({ ok: true, status: "REJECTED" }, 200, cors(env));
  }

  const result = await markOrderPaid(body.orderId, {
    amount: body.amount, currency: body.currency, provider: "manual",
    method: body.method || "bank_transfer", providerTransactionId: body.transactionId || null
  }, env, admin.email);
  if (!result.ok) return json({ error: result.error }, result.status || 400, cors(env));

  await env.DB.prepare(`INSERT INTO audit_logs(id,admin_id,action,entity_type,entity_id,metadata_json) VALUES(?,?,?,?,?,?)`).bind(
    id("audit"), admin.id, "VERIFY_PAYMENT", "order", body.orderId,
    JSON.stringify({ transactionId: body.transactionId || null })
  ).run();
  return json(result, 200, cors(env));
}
__name(adminVerifyPayment, "adminVerifyPayment");
async function paymentWebhook(request, env) {
  const serverKey = String(env.MIDTRANS_SERVER_KEY || "").trim();
  if (!serverKey) return json({ error: "MIDTRANS_SERVER_KEY belum dikonfigurasi" }, 503, cors(env));
  const raw = await request.text();
  let body;
  try { body = JSON.parse(raw); } catch { return json({ error: "Payload webhook bukan JSON valid" }, 400, cors(env)); }

  const orderNumber = String(body.order_id || "").trim();
  const statusCode = String(body.status_code || "").trim();
  const grossAmount = String(body.gross_amount || "").trim();
  const signature = String(body.signature_key || "").trim();
  const expected = await sha512(`${orderNumber}${statusCode}${grossAmount}${serverKey}`);
  if (!timingSafeEqualHex(signature, expected)) return json({ error: "Invalid Midtrans signature" }, 401, cors(env));

  const transactionStatus = String(body.transaction_status || "").toLowerCase();
  const transactionId = String(body.transaction_id || "").trim();
  const eventId = await sha256(`${orderNumber}|${transactionId}|${transactionStatus}|${statusCode}`);
  if (await env.DB.prepare(`SELECT id FROM payment_webhooks WHERE event_id=?`).bind(eventId).first()) {
    return json({ ok: true, duplicate: true }, 200, cors(env));
  }

  const order = await env.DB.prepare(`SELECT * FROM orders WHERE order_number=?`).bind(orderNumber).first();
  if (!order) return json({ error: "Order tidak ditemukan" }, 404, cors(env));

  const fraudStatus = String(body.fraud_status || "").toLowerCase();
  const isSuccess = transactionStatus === "settlement" || (transactionStatus === "capture" && fraudStatus === "accept");
  let result = { ok: true, ignored: false };

  if (isSuccess) {
    result = await markOrderPaid(order.id, {
      amount: Math.round(Number(body.gross_amount)), currency: "IDR",
      provider: "midtrans", method: body.payment_type || "snap",
      providerTransactionId: transactionId || null
    }, env, "midtrans_webhook");
    if (!result.ok) return json({ error: result.error }, result.status || 400, cors(env));
  } else {
    const mapped = { pending: "PENDING", deny: "REJECTED", cancel: "CANCELLED", expire: "EXPIRED", failure: "FAILED" }[transactionStatus];
    if (mapped && order.payment_status !== "PAID") {
      await env.DB.batch([
        env.DB.prepare(`UPDATE orders SET payment_status=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND payment_status<>'PAID'`).bind(mapped, order.id),
        env.DB.prepare(`INSERT INTO order_status_history(id,order_id,status,note) VALUES(?,?,?,?)`).bind(id("hist"), order.id, mapped, `Midtrans status: ${transactionStatus}`)
      ]);
    }
    result.ignored = true;
  }

  await env.DB.prepare(`INSERT INTO payment_webhooks(id,provider,event_id,payload_hash) VALUES(?,?,?,?)`).bind(
    id("wh"), "midtrans", eventId, await sha256(raw)
  ).run();

  return json({
    ok: true, orderId: order.id, orderNumber, transactionStatus,
    invoiceNo: result.invoiceNo || null, packingNo: result.packingNo || null
  }, 200, cors(env));
}
__name(paymentWebhook, "paymentWebhook");
function safePdfText(value) {
  return String(value ?? "").replace(/[^\x20-\x7E]/g, "?").replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}
__name(safePdfText, "safePdfText");
function makeProfessionalPdf(type, order, items) {
  const esc = safePdfText;
  const W = 595, H = 842, M = 42;
  const commands = [];
  const brown = "0.24 0.12 0.06";
  const tan = "0.72 0.55 0.35";
  const cream = "0.965 0.945 0.91";
  const muted = "0.42 0.36 0.30";

  const money = (n, currency) => {
    const v = Number(n) || 0;
    return currency === "IDR"
      ? "Rp " + new Intl.NumberFormat("id-ID", { maximumFractionDigits: 0 }).format(v)
      : "$ " + new Intl.NumberFormat("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(v);
  };
  const text = (x, y, value, size = 10, font = "F1", color = brown) => {
    commands.push(color + " rg", "BT", `/${font} ${size} Tf`, `1 0 0 1 ${x} ${y} Tm`, `(${esc(value)}) Tj`, "ET");
  };
  const line = (x1,y1,x2,y2,width=0.7,color=tan) => commands.push(color + " RG", `${width} w`,`${x1} ${y1} m ${x2} ${y2} l S`);
  const rect = (x,y,w,h,fill=false,color=cream) => commands.push(fill ? `q ${color} rg ${x} ${y} ${w} ${h} re f Q` : `q ${tan} RG 0.55 w ${x} ${y} ${w} ${h} re S Q`);
  const roundRect = (x,y,w,h,fill=false,color=cream) => {
    const r=5,k=0.5522848*r;
    const p=[`q ${fill?color+" rg":tan+" RG"} 0.6 w`,
      `${x+r} ${y} m ${x+w-r} ${y} l`,
      `${x+w-k} ${y} ${x+w} ${y+r-k} ${x+w} ${y+r} c`,
      `${x+w} ${y+h-r} l`,
      `${x+w} ${y+h-r+k} ${x+w-k} ${y+h} ${x+w-r} ${y+h} c`,
      `${x+r} ${y+h} l`,
      `${x+r-k} ${y+h} ${x} ${y+h-r+k} ${x} ${y+h-r} c`,
      `${x} ${y+r} l`,
      `${x} ${y+r-k} ${x+r-k} ${y} ${x+r} ${y} c`,
      "S Q"]; 
    if(fill) p[p.length-1]="f Q";
    commands.push(...p);
  };
  const wrap = (value, max=56) => {
    const words=String(value ?? "").replace(/\s+/g," ").trim().split(" ");
    const out=[]; let cur="";
    for(const word of words){ const next=cur?cur+" "+word:word; if(next.length>max&&cur){out.push(cur);cur=word}else cur=next; }
    if(cur) out.push(cur); return out.length?out:["-"];
  };
  const palmLogo = (x,y,scale=1) => {
    commands.push(`${brown} RG ${brown} rg 1.5 w`);
    commands.push(`${x+10*scale} ${y} m ${x+15*scale} ${y+38*scale} ${x+22*scale} ${y+58*scale} ${x+31*scale} ${y+72*scale} c S`);
    commands.push(`${x+10*scale} ${y} m ${x+30*scale} ${y-2*scale} ${x+38*scale} ${y+2*scale} ${x+42*scale} ${y+6*scale} c S`);
    for(const leaf of [[31,72,0],[31,72,45],[31,72,90],[31,72,135],[31,72,180],[31,72,225],[31,72,270]]){
      const a=leaf[2]*Math.PI/180, ex=31+34*Math.cos(a), ey=72+18*Math.sin(a);
      commands.push(`${x+31*scale} ${y+72*scale} m ${x+ex*scale} ${y+ey*scale} l S`);
    }
  };

  // Paper background and top brand band.
  commands.push(`q ${cream} rg 0 0 ${W} ${H} re f Q`);
  commands.push(`q 0.985 0.975 0.95 rg 0 ${H-108} ${W} 108 re f Q`);
  palmLogo(M, 760, 0.62);
  text(88, 795, "PALMA", 25, "F2");
  text(88, 770, "ROTAN", 25, "F2");
  line(205, 772, 205, 808, 0.8, tan);
  text(220, 797, "NATURAL CRAFT", 8, "F2", muted);
  text(220, 783, "TIMELESS BEAUTY", 8, "F1", muted);
  text(410, 800, "palmarotancraft.id", 7, "F1", muted);
  text(410, 785, "+62 812 3456 7890", 7, "F1", muted);
  text(410, 770, "Yogyakarta, Indonesia", 7, "F1", muted);
  line(M, 748, W-M, 748, 1.2, brown);

  // Document title and metadata.
  text(M, 710, type === "invoice" ? "INVOICE" : "PACKING LIST", 25, "F3");
  text(M, 690, type === "invoice" ? "Faktur Pembelian" : "Daftar Kemasan Pengiriman", 9, "F1", muted);
  const docNo = type === "invoice" ? (order.invoice_number || "-") : (order.packing_number || "-");
  text(350, 714, type === "invoice" ? "No. Invoice" : "No. Packing", 8, "F2", muted);
  text(430, 714, docNo, 8, "F1");
  text(350, 696, "No. Order", 8, "F2", muted);
  text(430, 696, order.order_number || "-", 8, "F1");
  text(350, 678, "Tanggal", 8, "F2", muted);
  text(430, 678, String(order.created_at || "-").replace("T"," ").slice(0,19), 8, "F1");

  // Customer / destination cards.
  roundRect(M, 595, 245, 61, false);
  roundRect(308, 595, 245, 61, false);
  text(54, 638, "KEPADA", 8, "F2", muted);
  text(54, 621, (`${order.first_name || ""} ${order.last_name || ""}`.trim() || "-").slice(0,36), 10, "F2");
  text(54, 606, "Email: " + (order.email || "-"), 7.5, "F1", muted);
  text(320, 638, "PENGIRIMAN", 8, "F2", muted);
  const addr = order.shipping_address_json || "-";
  text(320, 621, "Alamat: " + wrap(addr, 31)[0], 8, "F1");
  if(wrap(addr,31)[1]) text(320,606,wrap(addr,31)[1],7.5,"F1",muted);

  if(type === "invoice"){
    roundRect(M, 550, 118, 27, true, "0.88 0.96 0.90");
    text(55, 559, "PEMBAYARAN: " + String(order.payment_status || "PENDING"), 8, "F2", brown);
    roundRect(174, 550, 113, 27, true, "0.94 0.90 0.84");
    text(182, 559, "MATA UANG: " + String(order.original_currency || "USD"), 8, "F2", brown);
  } else {
    roundRect(M, 550, 118, 27, true, "0.94 0.90 0.84");
    text(55, 559, "PAKET: 1", 8, "F2", brown);
    roundRect(174, 550, 113, 27, true, "0.94 0.90 0.84");
    text(182, 559, "STATUS: PENDING", 8, "F2", brown);
  }

  // Table.
  let y=520;
  const cols = type === "invoice"
    ? [M,70,350,415,490,W-M]
    : [M,70,350,405,465,525,W-M];
  rect(M,y-24,W-2*M,24,true,"0.90 0.85 0.77");
  if(type === "invoice"){
    text(49,y-16,"NO",7.5,"F2");
    text(82,y-16,"PRODUK",7.5,"F2");
    text(365,y-16,"QTY",7.5,"F2");
    text(423,y-16,"HARGA",7.5,"F2");
    text(497,y-16,"JUMLAH",7.5,"F2");
  } else {
    text(49,y-16,"NO",7.5,"F2");
    text(82,y-16,"PRODUK",7.5,"F2");
    text(363,y-16,"QTY",7.5,"F2");
    text(417,y-16,"BERAT",7.5,"F2");
    text(477,y-16,"DIMENSI",7.5,"F2");
    text(535,y-16,"KET.",7.5,"F2");
  }
  y-=24;
  items.forEach((item,index)=>{
    const name=wrap(item.product_name || "Product", type==="invoice"?35:30);
    const rowH=Math.max(38,name.length*10+14);
    line(M,y-rowH,W-M,y-rowH,0.45,tan);
    text(50,y-18,String(index+1),8,"F1");
    let yy=y-13;
    for(const n of name.slice(0,3)){ text(82,yy,n,8,"F1"); yy-=10; }
    text(type==="invoice"?365:363,y-18,String(item.quantity || 0),8,"F1");
    if(type==="invoice"){
      text(423,y-18,money(item.unit_price,item.currency),7.2,"F1");
      text(497,y-18,money(item.total_price,item.currency),7.2,"F1");
    } else {
      text(417,y-18,Number(item.weight_kg||0).toFixed(1)+" kg",7.2,"F1");
      text(477,y-18, item.dimensions_cm || "-",6.8,"F1");
      text(535,y-18,"Rattan",6.8,"F1");
    }
    y-=rowH;
  });

  if(type==="invoice"){
    const subtotal=Number(order.original_amount)||0, shipping=Number(order.shipping_amount)||0, total=Number(order.total_amount)||0, cur=order.original_currency||"USD";
    const sx=350; y=Math.max(y-8,245);
    text(sx,y,"Subtotal",8.5,"F1",muted); text(490,y,money(subtotal,cur),8.5,"F1");
    text(sx,y-18,"Pengiriman",8.5,"F1",muted); text(490,y-18,money(shipping,cur),8.5,"F1");
    line(sx,y-28,W-M,y-28,0.8,tan);
    roundRect(sx,y-62,W-M-sx,30,true,"0.86 0.78 0.66");
    text(sx+10,y-51,"TOTAL PEMBAYARAN",9,"F2");
    text(482,y-51,money(total,cur),9,"F2");
    text(M,205,"Metode Pembayaran",8,"F2",muted);
    text(M,189,"Midtrans / Payment Gateway",8.5,"F1");
  } else {
    const dy=Math.max(y-8,235);
    text(M,dy,"INFORMASI PENGIRIMAN",8,"F2",muted);
    text(M,dy-17,"Kurir: " + (order.shipping_method || "-"),8,"F1");
    text(M,dy-32,"No. Resi: -",8,"F1");
    text(310,dy,"RINGKASAN KEMASAN",8,"F2",muted);
    text(310,dy-17,"Jumlah Paket: 1",8,"F1");
    text(310,dy-32,"Status: Packing pending",8,"F1");
  }

  // Footer.
  line(M,92,W-M,92,0.8,tan);
  palmLogo(M, 52, 0.25);
  text(68,67,"Kerajinan Tangan",7,"F2",muted);
  text(68,56,"Bahan Alami • Ramah Lingkungan",6.5,"F1",muted);
  text(390,67,"PALMA ROTAN",8,"F2");
  text(390,54,"Natural Craft • Timeless Beauty",6.5,"F1",muted);

  const stream=commands.join("\n")+"\n";
  const objects=[
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R /F2 5 0 R /F3 6 0 R >> >> /Contents 7 0 R >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Times-Bold >>",
    `<< /Length ${new TextEncoder().encode(stream).length} >>
stream
${stream}endstream`
  ];
  let pdf="%PDF-1.4\n"; const offsets=[0];
  for(let i=0;i<objects.length;i++){offsets.push(new TextEncoder().encode(pdf).length);pdf+=`${i+1} 0 obj\n${objects[i]}\nendobj\n`;}
  const xref=new TextEncoder().encode(pdf).length;
  pdf+=`xref\n0 ${objects.length+1}\n0000000000 65535 f \n`;
  for(let i=1;i<offsets.length;i++) pdf+=String(offsets[i]).padStart(10,"0")+" 00000 n \n";
  pdf+=`trailer\n<< /Size ${objects.length+1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return new TextEncoder().encode(pdf);
}
__name(makeProfessionalPdf, "makeProfessionalPdf");
async function publicMedia(request, env, key) {
  if (!env.MEDIA) return new Response("R2 not configured", { status: 503 });
  if (!key || !key.startsWith("media/")) return new Response("Not found", { status: 404 });
  const object = await env.MEDIA.get(key);
  if (!object) return new Response("Not found", { status: 404 });
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("cache-control", "public, max-age=31536000, immutable");
  return new Response(object.body, { headers });
}
__name(publicMedia, "publicMedia");
async function adminMedia(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, cors(env));
  if (!env.MEDIA) return json({ error: "R2 MEDIA belum dikonfigurasi" }, 503, cors(env));
  if (request.method === "GET") {
    const rows = await env.DB.prepare("SELECT * FROM media ORDER BY created_at DESC").all();
    return json({ media: rows.results || [] }, 200, cors(env));
  }
  if (request.method === "POST") {
    const form = await request.formData();
    const file = form.get("file");
    if (!(file instanceof File)) return json({ error: "File wajib diunggah" }, 400, cors(env));
    if (file.size > 25 * 1024 * 1024) return json({ error: "Ukuran file maksimal 25 MiB" }, 413, cors(env));
    const allowed = /^(image\/(jpeg|png|webp|gif)|application\/pdf)$/i;
    if (!allowed.test(file.type)) return json({ error: "Tipe file tidak didukung" }, 415, cors(env));
    const ext = (file.name.split(".").pop() || "bin").toLowerCase().replace(/[^a-z0-9]/g, "");
    const key = `media/${(/* @__PURE__ */ new Date()).toISOString().slice(0, 10)}/${crypto.randomUUID()}.${ext}`;
    await env.MEDIA.put(key, file.stream(), { httpMetadata: { contentType: file.type, cacheControl: "public, max-age=31536000, immutable" } });
    const mediaId = id("media");
    await env.DB.prepare("INSERT INTO media(id,object_key,filename,mime_type,size_bytes,alt_en,alt_id) VALUES(?,?,?,?,?,?,?)").bind(mediaId, key, file.name, file.type, file.size, form.get("alt_en") || null, form.get("alt_id") || null).run();
    await env.DB.prepare("INSERT INTO audit_logs(id,admin_id,action,entity_type,entity_id,metadata_json) VALUES(?,?,?,?,?,?)").bind(id("audit"), admin.id, "UPLOAD", "media", mediaId, JSON.stringify({ key, filename: file.name, size: file.size })).run();
    const base = env.MEDIA_PUBLIC_BASE_URL || "";
    return json({ ok: true, media: { id: mediaId, key, filename: file.name, mimeType: file.type, size: file.size, url: base ? `${base.replace(/\/$/, "")}/${key}` : null } }, 201, cors(env));
  }
  if (request.method === "DELETE") {
    const body = await request.json().catch(() => ({}));
    const media = await env.DB.prepare("SELECT * FROM media WHERE id=?").bind(body.id || "").first();
    if (!media) return json({ error: "Media tidak ditemukan" }, 404, cors(env));
    await env.MEDIA.delete(media.object_key);
    await env.DB.prepare("DELETE FROM media WHERE id=?").bind(media.id).run();
    await env.DB.prepare("INSERT INTO audit_logs(id,admin_id,action,entity_type,entity_id,metadata_json) VALUES(?,?,?,?,?,?)").bind(id("audit"), admin.id, "DELETE", "media", media.id, JSON.stringify({ key: media.object_key })).run();
    return json({ ok: true }, 200, cors(env));
  }
  return json({ error: "Method not allowed" }, 405, cors(env));
}
__name(adminMedia, "adminMedia");
async function documentPdf(request, env, type, orderId) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, cors(env));
  const order = await env.DB.prepare(`SELECT o.*,c.first_name,c.last_name,c.email,c.phone,i.invoice_number,pk.packing_number FROM orders o LEFT JOIN customers c ON c.id=o.customer_id LEFT JOIN invoices i ON i.order_id=o.id LEFT JOIN packing_orders pk ON pk.order_id=o.id WHERE o.id=? OR o.order_number=?`).bind(orderId, orderId).first();
  if (!order) return json({ error: "Order tidak ditemukan" }, 404, cors(env));
  const items = (await env.DB.prepare("SELECT * FROM order_items WHERE order_id=? ORDER BY rowid").bind(order.id).all()).results || [];
  const bytes = makeProfessionalPdf(type, order, items);
  if (env.MEDIA) {
    const key = `documents/${type}/${order.order_number}.pdf`;
    await env.MEDIA.put(key, bytes, { httpMetadata: { contentType: "application/pdf", cacheControl: "private, no-store" } });
    const table = type === "invoice" ? "invoices" : "packing_orders";
    await env.DB.prepare(`UPDATE ${table} SET pdf_key=? WHERE order_id=?`).bind(key, order.id).run();
  }
  return new Response(bytes, { status: 200, headers: { "content-type": "application/pdf", "content-disposition": `inline; filename="${type}-${order.order_number}.pdf"`, "cache-control": "no-store", "access-control-allow-origin": cors(env) } });
}
__name(documentPdf, "documentPdf");
async function adminSettings(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, cors(env));
  if (request.method === "GET") {
    const rows = await env.DB.prepare("SELECT key,value_json FROM site_settings").all();
    return json({ settings: Object.fromEntries((rows.results || []).map((x) => [x.key, JSON.parse(x.value_json)])) }, 200, cors(env));
  }
  const body = await request.json();
  for (const [key, value] of Object.entries(body)) await env.DB.prepare(`INSERT INTO site_settings(key,value_json) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=CURRENT_TIMESTAMP`).bind(key, JSON.stringify(value)).run();
  await env.DB.prepare("INSERT INTO audit_logs(id,admin_id,action,entity_type,metadata_json) VALUES(?,?,?,?,?)").bind(id("audit"), admin.id, "UPDATE", "site_settings", JSON.stringify(body)).run();
  return json({ ok: true }, 200, cors(env));
}
__name(adminSettings, "adminSettings");
async function publicSettings(request, env) {
  if (request.method !== "GET") {
    return json({ error: "Method not allowed" }, 405, cors(env));
  }

  const rows = await env.DB
    .prepare("SELECT key,value_json FROM site_settings")
    .all();

  return json({
    settings: Object.fromEntries(
      (rows.results || []).map((x) => [
        x.key,
        JSON.parse(x.value_json)
      ])
    )
  }, 200, cors(env));
}

__name(publicSettings, "publicSettings");
var index_default = {
  
  async fetch(request, env) {
  const origin = cors(env);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { "access-control-allow-origin": origin, "access-control-allow-headers": "content-type, authorization, x-bootstrap-secret", "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS" } });
  const url = new URL(request.url);
  try {
    if (url.pathname === "/api/health") return json({ ok: true, environment: env.ENVIRONMENT || "unknown" }, 200, origin);
    if (url.pathname.startsWith("/media/") && request.method === "GET") return publicMedia(request, env, url.pathname.slice("/media/".length));
    if (url.pathname === "/api/auth/login" && request.method === "POST") return login(request, env);
    if (url.pathname === "/api/auth/bootstrap" && request.method === "POST") return bootstrap(request, env);
    if (url.pathname === "/api/products" && request.method === "GET") return products(request, env);
    if (url.pathname === "/api/settings" && request.method === "GET") return publicSettings(request, env);
    if (url.pathname === "/api/orders" && request.method === "POST") return createOrder(request, env);
    if (url.pathname === "/api/admin/orders" && request.method === "GET") return adminOrders(request, env);
    if (url.pathname === "/api/admin/products" && ["GET", "POST", "PUT", "PATCH"].includes(request.method)) return adminProducts(request, env);
    if (url.pathname === "/api/payment/webhook" && request.method === "POST") return paymentWebhook(request, env);
    if (url.pathname === "/api/admin/payments/verify" && request.method === "POST") return adminVerifyPayment(request, env);
    if (url.pathname === "/api/admin/settings" && ["GET", "PATCH", "PUT"].includes(request.method)) return adminSettings(request, env);
    if (url.pathname === "/api/admin/media" && ["GET", "POST", "DELETE"].includes(request.method)) return adminMedia(request, env);
    const invoiceMatch = url.pathname.match(/^\/api\/admin\/documents\/(invoice|packing)\/([^/]+)$/);
    if (invoiceMatch && request.method === "GET") return documentPdf(request, env, invoiceMatch[1], invoiceMatch[2]);
    return json({ error: "Not found" }, 404, origin);
  } catch (error) {
    console.error("WORKER_REQUEST_ERROR", {
      path: url.pathname,
      method: request.method,
      message: error?.message || String(error),
      stack: error?.stack || null
    });
    return json({ error: "Internal server error", requestId: id("req") }, 500, origin);
  }
} };
export {
  index_default as default
};
//# sourceMappingURL=index.js.map