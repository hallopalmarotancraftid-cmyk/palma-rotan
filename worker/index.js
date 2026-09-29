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
  await env.DB.prepare(`INSERT INTO products(id,sku,type,category,stock,moq,weight_kg,dimensions_cm,image_key,material,hs_code,package_type,units_per_package,packaging_weight_kg,active) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
    ON CONFLICT(id) DO UPDATE SET sku=excluded.sku,type=excluded.type,category=excluded.category,stock=excluded.stock,moq=excluded.moq,weight_kg=excluded.weight_kg,dimensions_cm=excluded.dimensions_cm,image_key=excluded.image_key,material=excluded.material,hs_code=excluded.hs_code,package_type=excluded.package_type,units_per_package=excluded.units_per_package,packaging_weight_kg=excluded.packaging_weight_kg,active=1,updated_at=CURRENT_TIMESTAMP`).bind(productId, body.sku || productId, type, body.category || "home", stock, moq, Number(body.weight) || 0, body.dimensions || "", body.image || null, body.material || "", body.hsCode || "", body.packageType || "", Math.max(1, Number(body.unitsPerPackage) || 1), Math.max(0, Number(body.packagingWeightKg) || 0)).run();;
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

function code128Widths(value){const text=String(value??"").replace(/[^\x20-\x7E]/g,"").slice(0,120);const patterns=["212222","222122","222221","121223","121322","131222","122213","122312","132212","221213","221312","231212","112232","122132","122231","113222","123122","123221","223211","221132","221231","213212","223112","312131","311222","321122","321221","312212","322112","322211","212123","212321","232121","111323","131123","131321","112313","132113","132311","211313","231113","231311","112133","112331","132131","113123","113321","133121","313121","211331","231131","213113","213311","213131","311123","311321","331121","312113","312311","332111","314111","221411","431111","111224","111422","121124","121421","141122","141221","112214","112412","122114","122411","142112","142211","241211","221114","413111","241112","134111","111242","121142","121241","114212","124112","124211","411212","421112","421211","212141","214121","412121","111143","111341","131141","114113","114311","411113","411311","113141","114131","311141","411131","211412","211214","211232","2331112"];const codes=[104];let checksum=104;for(let i=0;i<text.length;i++){const code=text.charCodeAt(i)-32;codes.push(code);checksum+=code*(i+1)}codes.push(checksum%103,106);return codes.map(c=>patterns[c]).join("")}
__name(code128Widths,"code128Widths");
function drawCode128(commands,x,y,maxWidth,height,value,color="0 0 0"){const widths=code128Widths(value),modules=[...widths].reduce((n,c)=>n+Number(c),0),unit=Math.min(1.15,maxWidth/modules);let cursor=x,bar=true;commands.push(color+" rg");for(const ch of widths){const ww=Number(ch)*unit;if(bar)commands.push("q "+cursor+" "+y+" "+ww+" "+height+" re f Q");cursor+=ww;bar=!bar}return cursor}
__name(drawCode128,"drawCode128");
function bytesToBase64(bytes){const arr=new Uint8Array(bytes);let out="";for(let i=0;i<arr.length;i+=0x8000)out+=String.fromCharCode(...arr.subarray(i,Math.min(i+0x8000,arr.length)));return btoa(out)}
__name(bytesToBase64,"bytesToBase64");
function trackingBase(env){return String(env.PUBLIC_SITE_URL||"https://palma-rotan.pages.dev").replace(/\/$/,"")}
__name(trackingBase,"trackingBase");
function trackingUrl(order,env){return trackingBase(env)+"/track/"+encodeURIComponent(order.order_number||"")+"/"+encodeURIComponent(order.auth_code||"")}
__name(trackingUrl,"trackingUrl");
async function ensurePackingAuth(orderId,env){const row=await env.DB.prepare("SELECT * FROM packing_orders WHERE order_id=?").bind(orderId).first();if(!row)return null;if(row.auth_code)return row;const authCode=crypto.randomUUID().replace(/-/g,"")+crypto.randomUUID().replace(/-/g,"").slice(0,16);await env.DB.prepare("UPDATE packing_orders SET auth_code=? WHERE order_id=?").bind(authCode,orderId).run();return {...row,auth_code:authCode}}
__name(ensurePackingAuth,"ensurePackingAuth");
function escEmail(value){return String(value??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}
__name(escEmail,"escEmail");
async function sendOrderDocumentsEmail(order,items,branding,env){const apiKey=String(env.RESEND_API_KEY||"").trim(),to=String(order.email||"").trim();if(!apiKey||!to)return {ok:false,skipped:true,reason:!apiKey?"RESEND_API_KEY belum dikonfigurasi":"email pembeli kosong"};const pack=await ensurePackingAuth(order.id,env);if(!pack)return {ok:false,skipped:true,reason:"packing order belum tersedia"};const enriched={...order,...pack}; enriched.tracking_link=trackingUrl(enriched,env); const track=enriched.tracking_link,brand=String(branding.brand||"PALMA ROTAN"),from=String(env.RESEND_FROM_EMAIL||"").trim();if(!from)return {ok:false,skipped:true,reason:"RESEND_FROM_EMAIL belum dikonfigurasi"};const invoicePdf=makeProfessionalPdf("invoice",enriched,items,branding),packingPdf=makeProfessionalPdf("packing",enriched,items,branding);const html="<div style=\"font-family:Arial,sans-serif;max-width:640px;margin:auto;color:#211a15\"><h2>"+escEmail(brand)+"</h2><p>Pesanan <b>"+escEmail(order.order_number)+"</b> telah menerima pembayaran dan dokumen pesanan tersedia.</p><p>Invoice: <b>"+escEmail(order.invoice_number||"-")+"</b><br>Packing List: <b>"+escEmail(order.packing_number||"-")+"</b></p><p><a href=\""+track+"\" style=\"display:inline-block;padding:12px 18px;background:#211a15;color:#fff;text-decoration:none;border-radius:6px\">Lacak Pengiriman</a></p></div>";const response=await fetch("https://api.resend.com/emails",{method:"POST",headers:{"content-type":"application/json","authorization":"Bearer "+apiKey,"Idempotency-Key":"order-documents-"+order.id},body:JSON.stringify({from,to:[to],subject:brand+" — Dokumen Pesanan "+order.order_number,html,attachments:[{filename:"invoice-"+order.order_number+".pdf",content:bytesToBase64(invoicePdf),content_type:"application/pdf"},{filename:"packing-"+order.order_number+".pdf",content:bytesToBase64(packingPdf),content_type:"application/pdf"}]})});const raw=await response.text();let data={};try{data=raw?JSON.parse(raw):{}}catch(_){data={raw:raw.slice(0,500)}}if(!response.ok)throw new Error(data?.message||data?.error||("Resend HTTP "+response.status));await env.DB.prepare("UPDATE packing_orders SET email_sent_at=CURRENT_TIMESTAMP,email_error=NULL WHERE order_id=?").bind(order.id).run();return {ok:true,id:data?.id||null,trackingUrl:track}}
__name(sendOrderDocumentsEmail,"sendOrderDocumentsEmail");
function shippingCarrierForCountry(country){const c=String(country||"").trim().toLowerCase();return ["indonesia","id","indonesia (id)"].includes(c)?"J&T":"DHL"}
__name(shippingCarrierForCountry,"shippingCarrierForCountry");
function generatedTrackingNumber(orderNumber,carrier){const prefix=carrier==="J&T"?"JNT":"DHL";const clean=String(orderNumber||"").replace(/[^A-Z0-9]/gi,"").toUpperCase().slice(-10);return prefix+clean}
__name(generatedTrackingNumber,"generatedTrackingNumber");
function carrierTrackingUrl(carrier,tracking){return carrier==="J&T"?"https://www.jet.co.id/track":"https://www.dhl.com/global-en/home/tracking.html?tracking-id="+encodeURIComponent(String(tracking||""))}
__name(carrierTrackingUrl,"carrierTrackingUrl");
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
  const country=String(body.shippingAddress?.country||body.customer?.country||"").trim();
  const shippingCarrier=shippingCarrierForCountry(country);
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
        orderId, orderNumber, currency, subtotal, shippingAmount: shipping, shippingCarrier, total, adminTotalIdr,
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
  return json({ orderId, orderNumber, currency, subtotal, shippingAmount: shipping, shippingCarrier, total, adminTotalIdr }, 201, cors(env));
}
__name(createOrder, "createOrder");
async function adminOrders(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, cors(env));
  const orderRows = await env.DB.prepare(`SELECT o.*,c.email,c.first_name,c.last_name,i.invoice_number,pk.packing_number,pk.courier,pk.tracking_number,pk.tracking_url,pk.status AS packing_status,pk.auth_code,pk.email_sent_at,pk.email_error FROM orders o LEFT JOIN customers c ON c.id=o.customer_id LEFT JOIN invoices i ON i.order_id=o.id LEFT JOIN packing_orders pk ON pk.order_id=o.id ORDER BY o.created_at DESC`).all();
  const orders = orderRows.results || [];
  if (!orders.length) return json({ orders: [] }, 200, cors(env));
  const itemRows = await env.DB.prepare(`SELECT oi.*,p.weight_kg,p.dimensions_cm,p.material,p.hs_code,p.package_type,p.units_per_package,p.packaging_weight_kg FROM order_items oi LEFT JOIN products p ON p.id=oi.product_id ORDER BY oi.rowid`).all();
  const paymentRows = await env.DB.prepare(`SELECT order_id,provider,method,provider_transaction_id,amount,currency,status,verified_at,created_at FROM payments ORDER BY created_at DESC`).all();
  const itemsByOrder = new Map();
  for (const item of itemRows.results || []) {
    if (!itemsByOrder.has(item.order_id)) itemsByOrder.set(item.order_id, []);
    itemsByOrder.get(item.order_id).push({id:item.id,product_id:item.product_id,name:item.product_name,product_name:item.product_name,qty:Number(item.quantity)||0,quantity:Number(item.quantity)||0,price:Number(item.unit_price)||0,unit_price:Number(item.unit_price)||0,total_price:Number(item.total_price)||0,currency:item.currency,weight_kg:Number(item.weight_kg)||0,dimensions_cm:item.dimensions_cm||""});
  }
  const paymentByOrder = new Map();
  for (const payment of paymentRows.results || []) if (!paymentByOrder.has(payment.order_id)) paymentByOrder.set(payment.order_id, payment);
  return json({orders:orders.map(order=>{const payment=paymentByOrder.get(order.id)||null;return {...order,items:itemsByOrder.get(order.id)||[],payment_method:payment?.method||null,payment_provider:payment?.provider||null,payment_transaction_id:payment?.provider_transaction_id||null,payment_reference:payment?.provider_transaction_id||null,paid_at:payment?.verified_at||null};})},200,cors(env));
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
    env.DB.prepare(`INSERT INTO packing_orders(id,order_id,packing_number,status,auth_code,courier,tracking_number,tracking_url,created_at) VALUES(?,?,?,'PENDING',?,?,?, ?,CURRENT_TIMESTAMP)`).bind(id("pack"), orderId, packingNo, crypto.randomUUID().replace(/-/g,"")+crypto.randomUUID().replace(/-/g,"").slice(0,16), shippingCarrier, generatedTrackingNumber(orderNumber,shippingCarrier), carrierTrackingUrl(shippingCarrier,generatedTrackingNumber(orderNumber,shippingCarrier))),
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
  const paidOrder=await env.DB.prepare(`SELECT o.*,c.first_name,c.last_name,c.email,c.phone,i.invoice_number,pk.packing_number,pk.auth_code,pk.courier,pk.tracking_number,pk.tracking_url FROM orders o LEFT JOIN customers c ON c.id=o.customer_id LEFT JOIN invoices i ON i.order_id=o.id LEFT JOIN packing_orders pk ON pk.order_id=o.id WHERE o.id=?`).bind(orderId).first();
  if(paidOrder?.email){try{const rows=await env.DB.prepare("SELECT key,value_json FROM site_settings WHERE key IN ('brand','website','whatsapp','email','address','pdfTagline1','pdfTagline2')").all();const branding=Object.fromEntries((rows.results||[]).map(row=>{let v=row.value_json;try{v=JSON.parse(v)}catch(_){}return [row.key,v]}));await sendOrderDocumentsEmail(paidOrder,items,branding,env)}catch(error){console.error("ORDER_DOCUMENT_EMAIL_ERROR",{orderId,message:error?.message||String(error)});await env.DB.prepare("UPDATE packing_orders SET email_error=? WHERE order_id=?").bind(String(error?.message||error).slice(0,500),orderId).run().catch(()=>{})}}
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

async function adminShipping(request,env){const admin=await requireAdmin(request,env);if(!admin)return json({error:"Unauthorized"},401,cors(env));const body=await request.json().catch(()=>({}));if(!body.orderId)return json({error:"orderId wajib diisi"},400,cors(env));const order=await env.DB.prepare("SELECT id,order_number,order_status FROM orders WHERE id=? OR order_number=? LIMIT 1").bind(body.orderId,body.orderId).first();if(!order)return json({error:"Order tidak ditemukan"},404,cors(env));const pack=await ensurePackingAuth(order.id,env);if(!pack)return json({error:"Packing order belum tersedia"},409,cors(env));const status=String(body.status||pack.status||"PENDING").toUpperCase(),allowed=["PENDING","PACKING","READY TO SHIP","SHIPPED","DELIVERED","CANCELLED"];if(!allowed.includes(status))return json({error:"Status pengiriman tidak valid"},400,cors(env));const trackingNumber=String(body.trackingNumber||"").trim()||null,courier=String(body.courier||"").trim().toUpperCase()||null,trackingUrlValue=String(body.trackingUrl||"").trim()||null;
  if(!["J&T","DHL"].includes(courier))return json({error:"Kurir harus J&T untuk domestik atau DHL untuk ekspor"},400,cors(env));
  const country=String((await env.DB.prepare("SELECT json_extract(shipping_address_json,'$.country') AS country FROM orders WHERE id=?").bind(order.id).first())?.country||"").toLowerCase();
  const domestic=["indonesia","id","indonesia (id)"].includes(country);
  if((domestic&&courier!=="J&T")||(!domestic&&courier!=="DHL"))return json({error:domestic?"Order domestik wajib menggunakan J&T":"Order ekspor wajib menggunakan DHL"},400,cors(env));await env.DB.prepare("UPDATE packing_orders SET courier=?,tracking_number=?,tracking_url=?,status=?,shipped_at=CASE WHEN ?='SHIPPED' AND shipped_at IS NULL THEN CURRENT_TIMESTAMP ELSE shipped_at END,delivered_at=CASE WHEN ?='DELIVERED' AND delivered_at IS NULL THEN CURRENT_TIMESTAMP ELSE delivered_at END WHERE order_id=?").bind(courier,trackingNumber,trackingUrlValue,status,status,status,order.id).run();const orderStatus=status==="DELIVERED"?"DELIVERED":status==="SHIPPED"?"SHIPPED":status==="READY TO SHIP"?"READY TO SHIP":status==="PACKING"?"PACKING":order.order_status||"PROCESSING";await env.DB.prepare("UPDATE orders SET order_status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(orderStatus,order.id).run();await env.DB.prepare("INSERT INTO order_status_history(id,order_id,status,note) VALUES(?,?,?,?)").bind(id("hist"),order.id,"Shipping update: "+(courier||"-")+" "+(trackingNumber||"-")).run();await env.DB.prepare("INSERT INTO audit_logs(id,admin_id,action,entity_type,entity_id,metadata_json) VALUES(?,?,?,?,?,?)").bind(id("audit"),admin.id,"UPDATE_SHIPPING","order",order.id,JSON.stringify({courier,trackingNumber,trackingUrl:trackingUrlValue,status})).run();return json({ok:true,orderId:order.id,orderNumber:order.order_number,status,courier,trackingNumber,trackingUrl:trackingUrlValue,trackingLink:trackingUrl({...order,...pack,courier,tracking_number:trackingNumber,tracking_url:trackingUrlValue},env)},200,cors(env))}
__name(adminShipping,"adminShipping");
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
function makeShippingLabelPdf(order, branding = {}) {
  const W=288,H=432,cmd=[]; const brown="0.24 0.12 0.06"; const muted="0.42 0.36 0.30";
  const esc=safePdfText; const text=(x,y,v,s=10,f="F1",c=brown)=>cmd.push(c+" rg","BT",`/${f} ${s} Tf`,`1 0 0 1 ${x} ${y} Tm`,`(${esc(v)}) Tj`,"ET");
  const rect=(x,y,w,h,c="0.96 0.94 0.90")=>cmd.push(`q ${c} rg ${x} ${y} ${w} ${h} re f Q`);
  rect(0,0,W,H);
  text(24,402,String(branding.brand||"PALMA ROTAN"),20,"F2");
  text(24,386,"SHIPPING LABEL",10,"F2",muted);
  text(24,360,"SHIP TO",8,"F2",muted);
  const name=(`${order.first_name||""} ${order.last_name||""}`).trim()||"-"; text(24,344,name.slice(0,34),13,"F2");
  let address="-"; try{const p=JSON.parse(order.shipping_address_json||"{}");address=[p.address,p.city,p.state,p.postalCode,p.country].filter(Boolean).join(", ")||"-"}catch(_){};
  text(24,326,address.slice(0,38),8,"F1");
  if(order.email)text(24,312,String(order.email).slice(0,38),8,"F1",muted);
  if(order.phone)text(24,298,String(order.phone).slice(0,30),8,"F1",muted);
  rect(18,242,252,36,"0.88 0.96 0.90"); text(28,256,"COURIER: "+String(order.courier||"-"),9,"F2"); text(160,256,"PKG: "+String(order.package_count||1),9,"F2");
  text(24,220,"TRACKING NUMBER",8,"F2",muted);
  text(24,202,String(order.tracking_number||"NOT ASSIGNED"),15,"F2");
  const tracking=String(order.tracking_number||order.order_number||""); if(tracking){drawCode128(cmd,24,134,240,52,tracking);text(24,120,tracking.slice(0,38),8,"F2");}
  text(24,96,"ORDER NO.",7,"F2",muted); text(24,82,String(order.order_number||"-"),9,"F1");
  text(150,96,"PACKING LIST",7,"F2",muted); text(150,82,String(order.packing_number||"-"),9,"F1");
  text(24,52,"Scan barcode to identify the shipment.",7,"F1",muted);
  const stream=cmd.join("\n")+"\n"; const objs=["<< /Type /Catalog /Pages 2 0 R >>","<< /Type /Pages /Kids [3 0 R] /Count 1 >>","<< /Type /Page /Parent 2 0 R /MediaBox [0 0 288 432] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>","<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>","<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",`<< /Length ${new TextEncoder().encode(stream).length} >>\nstream\n${stream}endstream`];
  let pdf="%PDF-1.4\n",offs=[0]; for(let i=0;i<objs.length;i++){offs.push(new TextEncoder().encode(pdf).length);pdf+=(i+1)+" 0 obj\n"+objs[i]+"\nendobj\n"} const xref=new TextEncoder().encode(pdf).length; pdf+="xref\n0 "+(objs.length+1)+"\n0000000000 65535 f \n"; for(let i=1;i<offs.length;i++)pdf+=String(offs[i]).padStart(10,"0")+" 00000 n \n"; pdf+="trailer\n<< /Size "+(objs.length+1)+" /Root 1 0 R >>\nstartxref\n"+xref+"\n%%EOF"; return new TextEncoder().encode(pdf);
}
__name(makeShippingLabelPdf,"makeShippingLabelPdf");
function makeProfessionalPdf(type, order, items, branding = {}) {
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
  const brand = String(branding.brand || "PALMA ROTAN").trim() || "PALMA ROTAN";
  const brandWords = brand.split(/\s+/);
  const brandLine1 = brandWords.slice(0, Math.max(1, Math.ceil(brandWords.length / 2))).join(" ");
  const brandLine2 = brandWords.slice(Math.max(1, Math.ceil(brandWords.length / 2))).join(" ");
  const tagline1 = String(branding.pdfTagline1 || "NATURAL CRAFT");
  const tagline2 = String(branding.pdfTagline2 || "TIMELESS BEAUTY");
  const website = String(branding.website || "palmarotancraft.id");
  const phone = String(branding.whatsapp || "08978186933");
  const address = String(branding.address || "Jl. Rotan Jaya, Ds. Teluk Wetan, RT 07/RW 01, Kec. Welahan, Kab. Jepara, Prov. Jawa Tengah, Indonesia");
  palmLogo(M, 760, 0.62);
  text(88, 795, brandLine1.slice(0, 18), 25, "F2");
  if (brandLine2) text(88, 770, brandLine2.slice(0, 18), 25, "F2");
  line(205, 772, 205, 808, 0.8, tan);
  text(220, 797, tagline1.slice(0, 24), 8, "F2", muted);
  text(220, 783, tagline2.slice(0, 24), 8, "F1", muted);
  text(410, 800, website.slice(0, 30), 7, "F1", muted);
  if (phone) text(410, 785, "WhatsApp: "+phone.slice(0, 20), 7, "F1", muted);
  const email = String(branding.email || "hallo.palmarotancraft.id@gmail.com");
  if (email) text(410, 770, email.slice(0, 30), 7, "F1", muted);
  if (address) text(220, 758, address.slice(0, 54), 6.5, "F1", muted);
  line(M, 748, W-M, 748, 1.2, brown);

  // Document title and metadata.
  text(M, 710, type === "invoice" ? "INVOICE" : "PACKING LIST", 25, "F3");
  text(M, 690, type === "invoice" ? "Commercial invoice" : "Shipment packing document", 9, "F1", muted);
  const docNo = type === "invoice" ? (order.invoice_number || "-") : (order.packing_number || "-");
  text(350, 714, type === "invoice" ? "Invoice No." : "Packing List No.", 8, "F2", muted);
  text(430, 714, docNo, 8, "F1");
  text(350, 696, "Order No.", 8, "F2", muted);
  text(430, 696, order.order_number || "-", 8, "F1");
  text(350, 678, "Date", 8, "F2", muted);
  text(430, 678, String(order.created_at || "-").replace("T"," ").slice(0,19), 8, "F1");

  // Customer / destination cards.
  roundRect(M, 595, 245, 61, false);
  roundRect(308, 595, 245, 61, false);
  text(54, 638, "BILL TO", 8, "F2", muted);
  text(54, 621, (`${order.first_name || ""} ${order.last_name || ""}`.trim() || "-").slice(0,36), 10, "F2");
  text(54, 606, "Email: " + (order.email || "-"), 7.5, "F1", muted);
  text(320, 638, "SHIPMENT", 8, "F2", muted);
  let addressText = "-";
  try {
    const parsedAddress = JSON.parse(order.shipping_address_json || "{}");
    addressText = [parsedAddress.address,parsedAddress.city,parsedAddress.state,parsedAddress.postalCode,parsedAddress.country].filter(Boolean).join(", ") || "-";
  } catch (_) {
    addressText = String(order.shipping_address_json || "-");
  }
  const addressLines = wrap(addressText,31);
  text(320,621,"Address: "+addressLines[0],8,"F1");
  if(addressLines[1]) text(320,606,addressLines[1],7.5,"F1",muted);

  if(type === "packing"){
    roundRect(M, 550, 250, 27, true, "0.88 0.96 0.90");
    text(55, 559, "TRACKING NO.: " + String(order.tracking_number || "NOT ASSIGNED").slice(0, 31), 8, "F2", brown);
    if(order.courier) text(55, 544, "COURIER: " + String(order.courier).slice(0, 36), 7.5, "F1", muted);
  }
  if(type === "invoice"){
    roundRect(M, 550, 118, 27, true, "0.88 0.96 0.90");
    text(55, 559, "PAYMENT: " + String(order.payment_status || "PENDING"), 8, "F2", brown);
    roundRect(174, 550, 113, 27, true, "0.94 0.90 0.84");
    text(182, 559, "CURRENCY: " + String(order.original_currency || "USD"), 8, "F2", brown);
  } else {
    roundRect(M, 550, 118, 27, true, "0.94 0.90 0.84");
    text(55, 559, "PACKAGES: " + String(order.package_count || 1), 8, "F2", brown);
    roundRect(174, 550, 113, 27, true, "0.94 0.90 0.84");
    text(182, 559, "STATUS: " + String(order.packing_status || "PENDING"), 8, "F2", brown);
  }

  // Table.
  let y=520;
  const cols = type === "invoice"
    ? [M,70,350,415,490,W-M]
    : [M,70,350,405,465,525,W-M];
  rect(M,y-24,W-2*M,24,true,"0.90 0.85 0.77");
  if(type === "invoice"){
    text(49,y-16,"NO",7.5,"F2");
    text(82,y-16,"PRODUCT / DESCRIPTION",7.5,"F2");
    text(365,y-16,"QTY",7.5,"F2");
    text(423,y-16,"UNIT PRICE",7.5,"F2");
    text(497,y-16,"AMOUNT",7.5,"F2");
  } else {
    text(49,y-16,"NO",7.5,"F2");
    text(82,y-16,"PRODUCT / DESCRIPTION",7.5,"F2");
    text(363,y-16,"QTY",7.5,"F2");
    text(417,y-16,"NET WT.",7.5,"F2");
    text(477,y-16,"DIMENSIONS",7.5,"F2");
    text(535,y-16,"MATERIAL",7.5,"F2");
  }
  y-=24;
  items.forEach((item,index)=>{
    const name=wrap(item.product_name || "Product", type==="invoice"?35:30);
    const rowH=Math.max(38,name.length*10+14);
    line(M,y-rowH,W-M,y-rowH,0.45,tan);
    text(50,y-18,String(index+1),8,"F1");
    let yy=y-13;
    for(const n of name.slice(0,3)){ text(82,yy,n,8,"F1"); yy-=10; }
    if(type==="packing" && item.sku) { text(82,yy,"SKU: "+item.sku,6.8,"F1",muted); yy-=9; if(item.hs_code) { text(82,yy,"HS: "+item.hs_code,6.8,"F1",muted); yy-=9; } }
    text(type==="invoice"?365:363,y-18,String(item.quantity || 0),8,"F1");
    if(type==="invoice"){
      text(423,y-18,money(item.unit_price,item.currency),7.2,"F1");
      text(497,y-18,money(item.total_price,item.currency),7.2,"F1");
    } else {
      text(417,y-18,Number(item.weight_kg||0).toFixed(1)+" kg",7.2,"F1");
      text(477,y-18, item.dimensions_cm || "-",6.8,"F1");
      text(535,y-18,item.material || "Rattan",6.2,"F1");
    }
    y-=rowH;
  });

  if(type==="invoice"){
    const subtotal=Number(order.original_amount)||0, shipping=Number(order.shipping_amount)||0, total=Number(order.total_amount)||0, cur=order.original_currency||"USD";
    const sx=350; y=Math.max(y-8,245);
    text(sx,y,"Subtotal",8.5,"F1",muted); text(490,y,money(subtotal,cur),8.5,"F1");
    text(sx,y-18,"Shipping",8.5,"F1",muted); text(490,y-18,money(shipping,cur),8.5,"F1");
    line(sx,y-28,W-M,y-28,0.8,tan);
    roundRect(sx,y-62,W-M-sx,30,true,"0.86 0.78 0.66");
    text(sx+10,y-51,"TOTAL",9,"F2");
    text(482,y-51,money(total,cur),9,"F2");
    text(M,205,"Payment Method",8,"F2",muted);
    text(M,189,"Midtrans / Payment Gateway",8.5,"F1");
  } else {
    const dy=Math.max(y-8,235);
    text(M,dy,"SHIPPING INFORMATION",8,"F2",muted);
    text(M,dy-17,"Courier: " + (order.courier || order.shipping_method || "-"),8,"F1");
    text(M,dy-32,"Tracking No.: " + (order.tracking_number || "-"),8,"F1");
    text(310,dy,"PACKAGE SUMMARY",8,"F2",muted);
    text(310,dy-17,"Packages: " + String(order.package_count || 1),8,"F1");
    text(310,dy-32,"Status: " + String(order.packing_status || "PENDING"),8,"F1");
  }

  if(type==="packing"){
    const packY=Math.max(y-8,235);
    const totalNet=items.reduce((s,it)=>s+(Number(it.weight_kg)||0)*(Number(it.quantity)||0),0);
    const packageWeight=Number(order.packaging_weight_kg)||0;
    const gross=Number(order.gross_weight_kg)||totalNet+packageWeight;
    text(M,packY-50,"Total Net Weight: "+totalNet.toFixed(2)+" kg",8,"F1");
    text(M,packY-65,"Total Gross Weight: "+gross.toFixed(2)+" kg",8,"F1");
    text(310,packY-50,"Package Type: "+String(order.packaging_type||"-"),8,"F1");
    text(310,packY-65,"Dimensions: "+String(order.dimensions_cm||"-"),8,"F1");
  }

  const barcodeValue=String(order.tracking_link || "");
  if(barcodeValue){drawCode128(commands,M,74,W-2*M,42,barcodeValue);text(M,58,"SCAN / AUTHENTICATE ORDER / TRACKING",7,"F2",muted);text(M,46,String(order.order_number||"").slice(0,42),7,"F1",muted)}

  // Footer.
  line(M,92,W-M,92,0.8,tan);
  palmLogo(M, 52, 0.25);
  text(68,67,"Handcrafted Rattan",7,"F2",muted);
  text(68,56,"Natural Materials • Crafted in Indonesia",6.5,"F1",muted);
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
  let ref = String(orderId || "").trim();
  try { ref = decodeURIComponent(ref); } catch (_) {}
  ref = ref.replace(/^#/, "").trim();
  if (!ref) return json({ error: "Order reference wajib diisi" }, 400, cors(env));
  let order = await env.DB.prepare(`SELECT o.*,c.first_name,c.last_name,c.email,c.phone,i.invoice_number,pk.packing_number,pk.courier,pk.tracking_number,pk.tracking_url,pk.status AS packing_status,pk.package_count,pk.gross_weight_kg,pk.net_weight_kg,pk.dimensions_cm,pk.packaging_type,pk.auth_code FROM orders o LEFT JOIN customers c ON c.id=o.customer_id LEFT JOIN invoices i ON i.order_id=o.id LEFT JOIN packing_orders pk ON pk.order_id=o.id WHERE o.id=? OR o.order_number=? OR lower(o.order_number)=lower(?) LIMIT 1`).bind(ref,ref,ref).first();
  if (!order) return json({error:"Order tidak ditemukan",reference:ref},404,cors(env));
  const ensuredPack=await ensurePackingAuth(order.id,env);
  if(ensuredPack)order={...order,...ensuredPack};
  order.tracking_link=trackingUrl(order,env);
  const items = (await env.DB.prepare("SELECT oi.*,p.weight_kg,p.dimensions_cm,p.material,p.hs_code,p.package_type,p.units_per_package,p.packaging_weight_kg FROM order_items oi LEFT JOIN products p ON p.id=oi.product_id WHERE oi.order_id=? ORDER BY oi.rowid").bind(order.id).all()).results || [];
  const brandRows = await env.DB.prepare("SELECT key,value_json FROM site_settings WHERE key IN ('brand','website','whatsapp','email','address','pdfTagline1','pdfTagline2')").all();
  const branding = Object.fromEntries((brandRows.results || []).map((row) => {
    let value = row.value_json;
    try { value = JSON.parse(value); } catch (_) {}
    return [row.key, value];
  }));
  const bytes = type === "label" ? makeShippingLabelPdf(order, branding) : makeProfessionalPdf(type, order, items, branding);
  if (env.MEDIA) {
    const key = `documents/${type}/${order.order_number}.pdf`;
    await env.MEDIA.put(key, bytes, {httpMetadata:{contentType:"application/pdf",cacheControl:"private, no-store"}});
    const table = type === "invoice" ? "invoices" : "packing_orders";
    await env.DB.prepare(`UPDATE ${table} SET pdf_key=? WHERE order_id=?`).bind(key,order.id).run();
  }
  return new Response(bytes,{status:200,headers:{"content-type":"application/pdf","content-disposition":`inline; filename="${type}-${order.order_number}.pdf"`,"cache-control":"private, no-store","access-control-allow-origin":cors(env),"access-control-allow-headers":"content-type, authorization, x-bootstrap-secret"}});
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

async function publicTracking(request,env,orderNumber,authCode){const order=await env.DB.prepare("SELECT o.order_number,o.order_status,o.payment_status,o.created_at,pk.packing_number,pk.courier,pk.tracking_number,pk.tracking_url,pk.status AS shipping_status,pk.shipped_at,pk.delivered_at,pk.auth_code FROM orders o LEFT JOIN packing_orders pk ON pk.order_id=o.id WHERE lower(o.order_number)=lower(?) LIMIT 1").bind(orderNumber).first();if(!order||!order.auth_code||String(order.auth_code)!==String(authCode))return new Response("Tracking link tidak valid atau sudah tidak tersedia.",{status:404,headers:{"content-type":"text/html; charset=utf-8"}});const rows=await env.DB.prepare("SELECT key,value_json FROM site_settings WHERE key IN ('brand','website','whatsapp','email')").all(),b=Object.fromEntries((rows.results||[]).map(row=>{let v=row.value_json;try{v=JSON.parse(v)}catch(_){}return [row.key,v]})),safe=v=>escEmail(v),external=order.tracking_url?String(order.tracking_url):"";const html="<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>"+safe(b.brand||"PALMA ROTAN")+" — Tracking "+safe(order.order_number)+"</title><style>body{margin:0;background:#f5eee4;color:#211a15;font-family:Arial,sans-serif}.wrap{max-width:720px;margin:40px auto;padding:24px}.card{background:#fff;border:1px solid #dccbb6;border-radius:16px;padding:28px;box-shadow:0 12px 30px rgba(33,26,21,.08)}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:22px}.item{border:1px solid #eadfd2;border-radius:10px;padding:14px}.muted{color:#6d6258}.status{font-weight:700}.btn{display:inline-block;margin-top:20px;padding:12px 18px;border-radius:8px;background:#211a15;color:#fff;text-decoration:none}@media(max-width:600px){.wrap{margin:12px auto;padding:12px}.grid{grid-template-columns:1fr}}</style></head><body><div class=\"wrap\"><div class=\"card\"><div class=\"muted\">"+safe(b.brand||"PALMA ROTAN")+"</div><h1>Tracking Pesanan</h1><p class=\"muted\">Order <b>"+safe(order.order_number)+"</b></p><div class=\"grid\"><div class=\"item\"><div class=\"muted\">Status Order</div><div class=\"status\">"+safe(order.order_status||"PROCESSING")+"</div></div><div class=\"item\"><div class=\"muted\">Status Pengiriman</div><div class=\"status\">"+safe(order.shipping_status||"PENDING")+"</div></div><div class=\"item\"><div class=\"muted\">Kurir</div><div class=\"status\">"+safe(order.courier||"Belum ditentukan")+"</div></div><div class=\"item\"><div class=\"muted\">Nomor Resi</div><div class=\"status\">"+safe(order.tracking_number||"Belum tersedia")+"</div></div><div class=\"item\"><div class=\"muted\">Packing List</div><div class=\"status\">"+safe(order.packing_number||"-")+"</div></div><div class=\"item\"><div class=\"muted\">Pembayaran</div><div class=\"status\">"+safe(order.payment_status||"PENDING")+"</div></div></div>"+(external?"<a class=\"btn\" href=\""+safe(external)+"\" target=\"_blank\" rel=\"noopener\">Buka Tracking Kurir</a>":"")+"<p class=\"muted\" style=\"margin-top:26px;font-size:12px\">Halaman ini menggunakan link autentikasi unik untuk pesanan.</p></div></div></body></html>";return new Response(html,{status:200,headers:{"content-type":"text/html; charset=utf-8","cache-control":"private, no-store"}})}
__name(publicTracking,"publicTracking");
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
    if (url.pathname === "/api/admin/shipping" && request.method === "POST") return adminShipping(request, env);
    const trackMatch = url.pathname.match(/^\/track\/([^/]+)\/([^/]+)$/);
    if (trackMatch && request.method === "GET") return publicTracking(request, env, decodeURIComponent(trackMatch[1]), decodeURIComponent(trackMatch[2]));
    if (url.pathname === "/api/admin/products" && ["GET", "POST", "PUT", "PATCH"].includes(request.method)) return adminProducts(request, env);
    if (url.pathname === "/api/payment/webhook" && request.method === "POST") return paymentWebhook(request, env);
    if (url.pathname === "/api/admin/payments/verify" && request.method === "POST") return adminVerifyPayment(request, env);
    if (url.pathname === "/api/admin/settings" && ["GET", "PATCH", "PUT"].includes(request.method)) return adminSettings(request, env);
    if (url.pathname === "/api/admin/media" && ["GET", "POST", "DELETE"].includes(request.method)) return adminMedia(request, env);
    const invoiceMatch = url.pathname.match(/^\/api\/admin\/documents\/(invoice|packing|label)\/([^/]+)$/);
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