import { deflateSync, inflateSync } from "node:zlib";
var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.js
var BUILD_ID = "2026-10-01-invoice-qr-product-fix-7";
var cors = /* @__PURE__ */ __name((request) => {
  const origin = request?.headers?.get?.("origin") || "";
  const isPagesOrigin = /^https:\/\/([a-z0-9-]+\.)?palma-rotan\.pages\.dev$/i.test(origin);
  const isPalmaDomain = /^https:\/\/([a-z0-9-]+\.)?palmarotancraft\.id$/i.test(origin);
  if (isPagesOrigin || isPalmaDomain || origin === "https://palmarotancraft-staging.pages.dev") return origin;
  return "https://palma-rotan.pages.dev";
}, "cors");
var json = /* @__PURE__ */ __name((data, status = 200, origin = "*") => new Response(JSON.stringify(data), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "access-control-allow-origin": origin,
    "access-control-allow-headers": "content-type, authorization, x-bootstrap-secret",
    "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "vary": "Origin"
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
  if (!body.email || !body.password) return json({ error: "Email dan password wajib diisi" }, 400, cors(request));
  const user = await env.DB.prepare("SELECT * FROM admin_users WHERE email=? AND active=1").bind(body.email.toLowerCase().trim()).first();
  if (!user || !await passwordVerify(body.password, user.password_hash, env.AUTH_PEPPER || "")) return json({ error: "Kredensial tidak valid" }, 401, cors(request));
  const rawToken = `${crypto.randomUUID()}${crypto.randomUUID()}`;
  await env.DB.prepare(`INSERT INTO admin_sessions(id,admin_id,token_hash,expires_at) VALUES(?,?,?,datetime('now','+8 hours'))`).bind(id("sess"), user.id, await sha256(rawToken)).run();
  return json({ token: rawToken, admin: { id: user.id, email: user.email, role: user.role } }, 200, cors(request));
}
__name(login, "login");
async function bootstrap(request, env) {
  if (!env.BOOTSTRAP_SECRET || request.headers.get("x-bootstrap-secret") !== env.BOOTSTRAP_SECRET) return json({ error: "Unauthorized" }, 401, cors(request));
  const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM admin_users").first();
  if (Number(count?.n) > 0) return json({ error: "Admin sudah pernah dibuat" }, 409, cors(request));
  const body = await request.json();
  if (!body.email || !body.password || String(body.password).length < 12) return json({ error: "Email dan password minimal 12 karakter wajib diisi" }, 400, cors(request));
  const adminId = id("adm");
  await env.DB.prepare("INSERT INTO admin_users(id,email,password_hash,role) VALUES(?,?,?,?)").bind(adminId, body.email.toLowerCase().trim(), await passwordHash(body.password, env.AUTH_PEPPER || ""), body.role || "super_admin").run();
  return json({ ok: true, id: adminId, email: body.email.toLowerCase().trim() }, 201, cors(request));
}
__name(bootstrap, "bootstrap");
async function products(request, env) {
  const rows = await env.DB.prepare(`SELECT p.*,MAX(CASE WHEN pp.currency='IDR' THEN pp.amount END) price_idr,MAX(CASE WHEN pp.currency='USD' THEN pp.amount END) price_usd,MAX(CASE WHEN pt.language='en' THEN pt.name END) name_en,MAX(CASE WHEN pt.language='id' THEN pt.name END) name_id,MAX(CASE WHEN pt.language='en' THEN pt.description END) description_en,MAX(CASE WHEN pt.language='id' THEN pt.description END) description_id FROM products p LEFT JOIN product_prices pp ON pp.product_id=p.id LEFT JOIN product_translations pt ON pt.product_id=p.id WHERE p.active=1 GROUP BY p.id ORDER BY p.created_at DESC`).all();
  return json({ products: rows.results || [] }, 200, cors(request));
}
__name(products, "products");
async function adminProducts(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, cors(request));
  // Product editor uses the logistics columns below. Ensure older D1 databases
  // are upgraded before the INSERT/UPDATE instead of failing with "no column".
  await ensureProductLogisticsSchema(env);
  if (request.method === "GET") return products(request, env, true);
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
  return json({ ok: true, id: productId }, 200, cors(request));
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
async function sendOrderDocumentsEmail(order,items,branding,env,idempotencyKey=null){const apiKey=String(env.RESEND_API_KEY||"").trim(),to=String(order.email||"").trim();if(!apiKey||!to)return {ok:false,skipped:true,reason:!apiKey?"RESEND_API_KEY belum dikonfigurasi":"email pembeli kosong"};const pack=await ensurePackingAuth(order.id,env);if(!pack)return {ok:false,skipped:true,reason:"packing order belum tersedia"};const enriched={...order,...pack}; enriched.tracking_link=trackingUrl(enriched,env); const invoiceAuth=await ensureDocumentAuthentication(order.id,"invoice",env),packingAuth=await ensureDocumentAuthentication(order.id,"packing",env); enriched.invoice_document_verification_url=invoiceAuth.verification_url; enriched.packing_document_verification_url=packingAuth.verification_url; const track=enriched.tracking_link,brand=String(branding.brand||"PALMA ROTAN"),from=String(env.RESEND_FROM_EMAIL||"").trim();if(!from)return {ok:false,skipped:true,reason:"RESEND_FROM_EMAIL belum dikonfigurasi"};const invoicePdf=await makeProfessionalPdf("invoice",{...enriched,document_verification_url:enriched.invoice_document_verification_url},items,branding),packingPdf=await makeProfessionalPdf("packing",{...enriched,document_verification_url:enriched.packing_document_verification_url},items,branding);const html="<div style=\"font-family:Arial,sans-serif;max-width:640px;margin:auto;color:#211a15\"><h2>"+escEmail(brand)+"</h2><p>Pesanan <b>"+escEmail(order.order_number)+"</b> siap dikirim dan nomor tracking sudah tersedia.</p><p>Invoice: <b>"+escEmail(order.invoice_number||"-")+"</b><br>Packing List: <b>"+escEmail(order.packing_number||"-")+"</b></p><p><a href=\""+track+"\" style=\"display:inline-block;padding:12px 18px;background:#211a15;color:#fff;text-decoration:none;border-radius:6px\">Lacak Pengiriman</a></p></div>";const response=await fetch("https://api.resend.com/emails",{method:"POST",headers:{"content-type":"application/json","authorization":"Bearer "+apiKey,"Idempotency-Key":String(idempotencyKey||("order-documents-"+order.id))},body:JSON.stringify({from,to:[to],subject:brand+" — Dokumen Pesanan "+order.order_number,html,attachments:[{filename:"invoice-"+order.order_number+".pdf",content:bytesToBase64(invoicePdf),content_type:"application/pdf"},{filename:"packing-"+order.order_number+".pdf",content:bytesToBase64(packingPdf),content_type:"application/pdf"}]})});const raw=await response.text();let data={};try{data=raw?JSON.parse(raw):{}}catch(_){data={raw:raw.slice(0,500)}}if(!response.ok)throw new Error(data?.message||data?.error||("Resend HTTP "+response.status));await env.DB.prepare("UPDATE packing_orders SET email_sent_at=CURRENT_TIMESTAMP,email_error=NULL WHERE order_id=?").bind(order.id).run();return {ok:true,id:data?.id||null,trackingUrl:track}}
__name(sendOrderDocumentsEmail,"sendOrderDocumentsEmail");
function shippingCarrierForCountry(country){const c=String(country||"").trim().toLowerCase();return ["indonesia","id","indonesia (id)"].includes(c)?"J&T":"DHL"}
__name(shippingCarrierForCountry,"shippingCarrierForCountry");
function shippingMode(env){return String(env.SHIPPING_MODE||"SANDBOX").trim().toUpperCase()==="PRODUCTION"?"PRODUCTION":"SANDBOX"}
async function ensureShippingSchema(env){const cols=["courier","tracking_number","tracking_url","shipped_at","delivered_at","auth_code","email_sent_at","email_error","packaging_type","dimensions_cm","packaging_weight_kg"];const info=await env.DB.prepare("PRAGMA table_info(packing_orders)").all();const existing=new Set((info.results||[]).map(x=>x.name));for(const col of cols){if(existing.has(col))continue;try{await env.DB.prepare("ALTER TABLE packing_orders ADD COLUMN "+col+" TEXT").run()}catch(err){if(!/duplicate column name/i.test(String(err?.message||err)))throw err}}await ensureLogisticsEventSchema(env);return true}
async function ensureLogisticsEventSchema(env){await env.DB.prepare(`CREATE TABLE IF NOT EXISTS tracking_events (id TEXT PRIMARY KEY,order_id TEXT NOT NULL,tracking_number TEXT,status TEXT,event_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,location TEXT,description TEXT,source TEXT NOT NULL DEFAULT 'system',raw_payload TEXT)`).run();await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_tracking_events_order_time ON tracking_events(order_id,event_time)").run();await env.DB.prepare(`CREATE TABLE IF NOT EXISTS notification_logs (id TEXT PRIMARY KEY,order_id TEXT NOT NULL,notification_type TEXT NOT NULL,idempotency_key TEXT NOT NULL UNIQUE,status TEXT NOT NULL,provider_id TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,sent_at TEXT,error_message TEXT)`).run();await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_notification_logs_order_type ON notification_logs(order_id,notification_type)").run();return true}
async function sendReadyToShipDocumentsEmail(order,items,branding,env){if(String(order.order_status||"").toUpperCase().replace(/_/g," ")!=="READY TO SHIP"||!String(order.tracking_number||"").trim())return {ok:false,skipped:true,reason:"READY_TO_SHIP dan tracking_number wajib tersedia"};const key="ready-to-ship-documents-"+order.id+"-"+String(order.tracking_number).trim();await ensureLogisticsEventSchema(env);const existing=await env.DB.prepare("SELECT * FROM notification_logs WHERE idempotency_key=?").bind(key).first();if(existing&&existing.status==="SENT")return {ok:true,duplicate:true,id:existing.provider_id||null};if(!existing){try{await env.DB.prepare("INSERT INTO notification_logs(id,order_id,notification_type,idempotency_key,status) VALUES(?,?,?,?,?)").bind(id("notif"),order.id,"READY_TO_SHIP_DOCUMENTS",key,"PENDING").run()}catch(error){if(!/unique|constraint/i.test(String(error?.message||error)))throw error;const concurrent=await env.DB.prepare("SELECT * FROM notification_logs WHERE idempotency_key=?").bind(key).first();if(concurrent?.status==="SENT")return {ok:true,duplicate:true,id:concurrent.provider_id||null}}}try{const result=await sendOrderDocumentsEmail(order,items,branding,env,key);if(result.ok){await env.DB.prepare("UPDATE notification_logs SET status='SENT',provider_id=?,sent_at=CURRENT_TIMESTAMP,error_message=NULL WHERE idempotency_key=?").bind(result.id||null,key).run();return result}await env.DB.prepare("UPDATE notification_logs SET status='SKIPPED',error_message=? WHERE idempotency_key=?").bind(result.reason||"skipped",key).run();return result}catch(error){await env.DB.prepare("UPDATE notification_logs SET status='FAILED',error_message=? WHERE idempotency_key=?").bind(String(error?.message||error).slice(0,500),key).run();throw error}}
async function ensureProductLogisticsSchema(env){
  const defs=[
    ["weight_kg","REAL"],
    ["dimensions_cm","TEXT"],
    ["material","TEXT"],
    ["hs_code","TEXT"],
    ["package_type","TEXT"],
    ["units_per_package","INTEGER NOT NULL DEFAULT 1"],
    ["packaging_weight_kg","REAL NOT NULL DEFAULT 0"]
  ];
  const info=await env.DB.prepare("PRAGMA table_info(products)").all();
  const existing=new Set((info.results||[]).map(x=>x.name));
  for(const [col,type] of defs){
    if(existing.has(col))continue;
    try{await env.DB.prepare("ALTER TABLE products ADD COLUMN "+col+" "+type).run()}
    catch(err){if(!/duplicate column name/i.test(String(err?.message||err)))throw err}
  }
  return true;
}
__name(ensureProductLogisticsSchema,"ensureProductLogisticsSchema");
function sandboxTrackingNumber(orderNumber,carrier){const prefix=carrier==="J&T"?"JNT":"DHL";const clean=String(orderNumber||"").replace(/[^A-Z0-9]/gi,"").toUpperCase().slice(-12);return "TEST-"+prefix+"-"+clean}
function createSandboxShipment(order,carrier,env){const trackingNumber=sandboxTrackingNumber(order.order_number,carrier);return {trackingNumber,trackingUrl:trackingUrl(order,env),mode:"SANDBOX",test:true}}
function generatedTrackingNumber(orderNumber,carrier){const prefix=carrier==="J&T"?"JNT":"DHL";const clean=String(orderNumber||"").replace(/[^A-Z0-9]/gi,"").toUpperCase().slice(-10);return prefix+clean}
__name(generatedTrackingNumber,"generatedTrackingNumber");
function carrierTrackingUrl(carrier,tracking){const t=String(tracking||"").trim();if(carrier==="J&T")return "https://www.jet.co.id/track"+(t?"?bills="+encodeURIComponent(t):"");return "https://www.dhl.com/global-en/home/tracking.html?tracking-id="+encodeURIComponent(t)}
__name(carrierTrackingUrl,"carrierTrackingUrl");
async function createOrder(request, env) {
  const body = await request.json();
  if (!Array.isArray(body.items) || !body.items.length) return json({ error: "Keranjang kosong" }, 400, cors(request));
  const currency = body.currency === "IDR" ? "IDR" : "USD";
  const ids = body.items.map((x) => x.productId);
  if (ids.some((x) => !x)) return json({ error: "Product ID tidak valid" }, 400, cors(request));
  const placeholders = ids.map(() => "?").join(",");
  const result = await env.DB.prepare(`SELECT p.id,p.stock,p.type,p.moq,pt.name,pp.amount FROM products p JOIN product_translations pt ON pt.product_id=p.id AND pt.language=? JOIN product_prices pp ON pp.product_id=p.id AND pp.currency=? WHERE p.id IN (${placeholders}) AND p.active=1`).bind(currency === "IDR" ? "id" : "en", currency, ...ids).all();
  const byId = new Map((result.results || []).map((x) => [x.id, x]));
  let subtotal = 0;
  const items = [];
  for (const item of body.items) {
    const p = byId.get(item.productId), qty = Number(item.quantity);
    if (!p || !Number.isInteger(qty) || qty < 1) return json({ error: "Produk atau quantity tidak valid" }, 400, cors(request));
    if (p.type !== "retail" && qty < Number(p.moq || 1)) return json({ error: `MOQ produk ${p.name} adalah ${p.moq}` }, 400, cors(request));
    if (qty > Number(p.stock)) return json({ error: `Stok ${p.name} tidak mencukupi` }, 409, cors(request));
    const unitPrice = Number(p.amount);
    if (!Number.isFinite(unitPrice) || unitPrice < 0) return json({ error: `Harga produk ${p.name} tidak valid` }, 500, cors(request));
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
  if (!Number.isFinite(adminTotalIdr) || adminTotalIdr <= 0) return json({ error: "Total order tidak valid" }, 500, cors(request));

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
  const persistedItemCount = Number((await env.DB.prepare("SELECT COUNT(*) AS n FROM order_items WHERE order_id=?").bind(orderId).first())?.n || 0);
  if (persistedItemCount !== items.length) {
    console.error("ORDER_ITEMS_PERSISTENCE_MISMATCH", {
      orderId,
      orderNumber,
      expected: items.length,
      persisted: persistedItemCount
    });
    return json({ error: "Data item pesanan gagal disimpan dengan lengkap", orderId, orderNumber }, 500, cors(request));
  }

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
      }, 201, cors(request));
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
      }, 502, cors(request));
    }
  }
  return json({ orderId, orderNumber, currency, subtotal, shippingAmount: shipping, shippingCarrier, total, adminTotalIdr }, 201, cors(request));
}
__name(createOrder, "createOrder");
async function adminOrders(request, env) {
  await ensureShippingSchema(env);
  await ensureProductLogisticsSchema(env);
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, cors(request));
  const orderRows = await env.DB.prepare(`SELECT o.*,c.email,c.first_name,c.last_name,i.invoice_number,pk.packing_number,pk.courier,pk.tracking_number,pk.tracking_url,pk.package_count,pk.status AS packing_status,pk.auth_code,pk.email_sent_at,pk.email_error FROM orders o LEFT JOIN customers c ON c.id=o.customer_id LEFT JOIN invoices i ON i.order_id=o.id LEFT JOIN packing_orders pk ON pk.order_id=o.id ORDER BY o.created_at DESC`).all();
  const orders = orderRows.results || [];
  if (!orders.length) return json({ orders: [] }, 200, cors(request));
  const itemRows = await env.DB.prepare(`SELECT oi.*,p.weight_kg,p.dimensions_cm FROM order_items oi LEFT JOIN products p ON p.id=oi.product_id ORDER BY oi.rowid`).all();
  const paymentRows = await env.DB.prepare(`SELECT order_id,provider,method,provider_transaction_id,amount,currency,status,verified_at,created_at FROM payments ORDER BY created_at DESC`).all();
  const itemsByOrder = new Map();
  for (const item of itemRows.results || []) {
    if (!itemsByOrder.has(item.order_id)) itemsByOrder.set(item.order_id, []);
    itemsByOrder.get(item.order_id).push({id:item.id,product_id:item.product_id,name:item.product_name,product_name:item.product_name,qty:Number(item.quantity)||0,quantity:Number(item.quantity)||0,price:Number(item.unit_price)||0,unit_price:Number(item.unit_price)||0,total_price:Number(item.total_price)||0,currency:item.currency,weight_kg:Number(item.weight_kg)||0,dimensions_cm:item.dimensions_cm||""});
  }
  const paymentByOrder = new Map();
  for (const payment of paymentRows.results || []) if (!paymentByOrder.has(payment.order_id)) paymentByOrder.set(payment.order_id, payment);
  return json({orders:orders.map(order=>{const payment=paymentByOrder.get(order.id)||null;return {...order,trackingLink:trackingUrl(order,env),items:itemsByOrder.get(order.id)||[],payment_method:payment?.method||null,payment_provider:payment?.provider||null,payment_transaction_id:payment?.provider_transaction_id||null,payment_reference:payment?.provider_transaction_id||null,paid_at:payment?.verified_at||null};})},200,cors(request));
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
  await ensureProductLogisticsSchema(env);
  await ensureShippingSchema(env);
  const order = await env.DB.prepare(`SELECT * FROM orders WHERE id=?`).bind(orderId).first();
  if (!order) return { ok: false, status: 404, error: "Order tidak ditemukan" };
  if (order.payment_status === "PAID") return { ok: true, alreadyPaid: true, order };
  const items = (await env.DB.prepare(`SELECT oi.*,p.stock,p.active,p.weight_kg,p.dimensions_cm,p.units_per_package,p.packaging_weight_kg FROM order_items oi JOIN products p ON p.id=oi.product_id WHERE oi.order_id=?`).bind(orderId).all()).results || [];
  let shippingCountry="";
  try { shippingCountry=String(JSON.parse(order.shipping_address_json||"{}").country||"").trim(); } catch (_) {}
  const shippingCarrier=shippingCarrierForCountry(shippingCountry);
  const trackingNumber=null;
  const packageCount=Math.max(1,items.reduce((sum,item)=>sum+Math.ceil(Number(item.quantity||0)/Math.max(1,Number(item.units_per_package||1))),0));
  const netWeight=items.reduce((sum,item)=>sum+(Number(item.weight_kg)||0)*(Number(item.quantity)||0),0);
  const packagingWeight=items.reduce((sum,item)=>sum+Math.ceil(Number(item.quantity||0)/Math.max(1,Number(item.units_per_package||1)))*(Number(item.packaging_weight_kg)||0),0);
  const grossWeight=netWeight+packagingWeight;
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
    env.DB.prepare(`INSERT INTO packing_orders(id,order_id,packing_number,status,auth_code,courier,tracking_number,tracking_url,package_count,gross_weight_kg,net_weight_kg,created_at) VALUES(?,?,?,'PENDING',?,?,?,?,?,?,?,CURRENT_TIMESTAMP)`).bind(id("pack"), orderId, packingNo, crypto.randomUUID().replace(/-/g,"")+crypto.randomUUID().replace(/-/g,"").slice(0,16), shippingCarrier, trackingNumber, carrierTrackingUrl(shippingCarrier,trackingNumber), packageCount, grossWeight, netWeight),
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
  const paidOrder=await env.DB.prepare(`SELECT o.*,c.first_name,c.last_name,c.email,c.phone,i.invoice_number,pk.packing_number,pk.auth_code,pk.courier,pk.tracking_number,pk.tracking_url,pk.package_count,pk.gross_weight_kg,pk.net_weight_kg,pk.packaging_type,pk.dimensions_cm FROM orders o LEFT JOIN customers c ON c.id=o.customer_id LEFT JOIN invoices i ON i.order_id=o.id LEFT JOIN packing_orders pk ON pk.order_id=o.id WHERE o.id=?`).bind(orderId).first();
  // Email is intentionally deferred until READY_TO_SHIP and tracking_number are both present.
  return { ok: true, alreadyPaid: false, invoiceNo, packingNo };
}
__name(markOrderPaid, "markOrderPaid");
async function adminVerifyPayment(request, env) {
  await ensureShippingSchema(env);
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, cors(request));
  const body = await request.json();
  if (!body.orderId) return json({ error: "orderId wajib diisi" }, 400, cors(request));
  const order = await env.DB.prepare(`SELECT id,payment_status,order_status FROM orders WHERE id=?`).bind(body.orderId).first();
  if (!order) return json({ error: "Order tidak ditemukan" }, 404, cors(request));

  if (String(body.status || "").toUpperCase() === "REJECTED") {
    if (order.payment_status === "PAID") return json({ error: "Pembayaran yang sudah PAID tidak dapat ditolak" }, 409, cors(request));
    const reason = String(body.reason || "Pembayaran ditolak");
    await env.DB.batch([
      env.DB.prepare(`UPDATE orders SET payment_status='REJECTED',updated_at=CURRENT_TIMESTAMP WHERE id=? AND payment_status<>'PAID'`).bind(body.orderId),
      env.DB.prepare(`INSERT INTO order_status_history(id,order_id,status,note) VALUES(?,?,?,?)`).bind(id("hist"), body.orderId, "REJECTED", reason),
      env.DB.prepare(`INSERT INTO audit_logs(id,admin_id,action,entity_type,entity_id,metadata_json) VALUES(?,?,?,?,?,?)`).bind(
        id("audit"), admin.id, "REJECT_PAYMENT", "order", body.orderId, JSON.stringify({ reason })
      )
    ]);
    return json({ ok: true, status: "REJECTED" }, 200, cors(request));
  }

  let result;
  try {
    result = await markOrderPaid(body.orderId, {
      amount: body.amount, currency: body.currency, provider: "manual",
      method: body.method || "bank_transfer", providerTransactionId: body.transactionId || null
    }, env, admin.email);
  } catch (error) {
    console.error("VERIFY_PAYMENT_FATAL", {orderId:body.orderId,message:error?.message||String(error),stack:error?.stack||null});
    return json({error:"Verifikasi pembayaran gagal: "+String(error?.message||error).slice(0,500)},500,cors(request));
  }
  if (!result.ok) return json({ error: result.error }, result.status || 400, cors(request));

  try {
    await env.DB.prepare(`INSERT INTO audit_logs(id,admin_id,action,entity_type,entity_id,metadata_json) VALUES(?,?,?,?,?,?)`).bind(
      id("audit"), admin.id, "VERIFY_PAYMENT", "order", body.orderId,
      JSON.stringify({ transactionId: body.transactionId || null })
    ).run();
  } catch (auditError) {
    console.error("VERIFY_PAYMENT_AUDIT_ERROR", { orderId: body.orderId, message: auditError?.message || String(auditError) });
  }
  return json(result, 200, cors(request));
}
__name(adminVerifyPayment, "adminVerifyPayment");

async function adminShipping(request,env){
  await ensureShippingSchema(env);
  const admin=await requireAdmin(request,env);
  if(!admin)return json({error:"Unauthorized"},401,cors(request));
  const body=await request.json().catch(()=>({}));
  if(!body.orderId)return json({error:"orderId wajib diisi"},400,cors(request));
  const order=await env.DB.prepare("SELECT id,order_number,order_status FROM orders WHERE id=? OR order_number=? LIMIT 1").bind(body.orderId,body.orderId).first();
  if(!order)return json({error:"Order tidak ditemukan"},404,cors(request));
  const pack=await ensurePackingAuth(order.id,env);
  if(!pack)return json({error:"Packing order belum tersedia"},409,cors(request));
  const status=String(body.status||pack.status||"PENDING").toUpperCase();
  const allowed=["PENDING","PACKING","READY TO SHIP","SHIPPED","DELIVERED","CANCELLED"];
  if(!allowed.includes(status))return json({error:"Status pengiriman tidak valid"},400,cors(request));
  const autoCreateShipment=body.autoCreateShipment===true;
  let trackingNumber=String(body.trackingNumber||"").trim()||null;
  const courier=String(body.courier||"").trim().toUpperCase()||null;
  let trackingUrlValue=String(body.trackingUrl||"").trim() || (trackingNumber ? carrierTrackingUrl(courier,trackingNumber) : null);
  const mode=shippingMode(env);
  let shipmentTest=false;
  if(autoCreateShipment && !trackingNumber){
    if(mode==="SANDBOX"){
      const shipment=createSandboxShipment(order,courier,env);
      trackingNumber=shipment.trackingNumber;
      trackingUrlValue=shipment.trackingUrl;
      shipmentTest=true;
    }else{
      return json({error:"Automatic production shipment belum dikonfigurasi dengan API resmi kurir. Masukkan nomor waybill resmi J&T/DHL secara manual atau konfigurasi provider resmi.",code:"SHIPPING_PROVIDER_NOT_CONFIGURED",shipmentMode:"PRODUCTION"},409,cors(request));
    }
  }
  if(!["J&T","DHL"].includes(courier))return json({error:"Kurir harus J&T untuk domestik atau DHL untuk ekspor"},400,cors(request));
  const country=String((await env.DB.prepare("SELECT json_extract(shipping_address_json,'$.country') AS country FROM orders WHERE id=?").bind(order.id).first())?.country||"").toLowerCase();
  const domestic=["indonesia","id","indonesia (id)"].includes(country);
  if((domestic&&courier!=="J&T")||(!domestic&&courier!=="DHL"))return json({error:domestic?"Order domestik wajib menggunakan J&T":"Order ekspor wajib menggunakan DHL"},400,cors(request));
  await env.DB.prepare("UPDATE packing_orders SET courier=?,tracking_number=?,tracking_url=?,status=?,shipped_at=CASE WHEN ?='SHIPPED' AND shipped_at IS NULL THEN CURRENT_TIMESTAMP ELSE shipped_at END,delivered_at=CASE WHEN ?='DELIVERED' AND delivered_at IS NULL THEN CURRENT_TIMESTAMP ELSE delivered_at END WHERE order_id=?").bind(courier,trackingNumber,trackingUrlValue,status,status,status,order.id).run();
  await env.DB.prepare("INSERT INTO tracking_events(id,order_id,tracking_number,status,event_time,location,description,source) VALUES(?,?,?,?,CURRENT_TIMESTAMP,?,?,?)").bind(id("trackevt"),order.id,trackingNumber,status,null,"Shipping status updated by admin","admin").run();
  const orderStatus=status==="DELIVERED"?"DELIVERED":status==="SHIPPED"?"SHIPPED":status==="READY TO SHIP"?"READY TO SHIP":status==="PACKING"?"PACKING":order.order_status||"PROCESSING";
  await env.DB.prepare("UPDATE orders SET order_status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(orderStatus,order.id).run();
  await env.DB.prepare("INSERT INTO order_status_history(id,order_id,status,note) VALUES(?,?,?,?)").bind(id("hist"),order.id,orderStatus,"Shipping update: "+(courier||"-")+" "+(trackingNumber||"-")).run();
  await env.DB.prepare("INSERT INTO audit_logs(id,admin_id,action,entity_type,entity_id,metadata_json) VALUES(?,?,?,?,?,?)").bind(id("audit"),admin.id,"UPDATE_SHIPPING","order",order.id,JSON.stringify({courier,trackingNumber,trackingUrl:trackingUrlValue,status})).run();
  try{
    const updated=await env.DB.prepare(`SELECT o.*,c.first_name,c.last_name,c.email,c.phone,i.invoice_number,pk.packing_number,pk.auth_code,pk.courier,pk.tracking_number,pk.tracking_url,pk.package_count,pk.gross_weight_kg,pk.net_weight_kg,pk.packaging_type,pk.dimensions_cm,pk.packaging_weight_kg,pk.status AS packing_status FROM orders o LEFT JOIN customers c ON c.id=o.customer_id LEFT JOIN invoices i ON i.order_id=o.id LEFT JOIN packing_orders pk ON pk.order_id=o.id WHERE o.id=?`).bind(order.id).first();
    const shipItems=(await env.DB.prepare("SELECT oi.*,p.weight_kg,p.dimensions_cm FROM order_items oi LEFT JOIN products p ON p.id=oi.product_id WHERE oi.order_id=? ORDER BY oi.rowid").bind(order.id).all()).results||[];
    const rows=await env.DB.prepare("SELECT key,value_json FROM site_settings WHERE key IN ('brand','website','whatsapp','businessPhone','email','address','pdfTagline1','pdfTagline2','countryOrigin','exporter','paymentTerms','incoterms','portLoading','portDestination')").all();
    const branding=Object.fromEntries((rows.results||[]).map(row=>{let v=row.value_json;try{v=JSON.parse(v)}catch(_){}return [row.key,v]}));
    if(updated && (trackingNumber || status==="SHIPPED" || status==="DELIVERED")){
      updated.tracking_link=trackingUrl(updated,env);
      if(String(status).toUpperCase().replace(/_/g," ")==="READY TO SHIP" && trackingNumber) await sendReadyToShipDocumentsEmail({...updated,order_status:"READY TO SHIP"},shipItems,branding,env);
    }
  }catch(error){
    console.error("SHIPPING_DOCUMENT_EMAIL_ERROR",{orderId:order.id,message:error?.message||String(error)});
    await env.DB.prepare("UPDATE packing_orders SET email_error=? WHERE order_id=?").bind(String(error?.message||error).slice(0,500),order.id).run().catch(()=>{});
  }
  return json({ok:true,orderId:order.id,orderNumber:order.order_number,status,courier,trackingNumber,trackingUrl:trackingUrlValue,trackingLink:trackingUrl({...order,...pack,courier,tracking_number:trackingNumber,tracking_url:trackingUrlValue},env),shipmentMode:mode,testShipment:shipmentTest},200,cors(request));
}
__name(adminShipping,"adminShipping");
async function paymentWebhook(request, env) {
  const serverKey = String(env.MIDTRANS_SERVER_KEY || "").trim();
  if (!serverKey) return json({ error: "MIDTRANS_SERVER_KEY belum dikonfigurasi" }, 503, cors(request));
  const raw = await request.text();
  let body;
  try { body = JSON.parse(raw); } catch { return json({ error: "Payload webhook bukan JSON valid" }, 400, cors(request)); }

  const orderNumber = String(body.order_id || "").trim();
  const statusCode = String(body.status_code || "").trim();
  const grossAmount = String(body.gross_amount || "").trim();
  const signature = String(body.signature_key || "").trim();
  const expected = await sha512(`${orderNumber}${statusCode}${grossAmount}${serverKey}`);
  if (!timingSafeEqualHex(signature, expected)) return json({ error: "Invalid Midtrans signature" }, 401, cors(request));

  const transactionStatus = String(body.transaction_status || "").toLowerCase();
  const transactionId = String(body.transaction_id || "").trim();
  const eventId = await sha256(`${orderNumber}|${transactionId}|${transactionStatus}|${statusCode}`);
  if (await env.DB.prepare(`SELECT id FROM payment_webhooks WHERE event_id=?`).bind(eventId).first()) {
    return json({ ok: true, duplicate: true }, 200, cors(request));
  }

  const order = await env.DB.prepare(`SELECT * FROM orders WHERE order_number=?`).bind(orderNumber).first();
  if (!order) return json({ error: "Order tidak ditemukan" }, 404, cors(request));

  const fraudStatus = String(body.fraud_status || "").toLowerCase();
  const isSuccess = transactionStatus === "settlement" || (transactionStatus === "capture" && fraudStatus === "accept");
  let result = { ok: true, ignored: false };

  if (isSuccess) {
    result = await markOrderPaid(order.id, {
      amount: Math.round(Number(body.gross_amount)), currency: "IDR",
      provider: "midtrans", method: body.payment_type || "snap",
      providerTransactionId: transactionId || null
    }, env, "midtrans_webhook");
    if (!result.ok) return json({ error: result.error }, result.status || 400, cors(request));
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
  }, 200, cors(request));
}
__name(paymentWebhook, "paymentWebhook");
function safePdfText(value) {
  return String(value ?? "").replace(/[^\x20-\x7E]/g, "?").replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}
__name(safePdfText, "safePdfText");
function makeShippingLabelPdf(order, branding = {}) {
  // Preserve the existing physical label canvas. Do not infer or change label dimensions here.
  const W=288,H=432,brown="0.24 0.12 0.06",muted="0.42 0.36 0.30";
  const packageCount=Math.max(1,Math.floor(Number(order.package_count)||1));
  const pages=[];
  const esc=safePdfText;
  const address=(()=>{try{const p=JSON.parse(order.shipping_address_json||"{}");return [p.address,p.city,p.state,p.postalCode,p.country].filter(Boolean).join(", ")||"-"}catch(_){return "-"}})();
  const name=([order.first_name,order.last_name].filter(Boolean).join(" ").trim()||"-").slice(0,34);
  const courier=String(order.courier||"-");
  const service=String(order.shipping_method||"-");
  const tracking=String(order.tracking_number||order.order_number||"");
  for(let packageIndex=1;packageIndex<=packageCount;packageIndex++){
    const cmd=[];
    const text=(x,y,v,size=10,font="F1",color=brown)=>cmd.push(color+" rg","BT",`/${font} ${size} Tf`,`1 0 0 1 ${x} ${y} Tm`,`(${esc(v)}) Tj`,"ET");
    const rect=(x,y,w,h,color="0.96 0.94 0.90")=>cmd.push(`q ${color} rg ${x} ${y} ${w} ${h} re f Q`);
    rect(0,0,W,H);
    text(24,402,String(branding.brand||"PALMA ROTAN"),20,"F2");
    text(24,386,"SHIPPING LABEL",10,"F2",muted);
    text(24,360,"SHIP TO",8,"F2",muted);
    text(24,344,name,13,"F2");
    text(24,326,address.slice(0,42),8);
    if(order.email)text(24,312,String(order.email).slice(0,38),8,"F1",muted);
    if(order.phone)text(24,298,String(order.phone).slice(0,30),8,"F1",muted);
    rect(18,242,252,36,"0.88 0.96 0.90");
    text(28,256,"PROVIDER: "+courier,9,"F2");
    text(142,256,"SERVICE: "+service.slice(0,18),9,"F2");
    text(24,220,"TRACKING NUMBER",8,"F2",muted);
    text(24,202,order.tracking_number?String(order.tracking_number):"NOT ASSIGNED",15,"F2");
    if(tracking){drawCode128(cmd,24,134,240,52,tracking);text(24,120,tracking.slice(0,38),8,"F2");}
    text(24,96,"ORDER NO.",7,"F2",muted); text(24,82,String(order.order_number||"-"),9);
    text(150,96,"PACKAGE",7,"F2",muted); text(150,82,`${packageIndex} / ${packageCount}`,9);
    text(24,52,"PACKING LIST",7,"F2",muted); text(24,38,String(order.packing_number||"-"),8);
    text(150,52,"PRINT ALL LABELS",7,"F2",muted);
    text(24,20,"Code 128 • Shipment identification",6,"F1",muted);
    pages.push(cmd.join("\n")+"\n");
  }
  const pageBase=3,contentBase=3+packageCount*2;
  const objects=[
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids ["+pages.map((_,i)=>`${pageBase+i*2} 0 R`).join(" ")+"] /Count "+pages.length+" >>"
  ];
  for(let i=0;i<pages.length;i++){
    const pageObj=pageBase+i*2,contentObj=pageObj+1;
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${W} ${H}] /Resources << /Font << /F1 ${contentBase} 0 R /F2 ${contentBase+1} 0 R >> >> /Contents ${contentObj} 0 R >>`);
    objects.push(`<< /Length ${new TextEncoder().encode(pages[i]).length} >>\nstream\n${pages[i]}endstream`);
  }
  objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");
  let pdf="%PDF-1.4\n",offs=[0];
  for(let i=0;i<objects.length;i++){offs.push(new TextEncoder().encode(pdf).length);pdf+=(i+1)+" 0 obj\n"+objects[i]+"\nendobj\n"}
  const xref=new TextEncoder().encode(pdf).length;
  pdf+="xref\n0 "+(objects.length+1)+"\n0000000000 65535 f \n";
  for(let i=1;i<offs.length;i++)pdf+=String(offs[i]).padStart(10,"0")+" 00000 n \n";
  pdf+="trailer\n<< /Size "+(objects.length+1)+" /Root 1 0 R >>\nstartxref\n"+xref+"\n%%EOF";
  return new TextEncoder().encode(pdf);
}
__name(makeShippingLabelPdf,"makeShippingLabelPdf");
const PALMA_LOGO_PNG_BASE64 = "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";
function pdfLogoImage() {
  const png = Buffer.from(PALMA_LOGO_PNG_BASE64, "base64");
  if (png.length < 32 || png.toString("ascii", 1, 4) !== "PNG") throw new Error("Invalid PALMA logo PNG");
  const readU32 = (o) => png.readUInt32BE(o);
  const width = readU32(16), height = readU32(20), bitDepth = png[24], colorType = png[25];
  if (bitDepth !== 8 || colorType !== 6) throw new Error("PALMA logo must be 8-bit RGBA PNG");
  const idats = [];
  let p = 8;
  while (p + 12 <= png.length) {
    const len = readU32(p), type = png.toString("ascii", p + 4, p + 8);
    const dataStart = p + 8, dataEnd = dataStart + len;
    if (type === "IDAT") idats.push(png.subarray(dataStart, dataEnd));
    p = dataEnd + 4;
    if (type === "IEND") break;
  }
  const raw = inflateSync(Buffer.concat(idats));
  const stride = width * 4, rgbRowSize = 1 + width * 3, alphaRowSize = 1 + width;
  const rgb = Buffer.alloc(rgbRowSize * height), alpha = Buffer.alloc(alphaRowSize * height);
  let src = 0, prev = Buffer.alloc(stride);
  const paeth = (a,b,c) => { const q=a+b-c, pa=Math.abs(q-a),pb=Math.abs(q-b),pc=Math.abs(q-c); return pa<=pb&&pa<=pc?a:pb<=pc?b:c; };
  for(let y=0;y<height;y++){
    const filter=raw[src++], row=Buffer.alloc(stride);
    for(let x=0;x<stride;x++){
      const left=x>=4?row[x-4]:0, up=prev[x]||0, upLeft=x>=4?(prev[x-4]||0):0, v=raw[src++];
      let out=v;
      if(filter===1)out=(v+left)&255; else if(filter===2)out=(v+up)&255; else if(filter===3)out=(v+Math.floor((left+up)/2))&255; else if(filter===4)out=(v+paeth(left,up,upLeft))&255; else if(filter!==0)throw new Error("Unsupported PNG filter");
      row[x]=out;
    }
    let ro=y*rgbRowSize, ao=y*alphaRowSize; rgb[ro++]=0; alpha[ao++]=0;
    for(let x=0;x<width;x++){const i=x*4;rgb[ro++]=row[i];rgb[ro++]=row[i+1];rgb[ro++]=row[i+2];alpha[ao++]=row[i+3];}
    prev=row;
  }
  return {width,height,rgb:deflateSync(rgb),alpha:deflateSync(alpha)};
}

async function qrPngMatrix(value) {
  const data=String(value||"").trim();
  if(!data) return null;
  const url="https://api.qrserver.com/v1/create-qr-code/?size=240x240&ecc=H&margin=2&format=png&data="+encodeURIComponent(data);
  const response=await fetch(url,{headers:{"accept":"image/png"},cache:"no-store"});
  if(!response.ok) throw new Error("QR service HTTP "+response.status);
  const png=Buffer.from(await response.arrayBuffer());
  if(png.length<32||png.toString("ascii",1,4)!=="PNG") throw new Error("QR response bukan PNG");
  const u32=o=>png.readUInt32BE(o);
  const width=u32(16),height=u32(20),depth=png[24],colorType=png[25];
  if(depth!==8||(colorType!==2&&colorType!==6)) throw new Error("QR PNG format tidak didukung");
  const channels=colorType===6?4:3;
  const idats=[];let p=8;
  while(p+12<=png.length){
    const len=u32(p),kind=png.toString("ascii",p+4,p+8),ds=p+8,de=ds+len;
    if(kind==="IDAT") idats.push(png.subarray(ds,de));
    p=de+4;
    if(kind==="IEND") break;
  }
  const raw=inflateSync(Buffer.concat(idats));
  const stride=width*channels;
  const rows=[];
  let src=0,prev=Buffer.alloc(stride);
  const paeth=(a,b,d)=>{const q=a+b-d,pa=Math.abs(q-a),pb=Math.abs(q-b),pc=Math.abs(q-d);return pa<=pb&&pa<=pc?a:pb<=pc?b:d};
  for(let y=0;y<height;y++){
    const filter=raw[src++],row=Buffer.alloc(stride);
    for(let x=0;x<stride;x++){
      const left=x>=channels?row[x-channels]:0,up=prev[x]||0,ul=x>=channels?(prev[x-channels]||0):0,v=raw[src++];
      let out=v;
      if(filter===1) out=(v+left)&255;
      else if(filter===2) out=(v+up)&255;
      else if(filter===3) out=(v+Math.floor((left+up)/2))&255;
      else if(filter===4) out=(v+paeth(left,up,ul))&255;
      else if(filter!==0) throw new Error("Unsupported QR PNG filter");
      row[x]=out;
    }
    const runs=[];let runStart=-1;
    for(let x=0;x<width;x++){
      const j=x*channels;
      const alpha=channels===4?row[j+3]:255;
      const lum=(0.299*row[j])+(0.587*row[j+1])+(0.114*row[j+2]);
      const dark=alpha>32&&lum<128;
      if(dark&&runStart<0) runStart=x;
      if(!dark&&runStart>=0){runs.push([runStart,x-runStart]);runStart=-1;}
    }
    if(runStart>=0) runs.push([runStart,width-runStart]);
    rows.push(runs);
    prev=row;
  }
  return {width,height,rows};
}

async function makeProfessionalPdf(type, order, items, branding = {}) {
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
  const logoImage = pdfLogoImage();
  let qrMatrix=null;
  if(type==="invoice" || type==="packing"){
    try{
      qrMatrix=await qrPngMatrix(String(order.document_verification_url||""));
    }catch(error){console.error("DOCUMENT_QR_ERROR",{orderId:order.id,type,message:error?.message||String(error)});}
  }
  const barcodeSlot = (x,y,w,h,title,value,displayValue=null) => {
    rect(x,y,w,h,false);
    text(x+9,y+h-14,title,7.0,"F2",muted);
    const raw=String(value||"").slice(0,180);
    if(raw){
      drawCode128(commands,x+10,y+19,w-20,Math.max(25,h-43),raw);
      const shown=String(displayValue ?? raw).replace(/\s+/g," ").trim().slice(0,34);
      text(x+9,y+6,shown||"SCANNED DATA",6.2,"F2",brown);
    } else {
      text(x+9,y+7,"NOT ASSIGNED",6.2,"F2",muted);
    }
  };
  // Compact carrier mark: only the mark is rendered beside "Courier";
  // no separate courier name is printed, so it cannot overlap the logo area.
  const carrierMark = (x,y,carrier) => {
    const v=String(carrier||"").toUpperCase();
    if(v.includes("DHL")){
      commands.push("q 0.98 0.78 0.02 rg", x+" "+y+" 42 15 re f", "Q");
      text(x+5,y+4,"DHL",9,"F2","0.82 0.03 0.03");
    } else if(v.includes("J&T") || v.includes("JNT") || v.includes("JET")){
      commands.push("q 0.82 0.03 0.03 rg", x+" "+y+" 42 15 re f", "Q");
      text(x+5,y+4,"J&T",9,"F2","1 1 1");
    } else {
      text(x+2,y+4,v.slice(0,10)||"-",7.2,"F2",brown);
    }
  };

  // Paper background and top brand band.
  commands.push(`q ${cream} rg 0 0 ${W} ${H} re f Q`);
  commands.push(`q 0.985 0.975 0.95 rg 0 ${H-108} ${W} 108 re f Q`);
  const brand = "PALMA ROTAN";
  const brandLine1 = "PALMA";
  const brandLine2 = "ROTAN";
  const tagline1 = String(branding.pdfTagline1 || "NATURAL CRAFT");
  const tagline2 = String(branding.pdfTagline2 || "TIMELESS BEAUTY");
  const website = String(branding.website || "palmarotancraft.id");
  const phone = String(branding.whatsapp || "08978186933");
  const businessPhone = String(branding.businessPhone || phone);
  const countryOrigin = String(branding.countryOrigin || "Indonesia");
  const exporter = String(branding.exporter || brand);
  const paymentTerms = String(branding.paymentTerms || "");
  const incoterms = String(branding.incoterms || "");
  const portLoading = String(branding.portLoading || "");
  const portDestination = String(branding.portDestination || "");
  const address = String(branding.address || "Jl. Rotan Jaya, Ds. Teluk Wetan, RT 07/RW 01, Kec. Welahan, Kab. Jepara, Prov. Jawa Tengah, Indonesia");
  commands.push("q", "160 0 0 55 42 760 cm", "/Logo Do", "Q");
  text(220, 797, tagline1.slice(0, 24), 8, "F2", muted);
  text(220, 783, tagline2.slice(0, 24), 8, "F1", muted);
  text(410, 800, website.slice(0, 30), 7, "F1", muted);
  if (phone) text(410, 785, "Phone / WhatsApp: "+businessPhone.slice(0, 18), 7, "F1", muted);
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
    roundRect(M, 510, 245, 66, false);
    roundRect(308, 510, 245, 66, false);
    text(54, 560, "SHIPPING INFORMATION", 8.0, "F2", muted);
    text(54, 544, "Courier", 7.6, "F1", muted);
    carrierMark(112, 539, order.courier || order.shipping_method || "");
    text(54, 530, "Tracking No.", 7.6, "F1", muted);
    text(112, 530, String(order.tracking_number||"-").slice(0,23), 7.0, "F1");
    text(54, 516, "Total Net Weight", 7.6, "F1", muted);
    text(112, 516, Number(order.net_weight_kg||0).toFixed(2)+" kg", 7.0, "F1");

    text(320, 560, "PACKAGE SUMMARY", 8.0, "F2", muted);
    text(320, 544, "Packages", 7.6, "F1", muted);
    text(390, 544, String(order.package_count||1), 7.0, "F1");
    text(320, 530, "Package Type", 7.6, "F1", muted);
    text(390, 530, String(order.packaging_type||"-").slice(0,22), 7.0, "F1");
    text(320, 516, "Status", 7.6, "F1", muted);
    text(390, 516, String(order.packing_status||"PENDING").replace(/_/g," ").slice(0,20), 7.0, "F1");
  }
  if(type === "invoice"){
    roundRect(M, 550, 118, 27, true, "0.88 0.96 0.90");
    text(55, 559, "PAYMENT: " + String(order.payment_status || "PENDING"), 8, "F2", brown);
    roundRect(174, 550, 113, 27, true, "0.94 0.90 0.84");
    text(182, 559, "CURRENCY: " + String(order.original_currency || "USD"), 8, "F2", brown);
  }

  if(type==="invoice"){
    const metaY=535;
    text(M,metaY,"EXPORTER: "+exporter.slice(0,38),7.2,"F1",muted);
    text(M,metaY-13,"COUNTRY OF ORIGIN: "+countryOrigin.slice(0,29),7.2,"F1",muted);
    if(paymentTerms) text(310,metaY,"PAYMENT TERMS: "+paymentTerms.slice(0,30),7.2,"F1",muted);
    if(incoterms) text(310,metaY-13,"INCOTERMS: "+incoterms.slice(0,30),7.2,"F1",muted);
    if(portLoading) text(M,metaY-26,"PORT OF LOADING: "+portLoading.slice(0,30),7.2,"F1",muted);
    if(portDestination) text(310,metaY-26,"PORT OF DESTINATION: "+portDestination.slice(0,30),7.2,"F1",muted);
  }

  // Table.
  let y=490;
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
  if(!items.length){
    line(M,y-38,W-M,y-38,0.45,tan);
    text(50,y-18,"—",8,"F1",muted);
    text(82,y-18,"Product data not available for this order",8,"F1",muted);
    y-=38;
  } else {
    items.forEach((item,index)=>{
      const name=wrap(item.product_name || item.name || "Product", type==="invoice"?35:30);
      const rowH=Math.max(42,name.length*10+16);
      line(M,y-rowH,W-M,y-rowH,0.45,tan);
      text(50,y-18,String(index+1),8,"F1");
      let yy=y-13;
      for(const n of name.slice(0,3)){ text(82,yy,n,8,"F1"); yy-=10; }
      if(type==="packing" && item.sku) { text(82,yy,"SKU: "+item.sku,6.8,"F1",muted); yy-=9; if(item.hs_code) { text(82,yy,"HS: "+item.hs_code,6.8,"F1",muted); yy-=9; } }
      text(type==="invoice"?365:363,y-18,String(item.quantity ?? item.qty ?? 0),8,"F1");
      if(type==="invoice"){
        text(423,y-18,money(item.unit_price ?? item.price,item.currency),7.2,"F1");
        text(497,y-18,money(item.total_price,item.currency),7.2,"F1");
      } else {
        text(417,y-18,Number(item.weight_kg||0).toFixed(1)+" kg",7.2,"F1");
        text(477,y-18, item.dimensions_cm || "-",6.8,"F1");
        text(535,y-18,item.material || "Rattan",6.2,"F1");
      }
      y-=rowH;
    });
  }

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

  }

  // Packing List: barcode row is placed directly above the weight/shipping
  // summary, with three proportional columns.
  if(type==="packing"){
    const barcodeY=Math.max(y-82,92);
    const bw=(W-2*M-20)/3;
    barcodeSlot(M,barcodeY,bw,72,"TRACKING BARCODE",String(order.tracking_link||""),String(order.tracking_number||"TRACKING LINK"));
    barcodeSlot(M+bw+10,barcodeY,bw,72,"RESI / WAYBILL BARCODE",String(order.tracking_number||""),String(order.tracking_number||"NOT ASSIGNED"));
    barcodeSlot(M+(bw+10)*2,barcodeY,bw,72,"ORDER AUTHENTICATION BARCODE",
      order.order_number&&order.auth_code
        ? String(order.order_number)+"|"+String(order.auth_code)
        : String(order.order_number||""),String(order.order_number||""));
  } else if(type==="invoice" || type==="packing"){
    // Each production document gets its own verification QR. Keep it separated
    // from barcode blocks and the footer.
    // Invoice has one clean authentication QR only. Keep it above the
    // footer and below the payment method so it cannot collide with other
    // barcode blocks.
    if(qrMatrix){
      const qrSize=72,qrX=W-M-qrSize,qrY=type==="packing"?Math.max(30,Math.min(118,Math.max(30,(y-82)-70))):118,unit=qrSize/qrMatrix.width;
      commands.push("q 1 1 1 rg",`${qrX} ${qrY} ${qrSize} ${qrSize} re f`,"Q");
      commands.push("q 0 0 0 rg");
      for(let row=0;row<qrMatrix.rows.length;row++){
        const py=qrY+qrSize-(row+1)*unit;
        for(const [start,len] of qrMatrix.rows[row]){
          commands.push(`${qrX+start*unit} ${py} ${len*unit+0.02} ${unit+0.02} re f`);
        }
      }
      commands.push("Q");
      text(qrX,qrY-12,type==="invoice"?"INVOICE AUTHENTICATION QR":"PACKING AUTHENTICATION QR",6.0,"F2",muted);
      text(qrX+9,qrY-23,"SCAN TO VERIFY",6.2,"F1",muted);
    }
  }
  if(type==="packing"){
    const cy=Math.max(y-88,132);
    text(M,cy,"PACKING CHECKLIST",8,"F2",muted);
    const checks=["Product quantity checked","Weight / dimensions checked","Tracking / label checked","Documents enclosed"];
    checks.forEach((label,i)=>{
      const yy=cy-16-i*12;
      commands.push(tan+" RG", "0.8 w", M+" "+yy+" 8 8 re S");
      text(M+14,yy+1,label,6.8,"F1",muted);
    });
  }

  // Footer.
  line(M,24,W-M,24,0.8,tan);
  commands.push("q", "36 0 0 12.37 42 6 cm", "/Logo Do", "Q");
  text(86,24,"Handcrafted Rattan • Natural Materials • Crafted in Indonesia",6.2,"F1",muted);
  text(390,24,"PALMA ROTAN",7,"F2");

  const stream=commands.join("\n")+"\n";
  const te=new TextEncoder();
  const chunks=[]; let total=0; const offsets=[0];
  const add=(b)=>{chunks.push(b);total+=b.length;};
  const addText=(t)=>add(te.encode(t));
  addText("%PDF-1.4\n");
  const addObj=(n,body)=>{offsets[n]=total;addText(`${n} 0 obj\n`);if(typeof body==="string")addText(body);else{addText(body.head);add(body.data);addText(body.tail);}addText("\nendobj\n");};
  addObj(1,"<< /Type /Catalog /Pages 2 0 R >>");
  addObj(2,"<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
  addObj(3,`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R /F2 5 0 R /F3 6 0 R >> /XObject << /Logo 8 0 R >> /Contents 7 0 R >>`);
  addObj(4,"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  addObj(5,"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");
  addObj(6,"<< /Type /Font /Subtype /Type1 /BaseFont /Times-Bold >>");
  addObj(7,{head:`<< /Length ${te.encode(stream).length} >>\nstream\n`,data:te.encode(stream),tail:"endstream"});
  addObj(8,{head:`<< /Type /XObject /Subtype /Image /Width ${logoImage.width} /Height ${logoImage.height} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /DecodeParms << /Predictor 15 /Colors 3 /BitsPerComponent 8 /Columns ${logoImage.width} >> /SMask 9 0 R /Length ${logoImage.rgb.length} >>\nstream\n`,data:logoImage.rgb,tail:"\nendstream"});
  addObj(9,{head:`<< /Type /XObject /Subtype /Image /Width ${logoImage.width} /Height ${logoImage.height} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /DecodeParms << /Predictor 15 /Colors 1 /BitsPerComponent 8 /Columns ${logoImage.width} >> /Length ${logoImage.alpha.length} >>\nstream\n`,data:logoImage.alpha,tail:"\nendstream"});
  const xref=total;
  addText("xref\n0 10\n0000000000 65535 f \n");
  for(let i=1;i<=9;i++)addText(String(offsets[i]).padStart(10,"0")+" 00000 n \n");
  addText(`trailer\n<< /Size 10 /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`);
  const out=new Uint8Array(total);let at=0;for(const c of chunks){out.set(c,at);at+=c.length;}return out;
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
  if (!admin) return json({ error: "Unauthorized" }, 401, cors(request));
  if (!env.MEDIA) return json({ error: "R2 MEDIA belum dikonfigurasi" }, 503, cors(request));
  if (request.method === "GET") {
    const rows = await env.DB.prepare("SELECT * FROM media ORDER BY created_at DESC").all();
    return json({ media: rows.results || [] }, 200, cors(request));
  }
  if (request.method === "POST") {
    const form = await request.formData();
    const file = form.get("file");
    if (!(file instanceof File)) return json({ error: "File wajib diunggah" }, 400, cors(request));
    if (file.size > 25 * 1024 * 1024) return json({ error: "Ukuran file maksimal 25 MiB" }, 413, cors(request));
    const allowed = /^(image\/(jpeg|png|webp|gif)|application\/pdf)$/i;
    if (!allowed.test(file.type)) return json({ error: "Tipe file tidak didukung" }, 415, cors(request));
    const ext = (file.name.split(".").pop() || "bin").toLowerCase().replace(/[^a-z0-9]/g, "");
    const key = `media/${(/* @__PURE__ */ new Date()).toISOString().slice(0, 10)}/${crypto.randomUUID()}.${ext}`;
    await env.MEDIA.put(key, file.stream(), { httpMetadata: { contentType: file.type, cacheControl: "public, max-age=31536000, immutable" } });
    const mediaId = id("media");
    await env.DB.prepare("INSERT INTO media(id,object_key,filename,mime_type,size_bytes,alt_en,alt_id) VALUES(?,?,?,?,?,?,?)").bind(mediaId, key, file.name, file.type, file.size, form.get("alt_en") || null, form.get("alt_id") || null).run();
    await env.DB.prepare("INSERT INTO audit_logs(id,admin_id,action,entity_type,entity_id,metadata_json) VALUES(?,?,?,?,?,?)").bind(id("audit"), admin.id, "UPLOAD", "media", mediaId, JSON.stringify({ key, filename: file.name, size: file.size })).run();
    const base = env.MEDIA_PUBLIC_BASE_URL || "";
    return json({ ok: true, media: { id: mediaId, key, filename: file.name, mimeType: file.type, size: file.size, url: base ? `${base.replace(/\/$/, "")}/${key}` : null } }, 201, cors(request));
  }
  if (request.method === "DELETE") {
    const body = await request.json().catch(() => ({}));
    const media = await env.DB.prepare("SELECT * FROM media WHERE id=?").bind(body.id || "").first();
    if (!media) return json({ error: "Media tidak ditemukan" }, 404, cors(request));
    await env.MEDIA.delete(media.object_key);
    await env.DB.prepare("DELETE FROM media WHERE id=?").bind(media.id).run();
    await env.DB.prepare("INSERT INTO audit_logs(id,admin_id,action,entity_type,entity_id,metadata_json) VALUES(?,?,?,?,?,?)").bind(id("audit"), admin.id, "DELETE", "media", media.id, JSON.stringify({ key: media.object_key })).run();
    return json({ ok: true }, 200, cors(request));
  }
  return json({ error: "Method not allowed" }, 405, cors(request));
}
__name(adminMedia, "adminMedia");
async function loadPdfOrderItems(env, order) {
  const refs=[...new Set([
    String(order.id||"").trim(),
    String(order.order_number||"").trim(),
    String(order.order_number||"").trim().replace(/^#/,"")
  ].filter(Boolean))];

  let raw=[];
  for(const ref of refs){
    const result=await env.DB.prepare(
      "SELECT oi.*,p.weight_kg,p.dimensions_cm,p.sku AS product_sku,p.material,p.hs_code,p.package_type FROM order_items oi LEFT JOIN products p ON p.id=oi.product_id WHERE TRIM(CAST(oi.order_id AS TEXT))=? ORDER BY oi.rowid"
    ).bind(ref).all();
    raw=result.results||[];
    if(raw.length)break;
  }

  if(!raw.length && order.order_number){
    raw=(await env.DB.prepare(
      "SELECT oi.*,p.weight_kg,p.dimensions_cm,p.sku AS product_sku,p.material,p.hs_code,p.package_type FROM order_items oi LEFT JOIN products p ON p.id=oi.product_id WHERE lower(TRIM(CAST(oi.order_id AS TEXT)))=lower(TRIM(?)) ORDER BY oi.rowid"
    ).bind(String(order.order_number)).all()).results||[];
  }

  if(!raw.length && order.order_number){
    raw=(await env.DB.prepare(
      "SELECT oi.*,p.weight_kg,p.dimensions_cm,p.sku AS product_sku,p.material,p.hs_code,p.package_type FROM order_items oi LEFT JOIN products p ON p.id=oi.product_id WHERE oi.order_id=(SELECT id FROM orders WHERE lower(TRIM(order_number))=lower(TRIM(?)) LIMIT 1) ORDER BY oi.rowid"
    ).bind(String(order.order_number)).all()).results||[];
  }

  if(!raw.length)return [];

  return raw.map((item,index)=>({
    ...item,
    id:item.id||("pdf_item_"+index),
    product_name:item.product_name||item.name||"Product",
    name:item.name||item.product_name||"Product",
    quantity:Number(item.quantity??item.qty??0),
    qty:Number(item.qty??item.quantity??0),
    unit_price:Number(item.unit_price??item.price??0),
    price:Number(item.price??item.unit_price??0),
    total_price:Number(item.total_price??item.subtotal??item.total??0),
    currency:item.currency||order.original_currency||"USD",
    weight_kg:Number(item.weight_kg??0),
    dimensions_cm:item.dimensions_cm||"",
    sku:item.sku||item.product_sku||"",
    material:item.material||"",
    hs_code:item.hs_code||"",
    package_type:item.package_type||""
  }));
}
__name(loadPdfOrderItems, "loadPdfOrderItems");

async function ensureDocumentAuthSchema(env){
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS document_authentications (
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
  )`).run();
}
function documentVerificationBase(env){
  return String(env.PUBLIC_SITE_URL||"https://palma-rotan.pages.dev").replace(/\/$/,"");
}
async function ensureDocumentAuthentication(orderId,type,env){
  if(!["invoice","packing"].includes(String(type))) throw new Error("Jenis dokumen tidak valid");
  await ensureDocumentAuthSchema(env);
  const existing=await env.DB.prepare("SELECT * FROM document_authentications WHERE order_id=? AND document_type=?").bind(orderId,type).first();
  if(existing) return existing;
  const token=crypto.randomUUID().replace(/-/g,"")+crypto.randomUUID().replace(/-/g,"");
  const tokenHash=await sha256(token);
  const verificationUrl=documentVerificationBase(env)+"/verify-document/"+encodeURIComponent(type)+"/"+encodeURIComponent(token);
  const row={id:id("docauth"),order_id:orderId,document_type:type,token_hash:tokenHash,token,verification_url:verificationUrl};
  await env.DB.prepare("INSERT INTO document_authentications(id,order_id,document_type,token_hash,token,verification_url) VALUES(?,?,?,?,?,?)")
    .bind(row.id,row.order_id,row.document_type,row.token_hash,row.token,row.verification_url).run();
  return row;
}
async function publicDocumentVerification(request,env,type,token){
  if(!["invoice","packing"].includes(String(type))) return new Response("Dokumen tidak valid",{status:404});
  await ensureDocumentAuthSchema(env);
  const tokenHash=await sha256(String(token||""));
  const auth=await env.DB.prepare("SELECT da.*,o.order_number,o.created_at,o.payment_status,o.order_status,i.invoice_number,pk.packing_number,pk.tracking_number,pk.courier FROM document_authentications da JOIN orders o ON o.id=da.order_id LEFT JOIN invoices i ON i.order_id=o.id LEFT JOIN packing_orders pk ON pk.order_id=o.id WHERE da.document_type=? AND da.token_hash=? LIMIT 1").bind(type,tokenHash).first();
  if(!auth) return new Response("<!doctype html><meta charset='utf-8'><title>PALMA ROTAN — Verification</title><h1>Dokumen tidak valid</h1><p>Authentication token tidak ditemukan.</p>",{status:404,headers:{"content-type":"text/html;charset=utf-8","cache-control":"no-store"}});
  await env.DB.prepare("UPDATE document_authentications SET verified_at=CURRENT_TIMESTAMP WHERE id=?").bind(auth.id).run();
  const number=type==="invoice"?(auth.invoice_number||"-"):(auth.packing_number||"-");
  const html="<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>PALMA ROTAN — Document Verification</title><style>body{margin:0;background:#f5eee4;color:#211a15;font-family:Arial,sans-serif}.wrap{max-width:680px;margin:40px auto;padding:20px}.card{background:#fff;border:1px solid #dccbb6;border-radius:16px;padding:28px}dt{color:#6d6258;font-size:12px;margin-top:14px}dd{margin:4px 0;font-weight:700}</style></head><body><div class='wrap'><div class='card'><div>PALMA ROTAN</div><h1>Document Verified</h1><p>Dokumen "+(type==="invoice"?"Invoice":"Packing List")+" terdaftar pada sistem PALMA ROTAN.</p><dl><dt>Document Number</dt><dd>"+escEmail(number)+"</dd><dt>Order Number</dt><dd>"+escEmail(auth.order_number||"-")+"</dd><dt>Payment Status</dt><dd>"+escEmail(auth.payment_status||"-")+"</dd><dt>Order Status</dt><dd>"+escEmail(auth.order_status||"-")+"</dd><dt>Courier</dt><dd>"+escEmail(auth.courier||"-")+"</dd><dt>Tracking Number</dt><dd>"+escEmail(auth.tracking_number||"-")+"</dd></dl></div></div></body></html>";
  return new Response(html,{status:200,headers:{"content-type":"text/html;charset=utf-8","cache-control":"no-store"}});
}

function base64Url(value){return btoa(value)}
function base64UrlDecode(value){return atob(String(value||""))}
async function createDocumentAccessToken(env,type,ref){
  const secret=String(env.AUTH_PEPPER||"").trim();
  if(!secret) throw new Error("AUTH_PEPPER belum dikonfigurasi");
  const payload=encodeURIComponent(JSON.stringify({type:String(type),ref:String(ref),exp:Date.now()+5*60*1000}));
  const sig=await sha256(secret+"|document|"+payload);
  return base64Url(payload+"."+sig);
}
async function verifyDocumentAccessToken(env,token,type,ref){
  const secret=String(env.AUTH_PEPPER||"").trim();
  if(!secret||!token)return false;
  try{
    const raw=base64UrlDecode(token);
    const dot=raw.lastIndexOf(".");
    if(dot<1)return false;
    const payload=raw.slice(0,dot),sig=raw.slice(dot+1);
    const expected=await sha256(secret+"|document|"+payload);
    if(sig!==expected)return false;
    const data=JSON.parse(decodeURIComponent(payload));
    return data?.type===String(type)&&data?.ref===String(ref)&&Number(data?.exp)>Date.now();
  }catch(_){return false}
}
async function adminDocumentAccess(request,env){
  const admin=await requireAdmin(request,env);
  if(!admin)return json({error:"Unauthorized"},401,cors(request));
  const body=await request.json().catch(()=>({}));
  const type=["invoice","packing","label"].includes(String(body.type))?String(body.type):"";
  const ref=String(body.ref||"").trim();
  if(!type||!ref)return json({error:"Jenis dokumen dan order reference wajib diisi"},400,cors(request));
  let decoded=ref;try{decoded=decodeURIComponent(ref)}catch(_){}
  const order=await env.DB.prepare("SELECT id FROM orders WHERE id=? OR order_number=? OR lower(order_number)=lower(?) LIMIT 1").bind(decoded,decoded,decoded).first();
  if(!order)return json({error:"Order tidak ditemukan",reference:decoded},404,cors(request));
  const token=await createDocumentAccessToken(env,type,decoded);
  const url=new URL(request.url);
  url.pathname="/api/admin/documents/"+type+"/"+encodeURIComponent(decoded);
  url.search="?access_token="+encodeURIComponent(token);
  return json({ok:true,url:url.toString(),expiresInSeconds:300},200,cors(request));
}

async function documentPdf(request, env, type, orderId) {
  await ensureShippingSchema(env);
  await ensureProductLogisticsSchema(env);
  let ref = String(orderId || "").trim();
  try { ref = decodeURIComponent(ref); } catch (_) {}
  ref = ref.replace(/^#/, "").trim();
  const accessToken = new URL(request.url).searchParams.get("access_token") || "";
  const admin = await requireAdmin(request, env);
  const authorizedByLink = await verifyDocumentAccessToken(env, accessToken, type, ref);
  if (!admin && !authorizedByLink) return json({ error: "Unauthorized" }, 401, cors(request));
  if (!ref) return json({ error: "Order reference wajib diisi" }, 400, cors(request));
  let order = await env.DB.prepare(`SELECT o.*,c.first_name,c.last_name,c.email,c.phone,i.invoice_number,pk.packing_number,pk.courier,pk.tracking_number,pk.tracking_url,pk.package_count,pk.status AS packing_status,pk.auth_code FROM orders o LEFT JOIN customers c ON c.id=o.customer_id LEFT JOIN invoices i ON i.order_id=o.id LEFT JOIN packing_orders pk ON pk.order_id=o.id WHERE o.id=? OR o.order_number=? OR lower(o.order_number)=lower(?) LIMIT 1`).bind(ref,ref,ref).first();
  if (!order) return json({error:"Order tidak ditemukan",reference:ref},404,cors(request));
  const ensuredPack=await ensurePackingAuth(order.id,env);
  if(ensuredPack)order={...order,...ensuredPack};
  order.tracking_link=trackingUrl(order,env);
  if(type==="invoice" || type==="packing"){
    const docAuth=await ensureDocumentAuthentication(order.id,type,env);
    order.document_auth_token=docAuth.token;
    order.document_verification_url=docAuth.verification_url;
  }
  const items = await loadPdfOrderItems(env, order);
  const brandRows = await env.DB.prepare("SELECT key,value_json FROM site_settings WHERE key IN ('brand','website','whatsapp','email','address','pdfTagline1','pdfTagline2')").all();
  const branding = Object.fromEntries((brandRows.results || []).map((row) => {
    let value = row.value_json;
    try { value = JSON.parse(value); } catch (_) {}
    return [row.key, value];
  }));
  const bytes = type === "label" ? makeShippingLabelPdf(order, branding) : await makeProfessionalPdf(type, order, items, branding);
  // PDF delivery is independent of optional R2 storage.
  // R2 persistence must never prevent the production document from opening.
  if (env.MEDIA) {
    try {
      const key = `documents/${type}/${order.order_number}.pdf`;
      await env.MEDIA.put(key, bytes, {httpMetadata:{contentType:"application/pdf",cacheControl:"private, no-store"}});
    } catch (storageError) {
      console.error("PDF_R2_STORE_ERROR", {type, orderId: order.id, message: storageError?.message || String(storageError)});
    }
  }
  return new Response(bytes,{status:200,headers:{"content-type":"application/pdf","content-disposition":`inline; filename="${type}-${order.order_number}.pdf"`,"cache-control":"private, no-store","access-control-allow-origin":cors(request),"access-control-allow-headers":"content-type, authorization, x-bootstrap-secret"}});
}
__name(documentPdf, "documentPdf");
async function adminSettings(request, env) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: "Unauthorized" }, 401, cors(request));
  if (request.method === "GET") {
    const rows = await env.DB.prepare("SELECT key,value_json FROM site_settings").all();
    return json({ settings: Object.fromEntries((rows.results || []).map((x) => [x.key, JSON.parse(x.value_json)])) }, 200, cors(request));
  }
  const body = await request.json();
  for (const [key, value] of Object.entries(body)) await env.DB.prepare(`INSERT INTO site_settings(key,value_json) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=CURRENT_TIMESTAMP`).bind(key, JSON.stringify(value)).run();
  await env.DB.prepare("INSERT INTO audit_logs(id,admin_id,action,entity_type,metadata_json) VALUES(?,?,?,?,?)").bind(id("audit"), admin.id, "UPDATE", "site_settings", JSON.stringify(body)).run();
  return json({ ok: true }, 200, cors(request));
}
__name(adminSettings, "adminSettings");
async function publicSettings(request, env) {
  if (request.method !== "GET") {
    return json({ error: "Method not allowed" }, 405, cors(request));
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
  }, 200, cors(request));
}

__name(publicSettings, "publicSettings");

async function publicTracking(request,env,orderNumber,authCode){const order=await env.DB.prepare("SELECT o.id,o.order_number,o.order_status,o.payment_status,o.created_at,pk.packing_number,pk.courier,pk.tracking_number,pk.tracking_url,pk.status AS shipping_status,pk.shipped_at,pk.delivered_at,pk.auth_code FROM orders o LEFT JOIN packing_orders pk ON pk.order_id=o.id WHERE lower(o.order_number)=lower(?) LIMIT 1").bind(orderNumber).first();if(!order||!order.auth_code||String(order.auth_code)!==String(authCode))return new Response("Tracking link tidak valid atau sudah tidak tersedia.",{status:404,headers:{"content-type":"text/html; charset=utf-8"}});const events=(await env.DB.prepare("SELECT status,event_time,location,description,source FROM tracking_events WHERE order_id=? ORDER BY event_time DESC").bind(order.id).all()).results||[];const rows=await env.DB.prepare("SELECT key,value_json FROM site_settings WHERE key IN ('brand','website','whatsapp','email')").all(),b=Object.fromEntries((rows.results||[]).map(row=>{let v=row.value_json;try{v=JSON.parse(v)}catch(_){}return [row.key,v]})),safe=v=>escEmail(v),external=order.tracking_url?String(order.tracking_url):"",eventHtml=events.length?events.map(e=>"<div style='padding:10px 0;border-bottom:1px solid #eadfd2'><b>"+safe(e.status)+"</b> — "+safe(e.event_time||"")+"<br><span class='muted'>"+safe(e.location||"")+" "+safe(e.description||"")+"</span></div>").join(""):"<p class='muted'>Belum ada tracking event.</p>";const html="<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>"+safe(b.brand||"PALMA ROTAN")+" — Tracking "+safe(order.order_number)+"</title><style>body{margin:0;background:#f5eee4;color:#211a15;font-family:Arial,sans-serif}.wrap{max-width:720px;margin:40px auto;padding:24px}.card{background:#fff;border:1px solid #dccbb6;border-radius:16px;padding:28px;box-shadow:0 12px 30px rgba(33,26,21,.08)}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:22px}.item{border:1px solid #eadfd2;border-radius:10px;padding:14px}.muted{color:#6d6258}.status{font-weight:700}.btn{display:inline-block;margin-top:20px;padding:12px 18px;border-radius:8px;background:#211a15;color:#fff;text-decoration:none}@media(max-width:600px){.wrap{margin:12px auto;padding:12px}.grid{grid-template-columns:1fr}}</style></head><body><div class=\"wrap\"><div class=\"card\"><div class=\"muted\">"+safe(b.brand||"PALMA ROTAN")+"</div><h1>Tracking Pesanan</h1><p class=\"muted\">Order <b>"+safe(order.order_number)+"</b></p><div class=\"grid\"><div class=\"item\"><div class=\"muted\">Status Order</div><div class=\"status\">"+safe(order.order_status||"PROCESSING")+"</div></div><div class=\"item\"><div class=\"muted\">Status Pengiriman</div><div class=\"status\">"+safe(order.shipping_status||"PENDING")+"</div></div><div class=\"item\"><div class=\"muted\">Kurir</div><div class=\"status\">"+safe(order.courier||"Belum ditentukan")+"</div></div><div class=\"item\"><div class=\"muted\">Nomor Resi</div><div class=\"status\">"+safe(order.tracking_number||"Belum tersedia")+"</div></div><div class=\"item\"><div class=\"muted\">Packing List</div><div class=\"status\">"+safe(order.packing_number||"-")+"</div></div><div class=\"item\"><div class=\"muted\">Pembayaran</div><div class=\"status\">"+safe(order.payment_status||"PENDING")+"</div></div></div><div style=\"margin-top:24px\"><h3>Tracking Events</h3>"+eventHtml+"</div>"+(external?"<a class=\"btn\" href=\""+safe(external)+"\" target=\"_blank\" rel=\"noopener\">Buka Tracking Kurir</a>":"")+"<p class=\"muted\" style=\"margin-top:26px;font-size:12px\">Halaman ini menggunakan link autentikasi unik untuk pesanan.</p></div></div></body></html>";return new Response(html,{status:200,headers:{"content-type":"text/html; charset=utf-8","cache-control":"private, no-store"}})}
__name(publicTracking,"publicTracking");
var index_default = {
  
  async fetch(request, env) {
  const origin = cors(request);
  if (request.method === "OPTIONS") {
    const requestedHeaders = request.headers.get("access-control-request-headers") || "content-type, authorization, x-bootstrap-secret";
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": origin,
        "access-control-allow-headers": requestedHeaders,
        "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
        "access-control-max-age": "86400",
        "vary": "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
      }
    });
  }
  const url = new URL(request.url);
  try {
    if (url.pathname === "/api/health") return json({ ok: true, environment: env.ENVIRONMENT || "unknown", build: BUILD_ID }, 200, origin);
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
    const verifyMatch = url.pathname.match(/^\/verify-document\/(invoice|packing)\/([^/]+)$/);
    if (verifyMatch && request.method === "GET") return publicDocumentVerification(request, env, decodeURIComponent(verifyMatch[1]), decodeURIComponent(verifyMatch[2]));
    if (url.pathname === "/api/admin/products" && ["GET", "POST", "PUT", "PATCH"].includes(request.method)) return adminProducts(request, env);
    if (url.pathname === "/api/payment/webhook" && request.method === "POST") return paymentWebhook(request, env);
    if (url.pathname === "/api/admin/payments/verify" && request.method === "POST") return adminVerifyPayment(request, env);
    if (url.pathname === "/api/admin/settings" && ["GET", "PATCH", "PUT"].includes(request.method)) return adminSettings(request, env);
    if (url.pathname === "/api/admin/media" && ["GET", "POST", "DELETE"].includes(request.method)) return adminMedia(request, env);
    if (url.pathname === "/api/admin/documents/access" && request.method === "POST") return adminDocumentAccess(request, env);
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
