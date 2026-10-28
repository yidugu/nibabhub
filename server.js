/* Nibab Hub — የኢሜይል ማረጋገጫ ሰርቨር (Node.js 18+)
 * ከማንኛውም ቦታ ይሰራል፦ VPS፣ cPanel (Node app)፣ Render፣ Railway፣ Fly.io፣ ወዘተ።
 * Endpoints:  POST /api/send-code   { email }
 *             POST /api/verify-code { email, code, token }
 * ኢሜይል በ SMTP ይላካል (የራስዎ ዶሜይን ኢሜይል፣ Gmail App Password፣ Brevo SMTP፣ ወዘተ)። */
"use strict";
const http = require("http");
const crypto = require("crypto");

const PORT = +process.env.PORT || 3000;
const SECRET = process.env.CODE_SECRET || "";
const ORIGINS = (process.env.ALLOWED_ORIGIN || "*").split(",").map(s => s.trim()).filter(Boolean);
const FROM = process.env.MAIL_FROM || process.env.SMTP_USER || "";
const DEBUG_MAIL = process.env.MAIL_DEBUG === "1";   // ለሙከራ፦ ኮዱን ኢሜይል ሳይልክ በኮንሶል ያሳያል
const TTL = 10 * 60 * 1000;
const PAY_TO = process.env.PAY_TO || "nibabhubet@gmail.com";   // የክፍያ ደረሰኞች የሚላኩበት ኢሜይል

if (!SECRET || SECRET.length < 16) { console.error("✖ CODE_SECRET (ቢያንስ 16 ፊደል) ያስፈልጋል"); process.exit(1); }

let transporter = null;
function mailer() {
  if (transporter) return transporter;
  const nodemailer = require("nodemailer");
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: +process.env.SMTP_PORT || 587,
    secure: process.env.SMTP_SECURE === "1" || +process.env.SMTP_PORT === 465,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
  });
  return transporter;
}

/* ቀላል ገደብ (በሜሞሪ) */
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now(), a = (hits.get(key) || []).filter(t => now - t < windowMs);
  if (a.length >= max) { hits.set(key, a); return true; }
  a.push(now); hits.set(key, a); return false;
}
const tries = new Map(); // token sig -> ሙከራዎች
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of hits) { const a = v.filter(t => now - t < 3600e3); a.length ? hits.set(k, a) : hits.delete(k); }
  for (const [k, v] of tries) if (now > v.x) tries.delete(k);
}, 600e3).unref();

function cors(req, res) {
  const o = req.headers.origin;
  if (ORIGINS.includes("*")) res.setHeader("Access-Control-Allow-Origin", "*");
  else if (o && ORIGINS.includes(o)) { res.setHeader("Access-Control-Allow-Origin", o); res.setHeader("Vary", "Origin"); }
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}
function send(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(obj));
}
function body(req, max) {
  max = max || 8192;
  return new Promise((ok) => {
    let s = "", big = false;
    req.on("data", c => { if (big) return; s += c; if (s.length > max) { big = true; s = ""; } });
    req.on("end", () => { if (big) return ok({ __big: true }); try { ok(JSON.parse(s || "{}")); } catch (e) { ok({}); } });
    req.on("error", () => ok({}));
  });
}
const sign = (email, exp, code) => crypto.createHmac("sha256", SECRET).update(email + "|" + exp + "|" + code).digest("hex");
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

async function sendCode(req, res) {
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").toString().split(",")[0].trim();
  const b = await body(req);
  const email = String(b.email || "").trim().toLowerCase();
  if (!EMAIL_RE.test(email) || email.length > 120) return send(res, 400, { ok: false, message: "ኢሜይሉ ትክክል አይደለም" });
  if (limited("ip:" + ip, 20, 3600e3) || limited("em:" + email, 5, 3600e3))
    return send(res, 429, { ok: false, message: "ብዙ ጊዜ ጠይቀዋል — ከትንሽ ቆይታ በኋላ ይሞክሩ" });

  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  const exp = Date.now() + TTL;
  const token = Buffer.from(JSON.stringify({ e: email, x: exp, s: sign(email, exp, code) })).toString("base64url");

  if (DEBUG_MAIL) { console.log("[MAIL_DEBUG]", email, "→ ኮድ:", code); return send(res, 200, { ok: true, token }); }
  try {
    await mailer().sendMail({
      from: FROM, to: email, subject: "የማረጋገጫ ኮድ — Nibab Hub",
      text: "የማረጋገጫ ኮድዎ፦ " + code + "\nኮዱ ለ10 ደቂቃ ያገለግላል። እርስዎ ካልጠየቁ ይህን መልዕክት ችላ ይበሉ።",
      html: '<div style="font-family:sans-serif;max-width:380px;margin:auto;text-align:center"><h2>Nibab Hub</h2><p>የማረጋገጫ ኮድዎ፦</p>' +
            '<div style="font-size:34px;font-weight:700;letter-spacing:8px;color:#1f5e3b">' + code + "</div>" +
            '<p style="color:#666;font-size:13px">ኮዱ ለ10 ደቂቃ ያገለግላል። እርስዎ ካልጠየቁ ይህን መልዕክት ችላ ይበሉ።</p></div>'
    });
  } catch (e) {
    console.error("SMTP error:", e && e.message);
    return send(res, 502, { ok: false, message: "ኢሜይል መላክ አልተቻለም — ቆይተው ይሞክሩ" });
  }
  send(res, 200, { ok: true, token });
}

async function verifyCode(req, res) {
  const b = await body(req);
  const email = String(b.email || "").trim().toLowerCase(), code = String(b.code || "").trim();
  let tk = null;
  try { tk = JSON.parse(Buffer.from(String(b.token || ""), "base64url").toString()); } catch (e) {}
  const bad = () => send(res, 400, { ok: false, message: "ኮዱ ትክክል አይደለም" });
  if (!tk || tk.e !== email || !/^\d{6}$/.test(code) || typeof tk.s !== "string") return bad();
  if (Date.now() > Number(tk.x)) return send(res, 400, { ok: false, message: "ኮዱ ጊዜው አልፏል — እንደገና ይላኩ" });
  const t = tries.get(tk.s) || { n: 0, x: +tk.x };
  if (t.n >= 5) return send(res, 429, { ok: false, message: "ብዙ ጊዜ ሞክረዋል — አዲስ ኮድ ይጠይቁ" });
  t.n++; tries.set(tk.s, t);
  const a = Buffer.from(sign(email, tk.x, code)), c = Buffer.from(tk.s);
  if (a.length !== c.length || !crypto.timingSafeEqual(a, c)) return bad();
  tries.delete(tk.s);
  send(res, 200, { ok: true });
}

const esc = (x) => String(x == null ? "" : x).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const PLANS = { basic: 20, standard: 49, pro: 99 };
const METHODS = ["Telebirr", "Dashen Bank", "M-Pesa"];

async function paymentProof(req, res) {
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").toString().split(",")[0].trim();
  const b = await body(req, 3.5 * 1024 * 1024);
  if (b.__big) return send(res, 413, { ok: false, message: "ፎቶው በጣም ትልቅ ነው — ትንሽ ፎቶ ይሞክሩ" });
  const name = String(b.name || "").trim().slice(0, 80);
  const contact = String(b.contact || "").trim().slice(0, 120);
  const ref = String(b.ref || "").trim().slice(0, 60);
  const planId = String(b.planId || "");
  const plan = String(b.plan || "").slice(0, 60);
  const method = METHODS.includes(b.method) ? b.method : "";
  const amount = Number(b.amount);
  if (name.length < 2 || contact.length < 5 || !method || !(planId in PLANS) || PLANS[planId] !== amount)
    return send(res, 400, { ok: false, message: "መረጃው ሙሉ አይደለም — እባክዎ ቅጹን ያስተካክሉ" });
  const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String(b.image || ""));
  if (!m) return send(res, 400, { ok: false, message: "የፎቶ ቅርጸቱ ተቀባይነት የለውም" });
  const buf = Buffer.from(m[2], "base64");
  const okMagic = (buf[0] === 0xFF && buf[1] === 0xD8) || (buf[0] === 0x89 && buf[1] === 0x50) || buf.slice(0, 4).toString() === "RIFF";
  if (!okMagic || buf.length < 1000 || buf.length > 2.6 * 1024 * 1024)
    return send(res, 400, { ok: false, message: "ፎቶው ትክክል አይደለም ወይም በጣም ትልቅ ነው" });
  if (limited("pip:" + ip, 6, 3600e3) || limited("pct:" + contact.toLowerCase(), 4, 3600e3))
    return send(res, 429, { ok: false, message: "ብዙ ጊዜ ልከዋል — ከትንሽ ቆይታ በኋላ ይሞክሩ" });

  const ext = m[1] === "jpeg" ? "jpg" : m[1];
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const subject = "💳 ክፍያ — " + plan + " — " + amount + " ETB — " + name;
  const html = '<div style="font-family:sans-serif;max-width:480px">' +
    "<h3>አዲስ የክፍያ ደረሰኝ — Nibab Hub</h3><table cellpadding='6' style='border-collapse:collapse'>" +
    [["ዕቅድ", plan + " (" + esc(b.days) + " ቀን)"], ["መጠን", amount + " ETB"], ["የክፍያ መንገድ", method], ["ስም", name],
     ["ስልክ/ኢሜይል", contact], ["የግብይት ቁጥር", ref || "—"], ["ሰዓት", new Date().toISOString()], ["IP", ip]]
      .map((r) => "<tr><td style='color:#666'>" + r[0] + "</td><td><b>" + esc(r[1]) + "</b></td></tr>").join("") +
    "</table><p>የደረሰኙ ፎቶ ተያይዟል።</p></div>";

  if (DEBUG_MAIL) { console.log("[MAIL_DEBUG] payment-proof", { to: PAY_TO, subject, bytes: buf.length }); return send(res, 200, { ok: true }); }
  try {
    await mailer().sendMail({
      from: FROM, to: PAY_TO, subject, html,
      replyTo: EMAIL_RE.test(contact) ? contact : undefined,
      attachments: [{ filename: "receipt-" + stamp + "." + ext, content: buf, contentType: "image/" + m[1] }]
    });
  } catch (e) {
    console.error("SMTP error (payment):", e && e.message);
    return send(res, 502, { ok: false, message: "መላክ አልተቻለም — ቆይተው ይሞክሩ" });
  }
  send(res, 200, { ok: true });
}

http.createServer((req, res) => {
  cors(req, res);
  const path = (req.url || "").split("?")[0];
  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }
  if (req.method === "GET" && path === "/health") return send(res, 200, { ok: true });
  if (req.method === "POST" && path === "/api/send-code") return sendCode(req, res).catch(() => send(res, 500, { ok: false, message: "ስህተት ተፈጥሯል" }));
  if (req.method === "POST" && path === "/api/payment-proof") return paymentProof(req, res).catch(() => send(res, 500, { ok: false, message: "ስህተት ተፈጥሯል" }));
  if (req.method === "POST" && path === "/api/verify-code") return verifyCode(req, res).catch(() => send(res, 500, { ok: false, message: "ስህተት ተፈጥሯል" }));
  send(res, 404, { ok: false, message: "Not found" });
}).listen(PORT, () => console.log("Nibab verify server ::" + PORT + (DEBUG_MAIL ? "  (MAIL_DEBUG)" : "")));
