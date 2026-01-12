// src/index.js
import PostalMime from "postal-mime";

/**
 * Cloudflare Email Routing + Email Worker + Web Inbox
 * Features:
 * - Signup/Login/Logout
 * - Reset password via Resend (optional; but recommended)
 * - Mail (alias) management with per-user limit
 * - Admin dashboard: list users, set mail limit, disable user
 * - Email handler: accept via catch-all, store if mail registered else reject
 */

const encoder = new TextEncoder();

// -------------------- Security/Hashing constants --------------------
const PBKDF2_MAX_ITERS = 100000; // Cloudflare Workers WebCrypto limit
const PBKDF2_MIN_ITERS = 10000; // sensible floor

let USERS_HAS_PASS_ITERS = null;

// -------------------- Response helpers --------------------
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      ...headers,
    },
  });
}

function html(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      ...headers,
    },
  });
}

function badRequest(msg) {
  return json({ ok: false, error: msg }, 400);
}
function unauthorized(msg = "Unauthorized") {
  return json({ ok: false, error: msg }, 401);
}
function forbidden(msg = "Forbidden") {
  return json({ ok: false, error: msg }, 403);
}
function notFound() {
  return json({ ok: false, error: "Not found" }, 404);
}

// -------------------- Utils --------------------
function safeInt(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function clampPbkdf2Iters(n) {
  const x = safeInt(n, PBKDF2_MAX_ITERS);
  return Math.min(PBKDF2_MAX_ITERS, Math.max(PBKDF2_MIN_ITERS, x));
}

function pbkdf2Iters(env) {
  return clampPbkdf2Iters(env.PBKDF2_ITERS ?? PBKDF2_MAX_ITERS);
}

function base64Url(bytes) {
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(b64url) {
  const b64 = String(b64url || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(b64 + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256Base64Url(inputBytes) {
  const digest = await crypto.subtle.digest("SHA-256", inputBytes);
  return base64Url(new Uint8Array(digest));
}

async function pbkdf2HashBase64Url(password, saltBytes, iterations) {
  const it = safeInt(iterations, 0);
  if (it > PBKDF2_MAX_ITERS) {
    const err = new Error(
      `PBKDF2 iterations too high for Workers (max ${PBKDF2_MAX_ITERS}, got ${it}).`
    );
    err.name = "NotSupportedError";
    throw err;
  }

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: it },
    keyMaterial,
    256
  );

  return base64Url(new Uint8Array(bits));
}

function getCookie(request, name) {
  const cookie = request.headers.get("cookie") || "";
  const parts = cookie.split(";").map((p) => p.trim());
  for (const p of parts) {
    const [k, ...rest] = p.split("=");
    if (k === name) return rest.join("=");
  }
  return null;
}

function setCookieHeader(name, value, opts = {}) {
  const { httpOnly = true, secure = true, sameSite = "Lax", path = "/", maxAge } = opts;

  let c = `${name}=${value}; Path=${path}; SameSite=${sameSite}`;
  if (httpOnly) c += "; HttpOnly";
  if (secure) c += "; Secure";
  if (typeof maxAge === "number") c += `; Max-Age=${maxAge}`;
  return c;
}

async function readJson(request) {
  try {
    const ct = request.headers.get("content-type") || "";
    if (!ct.toLowerCase().includes("application/json")) return null;
    return await request.json();
  } catch {
    return null;
  }
}

function validLocalPart(local) {
  return /^[a-z0-9][a-z0-9._+-]{0,63}$/.test(local);
}

async function usersHasPassIters(env) {
  if (USERS_HAS_PASS_ITERS !== null) return USERS_HAS_PASS_ITERS;
  try {
    const res = await env.DB.prepare(`PRAGMA table_info(users)`).all();
    USERS_HAS_PASS_ITERS = (res.results || []).some((r) => r?.name === "pass_iters");
  } catch {
    USERS_HAS_PASS_ITERS = false;
  }
  return USERS_HAS_PASS_ITERS;
}

// -------------------- UI: Brand + Template --------------------
const LOGO_SVG = `
<svg viewBox="0 0 64 64" width="40" height="40" aria-hidden="true" focusable="false">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#60a5fa"/>
      <stop offset="1" stop-color="#818cf8"/>
    </linearGradient>
    <filter id="s" x="-30%" y="-30%" width="160%" height="160%">
      <feDropShadow dx="0" dy="8" stdDeviation="8" flood-color="#000" flood-opacity="0.35"/>
    </filter>
  </defs>
  <rect x="10" y="10" width="44" height="44" rx="12" fill="url(#g)" filter="url(#s)"/>
  <rect x="14" y="14" width="36" height="36" rx="10" fill="rgba(10,14,20,0.55)"/>
  <text x="32" y="40" text-anchor="middle" font-size="20" font-family="ui-sans-serif,system-ui,Arial" fill="#eef2ff" font-weight="800">OL</text>
</svg>
`;

const FAVICON_DATA = encodeURIComponent(`
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#60a5fa"/>
      <stop offset="1" stop-color="#818cf8"/>
    </linearGradient>
  </defs>
  <rect x="8" y="8" width="48" height="48" rx="14" fill="url(#g)"/>
  <text x="32" y="41" text-anchor="middle" font-size="22" font-family="Arial" fill="#0b0f14" font-weight="800">OL</text>
</svg>
`);

function headerHtml({ badge, subtitle, rightHtml = "" }) {
  return `
  <header class="hdr">
    <div class="brand">
      <div class="logo">${LOGO_SVG}</div>
      <div class="brandText">
        <div class="brandName">Org_Lemah</div>
        <div class="brandSub">${subtitle || ""}</div>
      </div>
      ${badge ? `<span class="pill">${badge}</span>` : ""}
    </div>
    <div class="hdrRight">${rightHtml}</div>
  </header>`;
}

function pageTemplate(title, body, extraHead = "") {
  return `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${title}</title>
  <meta name="theme-color" content="#070a10">
  <link rel="icon" href="data:image/svg+xml,${FAVICON_DATA}">
  <meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    base-uri 'none';
    object-src 'none';
    form-action 'self';
    frame-ancestors 'none';
    img-src 'self' data: https:;
    style-src 'self' 'unsafe-inline';
    script-src 'self' 'unsafe-inline';
    connect-src 'self';
    frame-src 'self';
  ">
  ${extraHead}
  <style>
    :root{
      /* Modern Professional Dark Theme */
      --bg0: #0B0E14;
      --bg1: #10141C;
      --bg2: #161B26;

      --card: linear-gradient(135deg, rgba(18,24,38,.95), rgba(12,17,29,.92));
      --card-hover: linear-gradient(135deg, rgba(22,30,46,.98), rgba(15,20,34,.95));
      --card2: rgba(16,22,36,.88);
      --border: rgba(56,72,105,.35);
      --border-focus: rgba(96,165,250,.45);

      --text: #F0F4FF;
      --text-bright: #FFFFFF;
      --muted: #9BA9C1;
      --muted-dark: #6B7A92;

      /* Enhanced Brand Colors */
      --brand: #60A5FA;
      --brand-light: #93C5FD;
      --brand-dark: #3B82F6;
      --brand2: #818CF8;
      --accent: #8B5CF6;
      --success: #10B981;
      --warning: #F59E0B;
      --danger: #EF4444;

      /* Shadows */
      --shadow-sm: 0 2px 8px rgba(0,0,0,.2);
      --shadow-md: 0 8px 24px rgba(0,0,0,.3);
      --shadow-lg: 0 16px 48px rgba(0,0,0,.4);
      --shadow-brand: 0 8px 24px rgba(96,165,250,.15);

      /* Paper */
      --paper: #FAFBFC;
      --paperText: #0F172A;
      --paperBorder: rgba(15,23,42,.08);
    }

    *{box-sizing:border-box; margin:0; padding:0;}
    
    body{
      font-family: 'Inter', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif;
      margin:0;
      color:var(--text);
      min-height:100vh;
      background:
        radial-gradient(1400px 700px at 25% -15%, rgba(96,165,250,.12), transparent 65%),
        radial-gradient(1000px 600px at 85% 5%, rgba(139,92,246,.08), transparent 60%),
        radial-gradient(800px 500px at 50% 100%, rgba(129,140,248,.06), transparent 55%),
        linear-gradient(180deg, var(--bg1), var(--bg0));
      background-attachment: fixed;
    }

    a{color:var(--brand-light); text-decoration:none; transition: color .2s ease;}
    a:hover{color:var(--brand); text-decoration:underline;}

    .wrap{max-width:1100px; margin:0 auto; padding:24px;}
    
    .hdr{
      display:flex; justify-content:space-between; align-items:center;
      gap:16px; padding:14px 0 10px;
      margin-bottom: 8px;
    }
    .brand{display:flex; align-items:center; gap:14px; flex-wrap:wrap;}
    .logo{display:flex; align-items:center;}
    .brandText{display:flex; flex-direction:column; line-height:1.1;}
    .brandName{font-weight:800; font-size:18px; letter-spacing:.3px; color:var(--text-bright);}
    .brandSub{color:var(--muted); font-size:13px; margin-top:5px; font-weight:500;}
    .hdrRight{display:flex; gap:12px; align-items:center; flex-wrap:wrap;}

    .card{
      background: var(--card);
      border:1px solid var(--border);
      border-radius:20px;
      padding:24px;
      margin:16px 0;
      box-shadow: var(--shadow-lg);
      transition: transform .2s ease, box-shadow .2s ease;
      position: relative;
      overflow: hidden;
    }
    .card::before{
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 1px;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,.1), transparent);
    }
    .card:hover{
      transform: translateY(-2px);
      box-shadow: var(--shadow-lg), var(--shadow-brand);
    }

    input, button, select, textarea{font:inherit;}
    
    label{
      display:block; 
      margin-bottom:8px; 
      color:var(--muted); 
      font-size:13px; 
      font-weight:600;
      letter-spacing:.3px;
      text-transform: uppercase;
    }
    
    input, select, textarea{
      width:100%;
      padding:14px 16px;
      border-radius:12px;
      border:1.5px solid var(--border);
      background: var(--card2);
      color:var(--text);
      outline:none;
      font-size: 15px;
      transition: all .2s ease;
    }
    input::placeholder{color: var(--muted-dark); opacity:.7;}
    input:focus, select:focus, textarea:focus{
      border-color: var(--border-focus);
      box-shadow: 0 0 0 3px rgba(96,165,250,.08), var(--shadow-sm);
      background: rgba(18,25,42,.92);
    }

    /* Password show/hide */
    .pwWrap{position:relative;}
    .pwWrap input{padding-right: 100px;}
    .pwToggle{
      position:absolute;
      right:12px;
      top:50%;
      transform:translateY(-50%);
      padding:7px 12px;
      border-radius:8px;
      border:1px solid var(--border);
      background: rgba(96,165,250,.08);
      color: var(--brand-light);
      font-size:12px;
      font-weight:600;
      cursor:pointer;
      transition: all .2s ease;
    }
    .pwToggle:hover{
      background: rgba(96,165,250,.15);
      color: var(--text-bright);
      border-color: var(--border-focus);
      transform:translateY(-50%) scale(1.05);
    }

    button{
      padding:11px 18px;
      border-radius:12px;
      border:1.5px solid var(--border);
      background: rgba(96,165,250,.1);
      color:var(--text);
      cursor:pointer;
      font-weight:600;
      font-size:14px;
      transition: all .2s ease;
      white-space:nowrap;
      box-shadow: var(--shadow-sm);
    }
    button:hover{
      background: rgba(96,165,250,.18);
      border-color: var(--border-focus);
      transform: translateY(-1px);
      box-shadow: var(--shadow-md);
    }
    button:active{transform: translateY(0); box-shadow: var(--shadow-sm);}
    
    .btn-primary{
      background: linear-gradient(135deg, rgba(96,165,250,.35), rgba(129,140,248,.25));
      border-color: rgba(96,165,250,.5);
      color: var(--text-bright);
      box-shadow: var(--shadow-md), 0 0 20px rgba(96,165,250,.15);
    }
    .btn-primary:hover{
      background: linear-gradient(135deg, rgba(96,165,250,.45), rgba(129,140,248,.35));
      border-color: var(--brand-light);
      box-shadow: var(--shadow-md), 0 0 30px rgba(96,165,250,.25);
    }
    
    .btn-ghost{
      background: rgba(255,255,255,.03);
      border-color: rgba(255,255,255,.08);
    }
    .btn-ghost:hover{
      background: rgba(255,255,255,.08);
      border-color: rgba(255,255,255,.15);
    }
    
    .danger{
      border-color: rgba(239,68,68,.5);
      background: rgba(239,68,68,.12);
      color: #FCA5A5;
    }
    .danger:hover{
      background: rgba(239,68,68,.2); 
      border-color: rgba(239,68,68,.65);
      color: #FEE2E2;
    }

    .muted{color:var(--muted);}
    
    .pill{
      display:inline-flex; align-items:center; gap:6px;
      padding:7px 13px; border-radius:999px;
      border:1px solid var(--border);
      background: rgba(255,255,255,.05);
      color:var(--muted);
      font-size:12px;
      font-weight:600;
      transition: all .2s ease;
      box-shadow: var(--shadow-sm);
    }
    .pill:hover{
      background: rgba(255,255,255,.08);
      border-color: var(--border-focus);
      transform: scale(1.02);
    }
    
    .kbd{
      font-family: ui-monospace, 'SF Mono', Menlo, Monaco, 'Cascadia Code', monospace;
      font-size: 12px;
      padding:4px 10px;
      border-radius:6px;
      border:1px solid var(--border);
      background: rgba(96,165,250,.08);
      color: var(--brand-light);
      font-weight:600;
    }

    .row{display:grid; grid-template-columns:1fr 1fr; gap:16px;}
    .split{display:grid; grid-template-columns:1fr 1fr; gap:18px; align-items:start;}

    .listItem{
      padding:16px 0;
      border-bottom:1px solid var(--border);
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:12px;
      flex-wrap:wrap;
      transition: all .2s ease;
    }
    .listItem:hover{
      padding-left: 8px;
      border-bottom-color: var(--border-focus);
    }

    /* Inbox list */
    .mailItem{
      padding:16px 18px;
      border:1px solid var(--border);
      border-radius:14px;
      background: linear-gradient(135deg, rgba(255,255,255,.04), rgba(255,255,255,.02));
      margin-bottom:12px;
      transition: all .2s ease;
      box-shadow: var(--shadow-sm);
    }
    .mailItem:hover{
      background: linear-gradient(135deg, rgba(255,255,255,.07), rgba(255,255,255,.04));
      border-color: var(--border-focus);
      transform: translateX(4px);
      box-shadow: var(--shadow-md);
    }
    
    .mailSubject{font-weight:800; font-size:15px; color:var(--text-bright); line-height:1.4;}
    .mailMeta{color:var(--muted); font-size:13px; margin-top:6px; line-height:1.4; font-weight:500;}
    .mailSnippet{
      color: var(--muted);
      font-size: 13.5px;
      margin-top:12px;
      line-height:1.6;
      white-space:pre-wrap;
      word-break:break-word;
    }

    /* Viewer */
    .viewerHead{
      display:flex;
      justify-content:space-between;
      gap:14px;
      align-items:flex-start;
      flex-wrap:wrap;
      padding-bottom: 12px;
    }
    
    .paper{
      background: var(--paper);
      color: var(--paperText);
      border: 1px solid var(--paperBorder);
      border-radius: 14px;
      padding: 18px;
      box-shadow: var(--shadow-sm);
    }
    
    .mailFrame{
      width:100%;
      height: 70vh;
      border: 1px solid var(--paperBorder);
      border-radius: 14px;
      background: var(--paper);
      box-shadow: var(--shadow-md);
    }
    
    .mailText{
      white-space:pre-wrap;
      word-break:break-word;
      font-family: ui-monospace, 'SF Mono', Menlo, Monaco, 'Cascadia Code', monospace;
      font-size: 14px;
      line-height: 1.7;
      margin:0;
    }

    .hr{border:0; border-top:1px solid var(--border); margin:18px 0;}

    /* Scrollbar */
    ::-webkit-scrollbar{width:10px; height:10px;}
    ::-webkit-scrollbar-track{background:rgba(255,255,255,.02);}
    ::-webkit-scrollbar-thumb{background:rgba(96,165,250,.2); border-radius:5px;}
    ::-webkit-scrollbar-thumb:hover{background:rgba(96,165,250,.35);}

    @media (max-width: 860px){
      .split{grid-template-columns:1fr;}
      .card{padding:20px;}
    }
    @media (max-width: 760px){
      .wrap{padding:16px;}
      .hdr{flex-direction:column; align-items:flex-start;}
      .row{grid-template-columns:1fr;}
      .mailFrame{height: 58vh;}
      .card{padding:18px;}
    }
  </style>
</head>
<body>
  <div class="wrap">
    ${body}
  </div>
</body>
</html>`;
}

// -------------------- Pages --------------------
const PAGES = {
  login() {
    return pageTemplate(
      "Login",
      `
      ${headerHtml({
        badge: "Login",
        subtitle: "Mail Portal • Kelola mail & inbox",
        rightHtml: `<a class="pill" href="/signup">Buat akun</a>`,
      })}

      <div class="card">
        <div class="row">
          <div>
            <label>Username / Email</label>
            <input id="id" placeholder="sipar / sipar@gmail.com" autocomplete="username" />
          </div>
          <div>
            <label>Password</label>
            <div class="pwWrap">
              <input id="pw" type="password" placeholder="••••••••" autocomplete="current-password" />
              <button type="button" class="pwToggle" onclick="togglePw('pw', this)">Show</button>
            </div>
          </div>
        </div>

        <div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:10px;align-items:center">
          <button class="btn-primary" onclick="login()">Login</button>
          <a href="/reset" class="muted">Lupa password?</a>
        </div>
        <pre id="out" class="muted"></pre>
      </div>

      <script>
        function togglePw(id, btn){
          const el = document.getElementById(id);
          if(!el) return;
          const show = el.type === 'password';
          el.type = show ? 'text' : 'password';
          btn.textContent = show ? 'Hide' : 'Show';
          btn.setAttribute('aria-pressed', show ? 'true' : 'false');
        }

        async function readJsonOrText(r){
          try { return await r.json(); }
          catch {
            const t = await r.text().catch(()=> '');
            return { ok:false, error: 'Server returned non-JSON ('+r.status+'). ' + (t ? t.slice(0,200) : '') };
          }
        }
        async function login(){
          const id = document.getElementById('id').value.trim();
          const pw = document.getElementById('pw').value;
          const out = document.getElementById('out');
          out.textContent = '...';
          const r = await fetch('/api/auth/login',{
            method:'POST',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({id,pw})
          });
          const j = await readJsonOrText(r);
          if(j.ok){ location.href='/app'; return; }
          out.textContent = j.error || 'gagal';
        }
      </script>
      `
    );
  },

  signup(domain) {
    return pageTemplate(
      "Signup",
      `
      ${headerHtml({
        badge: "Signup",
        subtitle: "Buat akun • Mail @" + domain,
        rightHtml: `<a class="pill" href="/login">Login</a>`,
      })}

      <div class="card">
        <div class="row">
          <div>
            <label>Username</label>
            <input id="u" placeholder="sipar" autocomplete="username" />
          </div>
          <div>
            <label>Email (untuk reset password)</label>
            <input id="e" placeholder="sipar@gmail.com" autocomplete="email" />
          </div>
        </div>

        <div style="margin-top:12px">
          <label>Password</label>
          <div class="pwWrap">
            <input id="pw" type="password" placeholder="minimal 8 karakter" autocomplete="new-password" />
            <button type="button" class="pwToggle" onclick="togglePw('pw', this)">Show</button>
          </div>
          <div class="muted" style="margin-top:10px">
            Mail kamu nanti berbentuk <span class="kbd">nama@${domain}</span>
          </div>
        </div>

        <div style="margin-top:14px;display:flex;flex-wrap:wrap;gap:10px;align-items:center">
          <button class="btn-primary" onclick="signup()">Buat Akun</button>
        </div>
        <pre id="out" class="muted"></pre>
      </div>

      <script>
        function togglePw(id, btn){
          const el = document.getElementById(id);
          if(!el) return;
          const show = el.type === 'password';
          el.type = show ? 'text' : 'password';
          btn.textContent = show ? 'Hide' : 'Show';
          btn.setAttribute('aria-pressed', show ? 'true' : 'false');
        }

        async function readJsonOrText(r){
          try { return await r.json(); }
          catch {
            const t = await r.text().catch(()=> '');
            return { ok:false, error: 'Server returned non-JSON ('+r.status+'). ' + (t ? t.slice(0,200) : '') };
          }
        }
        async function signup(){
          const username = document.getElementById('u').value.trim();
          const email = document.getElementById('e').value.trim();
          const pw = document.getElementById('pw').value;
          const out = document.getElementById('out');
          out.textContent = '...';
          const r = await fetch('/api/auth/signup',{
            method:'POST',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({username,email,pw})
          });
          const j = await readJsonOrText(r);
          if(j.ok){ location.href='/app'; return; }
          out.textContent = j.error || 'gagal';
        }
      </script>
      `
    );
  },

  reset() {
    return pageTemplate(
      "Reset Password",
      `
      ${headerHtml({
        badge: "Reset",
        subtitle: "Kirim token reset / set password baru",
        rightHtml: `<a class="pill" href="/login">Login</a>`,
      })}

      <div class="card">
        <label>Email akun</label>
        <input id="e" placeholder="sipar@gmail.com" autocomplete="email" />
        <div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:10px;align-items:center">
          <button class="btn-primary" onclick="reqReset()">Kirim Token</button>
        </div>
        <pre id="out" class="muted"></pre>
      </div>

      <div class="card">
        <div class="muted">Punya token?</div>
        <div class="row" style="margin-top:10px">
          <div>
            <label>Token</label>
            <input id="t" placeholder="token dari email" />
          </div>
          <div>
            <label>Password baru</label>
            <div class="pwWrap">
              <input id="npw" type="password" placeholder="••••••••" autocomplete="new-password" />
              <button type="button" class="pwToggle" onclick="togglePw('npw', this)">Show</button>
            </div>
          </div>
        </div>
        <div style="margin-top:12px">
          <button class="btn-primary" onclick="confirmReset()">Set Password</button>
        </div>
        <pre id="out2" class="muted"></pre>
      </div>

      <script>
        function togglePw(id, btn){
          const el = document.getElementById(id);
          if(!el) return;
          const show = el.type === 'password';
          el.type = show ? 'text' : 'password';
          btn.textContent = show ? 'Hide' : 'Show';
          btn.setAttribute('aria-pressed', show ? 'true' : 'false');
        }

        async function readJsonOrText(r){
          try { return await r.json(); }
          catch {
            const t = await r.text().catch(()=> '');
            return { ok:false, error: 'Server returned non-JSON ('+r.status+'). ' + (t ? t.slice(0,200) : '') };
          }
        }

        // autofill token from #token=...
        (function(){
          try{
            const h = location.hash || '';
            const m = h.match(/token=([^&]+)/);
            if(m && m[1]){
              document.getElementById('t').value = decodeURIComponent(m[1]);
            }
          }catch{}
        })();

        async function reqReset(){
          const email = document.getElementById('e').value.trim();
          const out = document.getElementById('out');
          out.textContent = '...';
          const r = await fetch('/api/auth/reset/request',{
            method:'POST',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({email})
          });
          const j = await readJsonOrText(r);
          out.textContent = j.ok ? 'Jika email terdaftar, token akan dikirim.' : (j.error || 'gagal');
        }

        async function confirmReset(){
          const token = document.getElementById('t').value.trim();
          const newPw = document.getElementById('npw').value;
          const out = document.getElementById('out2');
          out.textContent = '...';
          const r = await fetch('/api/auth/reset/confirm',{
            method:'POST',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({token,newPw})
          });
          const j = await readJsonOrText(r);
          out.textContent = j.ok ? 'Password diubah. Silakan login.' : (j.error || 'gagal');
        }
      </script>
      `
    );
  },

  app(domain) {
    return pageTemplate(
      "Inbox",
      `
      ${headerHtml({
        badge: "Inbox",
        subtitle: "Kelola mail & baca inbox",
        rightHtml: `
          <a href="/admin" id="adminLink" class="pill" style="display:none">Admin</a>
          <button class="danger" onclick="logout()">Logout</button>
        `,
      })}

      <div class="card">
        <div class="row">
          <div>
            <div class="muted">Akun</div>
            <div id="me" style="margin-top:6px">...</div>
          </div>
          <div>
            <div class="muted">Buat mail baru (<b>@${domain}</b>)</div>
            <div class="row" style="grid-template-columns:1fr auto;gap:10px;margin-top:10px">
              <input id="alias" placeholder="contoh: sipar" />
              <button class="btn-primary" onclick="createAlias()">Create</button>
            </div>
            <div id="aliasMsg" class="muted" style="margin-top:8px"></div>
          </div>
        </div>
      </div>

      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">
          <b>Mail</b>
          <span class="muted" id="limitInfo"></span>
        </div>
        <div id="aliases" style="margin-top:10px"></div>
      </div>

      <div class="card" id="emailView" style="display:none"></div>

      <script>
        let ME=null;
        let SELECTED=null;
        let AUTO_REFRESH_INTERVAL=null;

        function esc(s){return (s||'').replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m]));}

        function fmtDate(v){
          if(v===null || v===undefined || v==='') return '';
          try{
            // handle seconds epoch
            if(typeof v === 'number'){
              const ms = v < 1000000000000 ? (v*1000) : v;
              return new Date(ms).toLocaleString();
            }
            // if string numeric seconds
            const s = String(v);
            if(/^\\d{9,13}$/.test(s)){
              const n = Number(s);
              const ms = n < 1000000000000 ? (n*1000) : n;
              return new Date(ms).toLocaleString();
            }
            const d = new Date(v);
            if (Number.isNaN(d.getTime())) return String(v);
            return d.toLocaleString();
          }catch{ return String(v); }
        }

        async function api(path, opts){
          const r = await fetch(path, opts);
          const j = await r.json().catch(()=>null);
          if(!j) {
            const t = await r.text().catch(()=> '');
            throw new Error('Server returned non-JSON ('+r.status+'): ' + (t ? t.slice(0,200) : ''));
          }
          return j;
        }

        async function loadMe(){
          const j = await api('/api/me');
          if(!j.ok){ location.href='/login'; return; }
          ME=j.user;
          document.getElementById('me').innerHTML =
            '<div><b>'+esc(ME.username)+'</b> <span class="muted">('+esc(ME.email)+')</span></div>'+
            '<div class="muted" style="margin-top:4px">role: '+esc(ME.role)+'</div>';
          document.getElementById('limitInfo').textContent = 'limit: '+ME.alias_limit;
          if(ME.role==='admin') document.getElementById('adminLink').style.display='inline-flex';
        }

        async function loadAliases(){
          const j = await api('/api/aliases');
          if(!j.ok){ alert(j.error||'gagal'); return; }
          const box = document.getElementById('aliases');
          box.innerHTML='';
          if(j.aliases.length===0){
            box.innerHTML='<div class="muted">Belum ada mail.</div>';
            return;
          }
          for(const a of j.aliases){
            const div=document.createElement('div');
            div.style.marginBottom='10px';
            
            const addr = a.local_part+'@${domain}';
            const isOpen = SELECTED===a.local_part;
            
            div.innerHTML =
              '<div class="listItem">'+
                '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'+
                  '<button class="btn-primary" onclick="selectAlias(\\''+a.local_part+'\\')">'+
                    (isOpen?'Close':'Open')+
                  '</button>'+
                  '<span><b>'+esc(addr)+'</b></span>'+
                  (a.disabled?'<span class="pill">disabled</span>':'')+
                '</div>'+
                '<div><button onclick="delAlias(\\''+a.local_part+'\\')" class="danger">Delete</button></div>'+
              '</div>'+
              '<div id="inbox_'+a.local_part+'" style="display:'+(isOpen?'block':'none')+';margin-top:10px;padding-left:10px"></div>';
            
            box.appendChild(div);
          }
          
          // Reload emails if there's a selected alias
          if(SELECTED){
            await loadEmails();
          }
        }

        async function selectAlias(local){
          const wasSelected = SELECTED===local;
          
          if(wasSelected){
            // Close inbox
            SELECTED=null;
            stopAutoRefresh();
          } else {
            // Open inbox
            SELECTED=local;
            startAutoRefresh();
          }
          
          await loadAliases();
          
          if(!wasSelected){
            // Scroll to inbox
            const inbox = document.getElementById('inbox_'+local);
            if(inbox) inbox.scrollIntoView({behavior:'smooth', block:'nearest'});
          }
        }

        async function loadEmails(silent=false){
          if(!SELECTED) return;
          
          const box=document.getElementById('inbox_'+SELECTED);
          if(!box) return;
          
          try{
            const j = await api('/api/emails?alias='+encodeURIComponent(SELECTED));
            if(!j.ok){ 
              if(!silent) alert(j.error||'gagal'); 
              return; 
            }
            
            const refreshInfo = silent ? '<span class="muted" style="font-size:11px;margin-left:8px">🔄 Auto-refresh aktif (30s)</span>' : '';
            
            let html = '<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px">'+
              '<b>Inbox</b>'+refreshInfo+
              '<button class="btn-ghost" onclick="loadEmails()">Refresh</button>'+
              '</div>';
            
            if(j.emails.length===0){
              html += '<div class="muted">Belum ada email masuk.</div>';
            } else {
              for(const m of j.emails){
                html += '<div class="mailItem">'+
                  '<div class="mailSubject">'+esc(m.subject||'(no subject)')+'</div>'+
                  '<div class="mailMeta">From: '+esc(m.from_addr||'')+'</div>'+
                  '<div class="mailMeta">'+esc(fmtDate(m.date || m.created_at || ""))+'</div>'+
                  (m.snippet ? '<div class="mailSnippet">'+esc(m.snippet)+'</div>' : '')+
                  '<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">'+
                    '<button class="btn-primary" onclick="openEmail(\\''+m.id+'\\')">View</button>'+
                    '<button onclick="delEmail(\\''+m.id+'\\')" class="danger">Delete</button>'+
                  '</div>'+
                '</div>';
              }
            }
            
            box.innerHTML = html;
          }catch(e){
            if(!silent) alert('Error loading emails: '+e.message);
          }
        }

        function wrapEmailHtml(inner){
          // bikin email HTML kebaca jelas: background putih + text gelap
          return '<!doctype html><html><head><meta charset="utf-8">'+
            '<meta name="viewport" content="width=device-width,initial-scale=1">'+
            '<style>'+
              'html,body{margin:0;padding:0;background:#f8fafc;color:#0f172a;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}' +
              'body{padding:16px;line-height:1.55;font-size:14px;}' +
              'img{max-width:100%;height:auto;}' +
              'table{max-width:100%;border-collapse:collapse;}' +
              'a{color:#2563eb;}' +
              'pre{white-space:pre-wrap;word-break:break-word;}' +
              'blockquote{margin:0;padding-left:12px;border-left:3px solid rgba(15,23,42,.2);color:rgba(15,23,42,.85)}' +
            '</style></head><body>'+ (inner || '') +'</body></html>';
        }

        async function openEmail(id){
          const j = await api('/api/emails/'+encodeURIComponent(id));
          if(!j.ok){ alert(j.error||'gagal'); return; }

          const v=document.getElementById('emailView');
          v.style.display='block';
          v.innerHTML =
            '<div class="viewerHead">'+
              '<div>'+
                '<div style="font-weight:900;font-size:16px">'+esc(j.email.subject||'(no subject)')+'</div>'+
                '<div class="muted" style="margin-top:6px">From: '+esc(j.email.from_addr||'')+'</div>'+
                '<div class="muted">To: '+esc(j.email.to_addr||'')+'</div>'+
                '<div class="muted">'+esc(fmtDate(j.email.date || j.email.created_at || ""))+'</div>'+
              '</div>'+
              '<button class="btn-ghost" onclick="document.getElementById(\\'emailView\\').style.display=\\'none\\'">Close</button>'+
            '</div>'+
            '<hr class="hr" />'+
            '<div id="msgBody"></div>';

          const body = document.getElementById('msgBody');

          if (j.email.html) {
            const iframe = document.createElement('iframe');
            iframe.className = 'mailFrame';
            iframe.setAttribute('sandbox',''); // no scripts
            iframe.setAttribute('referrerpolicy','no-referrer');
            iframe.srcdoc = wrapEmailHtml(j.email.html);
            body.appendChild(iframe);

            const note = document.createElement('div');
            note.className = 'muted';
            note.style.marginTop = '10px';
            note.textContent = 'HTML ditampilkan aman (sandbox).';
            body.appendChild(note);
          } else {
            const box = document.createElement('div');
            box.className = 'paper';
            const pre = document.createElement('pre');
            pre.className = 'mailText';
            pre.textContent = j.email.text || '';
            box.appendChild(pre);
            body.appendChild(box);
          }

          v.scrollIntoView({behavior:'smooth'});
        }

        async function createAlias(){
          const local = document.getElementById('alias').value.trim().toLowerCase();
          const msg=document.getElementById('aliasMsg');
          msg.textContent='...';
          const j = await api('/api/aliases', {
            method:'POST',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({local})
          });
          msg.textContent = j.ok ? 'Mail dibuat.' : (j.error||'gagal');
          if(j.ok){
            document.getElementById('alias').value='';
            await loadMe();
            await loadAliases();
          }
        }

        async function delAlias(local){
          if(!confirm('Hapus mail '+local+'@${domain} ?')) return;
          const j = await api('/api/aliases/'+encodeURIComponent(local), {method:'DELETE'});
          if(!j.ok){ alert(j.error||'gagal'); return; }
          if(SELECTED===local){
            SELECTED=null;
            stopAutoRefresh();
          }
          document.getElementById('emailView').style.display='none';
          await loadMe();
          await loadAliases();
        }

        async function delEmail(id){
          if(!confirm('Hapus email ini?')) return;
          const j = await api('/api/emails/'+encodeURIComponent(id), {method:'DELETE'});
          if(!j.ok){ alert(j.error||'gagal'); return; }
          document.getElementById('emailView').style.display='none';
          await loadEmails();
        }

        function startAutoRefresh(){
          stopAutoRefresh();
          AUTO_REFRESH_INTERVAL = setInterval(()=>{
            loadEmails(true); // silent refresh
          }, 30000); // 30 seconds
        }

        function stopAutoRefresh(){
          if(AUTO_REFRESH_INTERVAL){
            clearInterval(AUTO_REFRESH_INTERVAL);
            AUTO_REFRESH_INTERVAL = null;
          }
        }

        async function logout(){
          stopAutoRefresh();
          await fetch('/api/auth/logout',{method:'POST'});
          location.href='/login';
        }

        (async ()=>{
          try{
            await loadMe();
            await loadAliases();
          }catch(e){
            alert(String(e && e.message ? e.message : e));
          }
        })();
      </script>
      `
    );
  },

  admin(domain) {
    return pageTemplate(
      "Admin",
      `
      ${headerHtml({
        badge: "Admin",
        subtitle: "Cek user yang daftar & atur limit • @" + domain,
        rightHtml: `
          <a href="/app" class="pill">Inbox</a>
          <button class="danger" onclick="logout()">Logout</button>
        `,
      })}

      <div class="card">
        <b>Users</b>
        <div class="muted" style="margin-top:6px">Domain: <span class="kbd">@${domain}</span></div>
        <div id="users" style="margin-top:12px"></div>
      </div>

      <script>
        function esc(s){return (s||'').replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m]));}

        async function api(path, opts){
          const r = await fetch(path, opts);
          const j = await r.json().catch(()=>null);
          if(!j) {
            const t = await r.text().catch(()=> '');
            throw new Error('Server returned non-JSON ('+r.status+'): ' + (t ? t.slice(0,200) : ''));
          }
          return j;
        }

        async function loadUsers(){
          const j = await api('/api/admin/users');
          if(!j.ok){
            alert(j.error||'gagal');
            if(j.error==='Forbidden') location.href='/app';
            return;
          }
          const box=document.getElementById('users');
          box.innerHTML='';
          for(const u of j.users){
            const div=document.createElement('div');
            div.className='listItem';
            div.innerHTML =
              '<div style="min-width:260px">'+
                '<div><b>'+esc(u.username)+'</b> <span class="muted">('+esc(u.email)+')</span></div>'+
                '<div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">'+
                  (u.role==='admin' ? '<span class="pill">admin</span>' : '<span class="pill">user</span>')+
                  (u.disabled?'<span class="pill">disabled</span>':'')+
                  '<span class="pill">created: '+esc(u.created_at)+'</span>'+
                '</div>'+
              '</div>'+
              '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">'+
                '<input id="lim_'+esc(u.id)+'" value="'+u.alias_limit+'" style="width:120px" />'+
                '<button class="btn-primary" onclick="setLimit(\\''+esc(u.id)+'\\')">Set limit</button>'+
                '<button onclick="toggleUser(\\''+esc(u.id)+'\\','+(u.disabled?0:1)+')" class="danger">'+(u.disabled?'Enable':'Disable')+'</button>'+
              '</div>';
            box.appendChild(div);
          }
        }

        async function setLimit(id){
          const v = document.getElementById('lim_'+id).value;
          const lim = parseInt(v,10);
          const j = await api('/api/admin/users/'+encodeURIComponent(id), {
            method:'PATCH',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({alias_limit:lim})
          });
          if(!j.ok){ alert(j.error||'gagal'); return; }
          await loadUsers();
        }

        async function toggleUser(id, disabled){
          const j = await api('/api/admin/users/'+encodeURIComponent(id), {
            method:'PATCH',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({disabled})
          });
          if(!j.ok){ alert(j.error||'gagal'); return; }
          await loadUsers();
        }

        async function logout(){
          await fetch('/api/auth/logout',{method:'POST'});
          location.href='/login';
        }

        loadUsers().catch(e=>alert(String(e && e.message ? e.message : e)));
      </script>
      `
    );
  },
};

// -------------------- Auth/session helpers --------------------
async function getUserBySession(request, env) {
  const token = getCookie(request, "session");
  if (!token) return null;

  const tokenHash = await sha256Base64Url(encoder.encode(token));
  const row = await env.DB.prepare(
    `SELECT s.user_id as user_id, u.id as id, u.username as username, u.email as email,
            u.role as role, u.alias_limit as alias_limit, u.disabled as disabled
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?`
  )
    .bind(tokenHash, nowSec())
    .first();

  if (!row) return null;
  if (row.disabled) return null;
  return row;
}

async function createSession(env, userId, ttlSeconds) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = base64Url(tokenBytes);
  const tokenHash = await sha256Base64Url(encoder.encode(token));
  const t = nowSec();

  await env.DB.prepare(
    `INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
     VALUES (?, ?, ?, ?)`
  )
    .bind(tokenHash, userId, t + ttlSeconds, t)
    .run();

  return token;
}

async function destroySession(request, env) {
  const token = getCookie(request, "session");
  if (!token) return;

  const tokenHash = await sha256Base64Url(encoder.encode(token));
  await env.DB.prepare(`DELETE FROM sessions WHERE token_hash = ?`).bind(tokenHash).run();
}

async function cleanupExpired(env) {
  const t = nowSec();
  try {
    await env.DB.prepare(`DELETE FROM sessions WHERE expires_at <= ?`).bind(t).run();
  } catch { }
  try {
    await env.DB.prepare(`DELETE FROM reset_tokens WHERE expires_at <= ?`).bind(t).run();
  } catch { }
}

// -------------------- Reset email (Resend) --------------------
async function sendResetEmail(env, toEmail, token) {
  if (!env.RESEND_API_KEY) {
    console.log("reset email: RESEND_API_KEY not set -> skipping send");
    return;
  }

  const base = env.APP_BASE_URL || "";
  const link = base ? `${base}/reset#token=${encodeURIComponent(token)}` : "";

  const subject = "Reset password";
  const bodyHtml = `
    <div style="font-family:Arial,sans-serif">
      <h3 style="margin:0 0 10px">Reset Password</h3>
      <p>Gunakan token berikut untuk reset password:</p>
      <p style="font-size:16px"><b>${token}</b></p>
      ${link ? `<p>Atau klik link: <a href="${link}">${link}</a></p>` : ""}
      <p style="color:#64748b">Jika bukan kamu, abaikan email ini.</p>
    </div>
  `;

  const from = env.RESET_FROM || `Org_Lemah <no-reply@${env.DOMAIN}>`;

  console.log("reset email: sending...", { toEmail, from });

  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: [toEmail],
      subject,
      html: bodyHtml,
    }),
  });

  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    console.log("reset email: failed", r.status, txt.slice(0, 800));
    return;
  }

  const okTxt = await r.text().catch(() => "");
  console.log("reset email: sent ok", okTxt.slice(0, 300));
}

// -------------------- Worker entry --------------------
export default {
  async fetch(request, env, ctx) {
    ctx.waitUntil(cleanupExpired(env));

    const url = new URL(request.url);
    const path = url.pathname;
    const cookieSecure = url.protocol === "https:";

    // Pages
    if (request.method === "GET") {
      if (path === "/" || path === "/login") return html(PAGES.login());
      if (path === "/signup") return html(PAGES.signup(env.DOMAIN));
      if (path === "/reset") return html(PAGES.reset());
      if (path === "/app") return html(PAGES.app(env.DOMAIN));
      if (path === "/admin") return html(PAGES.admin(env.DOMAIN));
    }

    // API
    if (path.startsWith("/api/")) {
      try {
        // Signup
        if (path === "/api/auth/signup" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const username = String(body.username || "").trim().toLowerCase();
          const email = String(body.email || "").trim().toLowerCase();
          const pw = String(body.pw || "");

          if (!/^[a-z0-9_]{3,24}$/.test(username)) return badRequest("Username 3-24, a-z0-9_");
          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return badRequest("Email tidak valid");
          if (pw.length < 8) return badRequest("Password minimal 8 karakter");

          const iters = pbkdf2Iters(env);
          const salt = crypto.getRandomValues(new Uint8Array(16));
          const pass_salt = base64Url(salt);
          const pass_hash = await pbkdf2HashBase64Url(pw, salt, iters);

          const t = nowSec();
          const id = crypto.randomUUID();

          const c = await env.DB.prepare(`SELECT COUNT(*) as c FROM users`).first();
          const count = Number(c?.c ?? 0);
          const role = count === 0 ? "admin" : "user";
          const aliasLimit = safeInt(env.DEFAULT_ALIAS_LIMIT, 3);

          try {
            const hasIters = await usersHasPassIters(env);
            if (hasIters) {
              await env.DB.prepare(
                `INSERT INTO users (id, username, email, pass_salt, pass_hash, pass_iters, role, alias_limit, disabled, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`
              )
                .bind(id, username, email, pass_salt, pass_hash, iters, role, aliasLimit, t)
                .run();
            } else {
              await env.DB.prepare(
                `INSERT INTO users (id, username, email, pass_salt, pass_hash, role, alias_limit, disabled, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`
              )
                .bind(id, username, email, pass_salt, pass_hash, role, aliasLimit, t)
                .run();
            }
          } catch (e) {
            const msg = String(e && e.message ? e.message : e);
            if (msg.toUpperCase().includes("UNIQUE")) return badRequest("Username/email sudah dipakai");
            console.log("signup db error:", msg);
            return json({ ok: false, error: "DB error" }, 500);
          }

          const ttl = safeInt(env.SESSION_TTL_SECONDS, 1209600);
          const token = await createSession(env, id, ttl);

          return json({ ok: true }, 200, {
            "set-cookie": setCookieHeader("session", token, { maxAge: ttl, secure: cookieSecure }),
          });
        }

        // Login
        if (path === "/api/auth/login" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const id = String(body.id || "").trim().toLowerCase();
          const pw = String(body.pw || "");
          if (!id || !pw) return badRequest("Lengkapi data");

          const hasIters = await usersHasPassIters(env);

          const user = hasIters
            ? await env.DB.prepare(
              `SELECT id, username, email, pass_salt, pass_hash, pass_iters, role, alias_limit, disabled
                 FROM users WHERE username = ? OR email = ?`
            )
              .bind(id, id)
              .first()
            : await env.DB.prepare(
              `SELECT id, username, email, pass_salt, pass_hash, role, alias_limit, disabled
                 FROM users WHERE username = ? OR email = ?`
            )
              .bind(id, id)
              .first();

          if (!user || user.disabled) return unauthorized("Login gagal");

          const saltBytes = base64UrlToBytes(user.pass_salt);
          const iters = hasIters ? safeInt(user.pass_iters, pbkdf2Iters(env)) : pbkdf2Iters(env);

          if (iters > PBKDF2_MAX_ITERS) {
            return unauthorized("Hash password lama tidak didukung. Silakan reset password.");
          }

          let hash;
          try {
            hash = await pbkdf2HashBase64Url(pw, saltBytes, iters);
          } catch (e) {
            if ((e?.name || "") === "NotSupportedError") {
              return unauthorized("Parameter hash tidak didukung. Silakan reset password.");
            }
            throw e;
          }

          if (hash !== user.pass_hash) return unauthorized("Login gagal");

          const ttl = safeInt(env.SESSION_TTL_SECONDS, 1209600);
          const token = await createSession(env, user.id, ttl);

          return json({ ok: true }, 200, {
            "set-cookie": setCookieHeader("session", token, { maxAge: ttl, secure: cookieSecure }),
          });
        }

        // Logout
        if (path === "/api/auth/logout" && request.method === "POST") {
          await destroySession(request, env);
          return json({ ok: true }, 200, {
            "set-cookie": setCookieHeader("session", "", { maxAge: 0, secure: cookieSecure }),
          });
        }

        // Reset request
        if (path === "/api/auth/reset/request" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const email = String(body.email || "").trim().toLowerCase();
          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return badRequest("Email tidak valid");

          const user = await env.DB.prepare(`SELECT id, disabled FROM users WHERE email = ?`)
            .bind(email)
            .first();

          // anti user-enumeration
          if (!user || user.disabled) return json({ ok: true });

          const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
          const token = base64Url(tokenBytes);
          const tokenHash = await sha256Base64Url(encoder.encode(token));
          const t = nowSec();
          const ttl = safeInt(env.RESET_TTL_SECONDS, 3600);

          await env.DB.prepare(
            `INSERT INTO reset_tokens (token_hash, user_id, expires_at, created_at)
             VALUES (?, ?, ?, ?)`
          )
            .bind(tokenHash, user.id, t + ttl, t)
            .run();

          ctx.waitUntil(sendResetEmail(env, email, token));
          return json({ ok: true });
        }

        // Reset confirm
        if (path === "/api/auth/reset/confirm" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const token = String(body.token || "").trim();
          const newPw = String(body.newPw || "");

          if (!token) return badRequest("Token wajib");
          if (newPw.length < 8) return badRequest("Password minimal 8 karakter");

          const tokenHash = await sha256Base64Url(encoder.encode(token));
          const rt = await env.DB.prepare(
            `SELECT user_id, expires_at FROM reset_tokens WHERE token_hash = ?`
          )
            .bind(tokenHash)
            .first();

          if (!rt || rt.expires_at <= nowSec()) return badRequest("Token invalid/expired");

          const iters = pbkdf2Iters(env);
          const salt = crypto.getRandomValues(new Uint8Array(16));
          const pass_salt = base64Url(salt);
          const pass_hash = await pbkdf2HashBase64Url(newPw, salt, iters);

          const hasIters = await usersHasPassIters(env);
          if (hasIters) {
            await env.DB.prepare(`UPDATE users SET pass_salt=?, pass_hash=?, pass_iters=? WHERE id=?`)
              .bind(pass_salt, pass_hash, iters, rt.user_id)
              .run();
          } else {
            await env.DB.prepare(`UPDATE users SET pass_salt=?, pass_hash=? WHERE id=?`)
              .bind(pass_salt, pass_hash, rt.user_id)
              .run();
          }

          await env.DB.prepare(`DELETE FROM reset_tokens WHERE token_hash=?`).bind(tokenHash).run();
          return json({ ok: true });
        }

        // Auth required below
        const me = await getUserBySession(request, env);
        if (!me) return unauthorized();

        if (path === "/api/me" && request.method === "GET") {
          return json({
            ok: true,
            user: {
              id: me.id,
              username: me.username,
              email: me.email,
              role: me.role,
              alias_limit: me.alias_limit,
            },
          });
        }

        // Mail (aliases)
        if (path === "/api/aliases" && request.method === "GET") {
          const rows = await env.DB.prepare(
            `SELECT local_part, disabled, created_at
             FROM aliases WHERE user_id = ? ORDER BY created_at DESC`
          )
            .bind(me.id)
            .all();
          return json({ ok: true, aliases: rows.results || [] });
        }

        if (path === "/api/aliases" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const local = String(body.local || "").trim().toLowerCase();
          if (!validLocalPart(local)) return badRequest("Mail tidak valid (a-z0-9._+- max 64)");

          const cnt = await env.DB.prepare(
            `SELECT COUNT(*) as c FROM aliases WHERE user_id = ? AND disabled = 0`
          )
            .bind(me.id)
            .first();

          if (Number(cnt?.c ?? 0) >= me.alias_limit) return forbidden("Limit mail tercapai");

          const t = nowSec();
          try {
            await env.DB.prepare(
              `INSERT INTO aliases (local_part, user_id, disabled, created_at)
               VALUES (?, ?, 0, ?)`
            )
              .bind(local, me.id, t)
              .run();
          } catch (e) {
            const msg = String(e && e.message ? e.message : e);
            if (msg.toUpperCase().includes("UNIQUE")) return badRequest("Mail sudah dipakai");
            console.log("alias db error:", msg);
            return json({ ok: false, error: "DB error" }, 500);
          }

          return json({ ok: true });
        }

        if (path.startsWith("/api/aliases/") && request.method === "DELETE") {
          const local = decodeURIComponent(path.slice("/api/aliases/".length)).toLowerCase();
          if (!validLocalPart(local)) return badRequest("Mail invalid");

          const own = await env.DB.prepare(
            `SELECT local_part FROM aliases WHERE local_part = ? AND user_id = ?`
          )
            .bind(local, me.id)
            .first();

          if (!own) return notFound();

          await env.DB.prepare(`DELETE FROM aliases WHERE local_part = ? AND user_id = ?`)
            .bind(local, me.id)
            .run();

          return json({ ok: true });
        }

        // Emails
        if (path === "/api/emails" && request.method === "GET") {
          const alias = (url.searchParams.get("alias") || "").trim().toLowerCase();
          if (!alias || !validLocalPart(alias)) return badRequest("alias required");

          const own = await env.DB.prepare(
            `SELECT local_part FROM aliases WHERE local_part = ? AND user_id = ? AND disabled = 0`
          )
            .bind(alias, me.id)
            .first();

          if (!own) return forbidden("Mail bukan milikmu / disabled");

          const rows = await env.DB.prepare(
            `SELECT id, from_addr, to_addr, subject, date, created_at,
                    substr(COALESCE(text,''), 1, 180) as snippet
             FROM emails
             WHERE user_id = ? AND local_part = ?
             ORDER BY created_at DESC
             LIMIT 50`
          )
            .bind(me.id, alias)
            .all();

          return json({ ok: true, emails: rows.results || [] });
        }

        if (path.startsWith("/api/emails/") && request.method === "GET") {
          const id = decodeURIComponent(path.slice("/api/emails/".length));
          const row = await env.DB.prepare(
            `SELECT id, from_addr, to_addr, subject, date, text, html, raw_key, created_at
             FROM emails WHERE id = ? AND user_id = ?`
          )
            .bind(id, me.id)
            .first();

          if (!row) return notFound();
          return json({ ok: true, email: row });
        }

        if (path.startsWith("/api/emails/") && request.method === "DELETE") {
          const id = decodeURIComponent(path.slice("/api/emails/".length));
          const row = await env.DB.prepare(`SELECT raw_key FROM emails WHERE id = ? AND user_id = ?`)
            .bind(id, me.id)
            .first();

          if (!row) return notFound();

          await env.DB.prepare(`DELETE FROM emails WHERE id = ? AND user_id = ?`)
            .bind(id, me.id)
            .run();

          if (row.raw_key && env.MAIL_R2) ctx.waitUntil(env.MAIL_R2.delete(row.raw_key));
          return json({ ok: true });
        }

        // Admin endpoints
        if (path === "/api/admin/users" && request.method === "GET") {
          if (me.role !== "admin") return forbidden("Forbidden");

          const rows = await env.DB.prepare(
            `SELECT id, username, email, role, alias_limit, disabled, created_at
             FROM users ORDER BY created_at DESC LIMIT 200`
          ).all();

          const users = (rows.results || []).map((u) => ({
            ...u,
            created_at: new Date(u.created_at * 1000).toISOString(),
          }));

          return json({ ok: true, users });
        }

        if (path.startsWith("/api/admin/users/") && request.method === "PATCH") {
          if (me.role !== "admin") return forbidden("Forbidden");

          const userId = decodeURIComponent(path.slice("/api/admin/users/".length));
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const alias_limit =
            body.alias_limit !== undefined ? safeInt(body.alias_limit, NaN) : undefined;
          const disabled = body.disabled !== undefined ? safeInt(body.disabled, NaN) : undefined;

          if (
            alias_limit !== undefined &&
            (!Number.isFinite(alias_limit) || alias_limit < 0 || alias_limit > 1000)
          ) {
            return badRequest("alias_limit invalid");
          }
          if (disabled !== undefined && !(disabled === 0 || disabled === 1)) {
            return badRequest("disabled invalid");
          }

          const sets = [];
          const binds = [];
          if (alias_limit !== undefined) {
            sets.push("alias_limit = ?");
            binds.push(alias_limit);
          }
          if (disabled !== undefined) {
            sets.push("disabled = ?");
            binds.push(disabled);
          }
          if (sets.length === 0) return badRequest("No fields");

          binds.push(userId);
          await env.DB.prepare(`UPDATE users SET ${sets.join(", ")} WHERE id = ?`)
            .bind(...binds)
            .run();
          return json({ ok: true });
        }

        return notFound();
      } catch (e) {
        console.log("API ERROR:", e && e.stack ? e.stack : e);
        return json({ ok: false, error: "Server error" }, 500);
      }
    }

    return notFound();
  },

  async email(message, env, ctx) {
    try {
      const domain = String(env.DOMAIN || "").toLowerCase();
      const to = String(message.to || "").toLowerCase();
      const [local, toDomain] = to.split("@");

      if (!local || !toDomain || toDomain !== domain) {
        message.setReject("Bad recipient");
        return;
      }

      const row = await env.DB.prepare(
        `SELECT a.local_part as local_part, a.user_id as user_id, a.disabled as alias_disabled,
                u.disabled as user_disabled
         FROM aliases a
         JOIN users u ON u.id = a.user_id
         WHERE a.local_part = ?`
      )
        .bind(local)
        .first();

      if (!row || row.alias_disabled || row.user_disabled) {
        message.setReject("Unknown recipient");
        return;
      }

      const maxStore = safeInt(env.MAX_STORE_BYTES, 262144);
      if (message.rawSize && message.rawSize > maxStore) {
        message.setReject("Message too large");
        return;
      }

      const ab = await new Response(message.raw).arrayBuffer();

      const parser = new PostalMime();
      const parsed = await parser.parse(ab);

      const id = crypto.randomUUID();
      const t = nowSec();

      const subject = parsed.subject || "";
      const date = parsed.date ? new Date(parsed.date).toISOString() : "";
      const fromAddr = parsed.from && parsed.from.address ? parsed.from.address : (message.from || "");
      const toAddr = message.to || "";

      const maxTextChars = safeInt(env.MAX_TEXT_CHARS, 200000);
      const text = (parsed.text || "").slice(0, maxTextChars);
      const htmlPart = (parsed.html || "").slice(0, maxTextChars);

      let raw_key = null;
      if (env.MAIL_R2) {
        raw_key = `emails/${id}.eml`;
        ctx.waitUntil(env.MAIL_R2.put(raw_key, ab, { httpMetadata: { contentType: "message/rfc822" } }));
      }

      await env.DB.prepare(
        `INSERT INTO emails
         (id, local_part, user_id, from_addr, to_addr, subject, date, text, html, raw_key, size, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(
          id,
          row.local_part,
          row.user_id,
          fromAddr,
          toAddr,
          subject,
          date,
          text,
          htmlPart,
          raw_key,
          ab.byteLength || (message.rawSize || 0),
          t
        )
        .run();
    } catch (e) {
      console.log("email handler error:", e && e.stack ? e.stack : e);
      message.setReject("Temporary processing error");
    }
  },
};
