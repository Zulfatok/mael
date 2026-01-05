// src/index.js
// Org_Lemah Mail Portal - Full Script with Improved Modern UI
// Ready to deploy!

import PostalMime from "postal-mime";

const encoder = new TextEncoder();

// Security/Hashing constants
const PBKDF2_MAX_ITERS = 100000;
const PBKDF2_MIN_ITERS = 10000;
let USERS_HAS_PASS_ITERS = null;

// Response helpers
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

// Utils
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
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations: it,
    },
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
  const {
    httpOnly = true,
    secure = true,
    sameSite = "Lax",
    path = "/",
    maxAge,
  } = opts;

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

// UI: Brand + Template
const LOGO_SVG = `
<svg viewBox="0 0 64 64" width="34" height="34" aria-hidden="true" focusable="false">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#7dd3fc"/>
      <stop offset="1" stop-color="#6366f1"/>
    </linearGradient>
    <filter id="s" x="-30%" y="-30%" width="160%" height="160%">
      <feDropShadow dx="0" dy="6" stdDeviation="6" flood-color="#000" flood-opacity="0.35"/>
    </filter>
  </defs>
  <circle cx="32" cy="32" r="26" fill="url(#g)" filter="url(#s)"/>
  <circle cx="32" cy="32" r="24" fill="rgba(11,15,20,0.35)"/>
  <path d="M22 40V24h6c6 0 10 3 10 8s-4 8-10 8h-6zm6-4h1c3.6 0 5.8-1.8 5.8-4s-2.2-4-5.8-4h-1v8z"
        fill="#e6edf3" opacity="0.95"/>
  <path d="M42 24h4v12c0 2.6-1.5 4.2-4.3 4.2-1 0-2.2-.2-3-.6l.7-3.4c.5.2 1.1.3 1.6.3 1 0 1-.5 1-1.1V24z"
        fill="#e6edf3" opacity="0.95"/>
</svg>
`;

const FAVICON_DATA = encodeURIComponent(`
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#7dd3fc"/>
      <stop offset="1" stop-color="#6366f1"/>
    </linearGradient>
  </defs>
  <circle cx="32" cy="32" r="28" fill="url(#g)"/>
  <text x="32" y="40" text-anchor="middle" font-size="26" font-family="Arial" fill="#0b0f14">OL</text>
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
  <meta name="theme-color" content="#0b0f14">
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
      --bg:#0b0f14;
      --card:#0f172a;
      --card2:#0b1220;
      --card-hover:#15213b;
      --border:#22314a;
      --border-light:#2d3f5f;
      --text:#e6edf3;
      --text-bright:#f0f6fc;
      --muted:#93a4b8;
      --muted-dark:#6b7a8f;
      --brand:#7dd3fc;
      --brand-glow:rgba(125,211,252,0.3);
      --accent:#818cf8;
      --danger:#ef4444;
      --ok:#22c55e;
      --warning:#f59e0b;
    }

    *{box-sizing:border-box;margin:0;padding:0}

    body{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      margin:0;
      background:
        radial-gradient(1400px 700px at 15% -5%, rgba(125,211,252,.15), transparent 60%),
        radial-gradient(1000px 600px at 88% 3%, rgba(129,140,248,.13), transparent 55%),
        radial-gradient(800px 500px at 25% 105%, rgba(34,197,94,.08), transparent 55%),
        var(--bg);
      background-attachment: fixed;
      color:var(--text);
      min-height:100vh;
      line-height:1.6;
    }

    b, strong { font-weight:600; color:var(--text-bright) }
    a{color:var(--brand);text-decoration:none;transition:opacity .2s}
    a:hover{opacity:.85;text-decoration:underline}

    .wrap{max-width:1180px;margin:0 auto;padding:20px}

    .hdr{
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:16px;
      padding:16px 0;
      margin-bottom:8px;
    }
    .brand{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
    .logo{display:flex;align-items:center}
    .brandText{display:flex;flex-direction:column;line-height:1.1}
    .brandName{
      font-weight:800;
      font-size:18px;
      letter-spacing:0.3px;
      background:linear-gradient(135deg, var(--brand), var(--accent));
      -webkit-background-clip:text;
      -webkit-text-fill-color:transparent;
      background-clip:text;
    }
    .brandSub{color:var(--muted);font-size:13px;margin-top:4px}
    .hdrRight{display:flex;gap:10px;align-items:center;flex-wrap:wrap}

    .card{
      background: linear-gradient(145deg, rgba(255,255,255,.045) 0%, rgba(255,255,255,.01) 100%), var(--card);
      border:1px solid var(--border);
      border-radius:20px;
      padding:20px;
      margin:14px 0;
      box-shadow: 
        0 10px 40px rgba(0,0,0,.4),
        0 2px 8px rgba(0,0,0,.3),
        inset 0 1px 0 rgba(255,255,255,.05);
      overflow:hidden;
      transition: border-color .3s, box-shadow .3s;
    }
    .card:hover{
      border-color:var(--border-light);
      box-shadow: 
        0 12px 50px rgba(0,0,0,.45),
        0 4px 12px rgba(0,0,0,.35),
        inset 0 1px 0 rgba(255,255,255,.08);
    }

    label{
      display:block;
      margin-bottom:7px;
      color:var(--muted);
      font-size:13px;
      font-weight:500;
      letter-spacing:0.2px;
    }
    input,select,textarea{
      width:100%;
      padding:12px 14px;
      border-radius:14px;
      border:1.5px solid var(--border);
      background: var(--card2);
      color:var(--text);
      outline:none;
      font-size:15px;
      transition: all .25s ease;
    }
    input:focus,select:focus,textarea:focus{
      border-color: var(--brand);
      box-shadow: 0 0 0 4px var(--brand-glow);
      background: rgba(15,23,42,0.8);
    }
    input::placeholder{color:var(--muted-dark)}

    button{
      padding:11px 16px;
      border-radius:14px;
      border:1.5px solid var(--border);
      background: rgba(125,211,252,.1);
      color:var(--text);
      cursor:pointer;
      font-size:14px;
      font-weight:500;
      transition: all .2s ease;
      white-space:nowrap;
      display:inline-flex;
      align-items:center;
      gap:6px;
    }
    button:hover:not(:disabled){
      background: rgba(125,211,252,.18);
      border-color: var(--brand);
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(125,211,252,.2);
    }
    button:active:not(:disabled){transform: translateY(0)}
    button:disabled{opacity:.5;cursor:not-allowed}

    .btn-primary{
      background: linear-gradient(135deg, rgba(125,211,252,.25) 0%, rgba(129,140,248,.2) 100%);
      border-color: rgba(125,211,252,.4);
      font-weight:600;
    }
    .btn-primary:hover:not(:disabled){
      background: linear-gradient(135deg, rgba(125,211,252,.35) 0%, rgba(129,140,248,.3) 100%);
      border-color: var(--brand);
      box-shadow: 0 4px 16px rgba(125,211,252,.3);
    }

    .btn-ghost{
      background: rgba(255,255,255,.04);
      border-color: rgba(255,255,255,.08);
    }
    .btn-ghost:hover:not(:disabled){
      background: rgba(255,255,255,.08);
      border-color: rgba(255,255,255,.12);
    }

    .danger{
      background: rgba(239,68,68,.12);
      border-color: rgba(239,68,68,.4);
      color:var(--text);
    }
    .danger:hover:not(:disabled){
      background: rgba(239,68,68,.18);
      border-color: var(--danger);
      box-shadow: 0 4px 12px rgba(239,68,68,.2);
    }

    .pill{
      display:inline-flex;
      align-items:center;
      gap:6px;
      padding:6px 12px;
      border-radius:999px;
      border:1px solid var(--border);
      background: rgba(255,255,255,.04);
      color:var(--muted);
      font-size:12.5px;
      font-weight:500;
      white-space:nowrap;
    }
    .badge{
      display:inline-block;
      padding:4px 10px;
      border-radius:8px;
      font-size:11px;
      font-weight:600;
      letter-spacing:0.3px;
      text-transform:uppercase;
    }

    .muted{color:var(--muted)}
    .muted-dark{color:var(--muted-dark)}

    .row{display:grid;grid-template-columns:1fr 1fr;gap:14px;align-items:start}
    .row3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}

    .split{
      display:grid;
      grid-template-columns: 1fr 1.5fr;
      gap:20px;
      align-items:start;
    }

    .listItem{
      padding:14px 16px;
      border-bottom:1px solid var(--border);
      background:transparent;
      border-radius:12px;
      margin-bottom:4px;
      transition: all .2s ease;
    }
    .listItem:hover{
      background:var(--card-hover);
      border-color:var(--border-light);
      transform:translateX(4px);
    }
    .listItem:last-child{border-bottom:0}

    .emailItem{
      padding:16px;
      border:1.5px solid var(--border);
      background:linear-gradient(145deg, rgba(255,255,255,.03), transparent);
      border-radius:16px;
      margin-bottom:10px;
      cursor:pointer;
      transition: all .25s ease;
      position:relative;
      overflow:hidden;
    }
    .emailItem::before{
      content:'';
      position:absolute;
      left:0;
      top:0;
      bottom:0;
      width:4px;
      background:linear-gradient(180deg, var(--brand), var(--accent));
      opacity:0;
      transition:opacity .25s;
    }
    .emailItem:hover{
      border-color:var(--brand);
      background:linear-gradient(145deg, rgba(125,211,252,.08), rgba(129,140,248,.05));
      transform:translateY(-2px);
      box-shadow: 0 8px 24px rgba(0,0,0,.3), 0 0 0 1px rgba(125,211,252,.1);
    }
    .emailItem:hover::before{opacity:1}

    .emailHeader{
      display:flex;
      justify-content:space-between;
      align-items:flex-start;
      gap:12px;
      margin-bottom:8px;
    }
    .emailSubject{
      font-size:15px;
      font-weight:600;
      color:var(--text-bright);
      line-height:1.4;
      flex:1;
    }
    .emailMeta{
      display:flex;
      align-items:center;
      gap:8px;
      font-size:13px;
      color:var(--muted);
      margin-bottom:10px;
    }
    .emailFrom{
      font-weight:500;
      color:var(--brand);
    }
    .emailDate{
      color:var(--muted-dark);
      font-size:12px;
    }
    .emailActions{
      display:flex;
      gap:8px;
      margin-top:12px;
      flex-wrap:wrap;
    }

    .aliasItem{
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:12px;
      padding:12px 14px;
      border:1.5px solid var(--border);
      background:rgba(255,255,255,.02);
      border-radius:14px;
      margin-bottom:8px;
      transition:all .2s ease;
    }
    .aliasItem:hover{
      border-color:var(--brand);
      background:rgba(125,211,252,.06);
      transform:translateX(3px);
    }
    .aliasAddr{
      font-family: ui-monospace, 'SF Mono', Monaco, 'Cascadia Code', monospace;
      font-size:14px;
      color:var(--text-bright);
      font-weight:500;
    }

    .emailViewer{
      border-top:2px solid var(--border);
      padding-top:20px;
      margin-top:20px;
    }
    .emailViewerHeader{
      margin-bottom:20px;
      padding-bottom:16px;
      border-bottom:1px solid var(--border);
    }
    .emailViewerSubject{
      font-size:22px;
      font-weight:700;
      color:var(--text-bright);
      margin-bottom:12px;
      line-height:1.3;
    }
    .emailViewerMeta{
      display:flex;
      flex-direction:column;
      gap:6px;
      font-size:14px;
    }
    .emailViewerMeta > div{
      display:flex;
      gap:8px;
      align-items:center;
    }
    .emailViewerMeta label{
      display:inline;
      min-width:60px;
      color:var(--muted-dark);
      margin:0;
    }
    .emailViewerMeta span{color:var(--text)}
    .emailViewerBody{
      background:var(--card2);
      border:1px solid var(--border);
      border-radius:14px;
      padding:20px;
      margin-top:16px;
      line-height:1.7;
      font-size:15px;
    }
    .emailViewerBody iframe{
      width:100%;
      height:70vh;
      border:0;
      border-radius:12px;
      background:white;
    }

    .kbd{
      font-family: ui-monospace, 'SF Mono', Monaco, monospace;
      font-size: 12.5px;
      padding:3px 9px;
      border-radius:8px;
      border:1px solid var(--border);
      background: rgba(255,255,255,.04);
      color: var(--muted);
      font-weight:500;
    }

    .hr{
      border:0;
      border-top:1px solid var(--border);
      margin:16px 0;
      opacity:0.8;
    }

    .emptyState{
      text-align:center;
      padding:40px 20px;
      color:var(--muted);
    }
    .emptyState svg{
      width:64px;
      height:64px;
      opacity:0.4;
      margin-bottom:16px;
    }

    @keyframes spin{
      to{transform:rotate(360deg)}
    }
    .spinner{
      display:inline-block;
      width:14px;
      height:14px;
      border:2px solid rgba(255,255,255,.2);
      border-top-color:var(--brand);
      border-radius:50%;
      animation:spin .6s linear infinite;
    }

    @keyframes fadeIn{
      from{opacity:0;transform:translateY(10px)}
      to{opacity:1;transform:translateY(0)}
    }
    .card{animation:fadeIn .4s ease-out}

    pre{white-space:pre-wrap;word-break:break-word}

    @media (max-width: 900px){
      .wrap{padding:16px}
      .hdr{flex-direction:column;align-items:flex-start}
      .split{grid-template-columns:1fr}
      .row,.row3{grid-template-columns:1fr}
      .card{padding:16px}
    }

    @media (max-width: 640px){
      .wrap{padding:12px}
      .card{padding:14px;border-radius:16px}
      .emailItem{padding:12px}
      .emailSubject{font-size:14px}
      .brandName{font-size:16px}
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

// Pages
const PAGES = {
  login() {
    return pageTemplate(
      "Login",
      `
      ${headerHtml({
        badge: "Login",
        subtitle: "Mail Portal • Domain alias + inbox",
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
            <input id="pw" type="password" placeholder="••••••••" autocomplete="current-password" />
          </div>
        </div>

        <div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:10px;align-items:center">
          <button class="btn-primary" onclick="login()">Login</button>
          <a href="/reset" class="muted">Lupa password?</a>
        </div>
        <pre id="out" class="muted"></pre>
      </div>

      <script>
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
        subtitle: "Buat akun • Alias email @" + domain,
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
          <input id="pw" type="password" placeholder="minimal 8 karakter" autocomplete="new-password" />
          <div class="muted" style="margin-top:8px">
            Alias kamu nanti akan berbentuk <span class="kbd">nama@${domain}</span>
          </div>
        </div>

        <div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:10px;align-items:center">
          <button class="btn-primary" onclick="signup()">Create account</button>
        </div>
        <pre id="out" class="muted"></pre>
      </div>

      <script>
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
          <button class="btn-primary" onclick="reqReset()">Kirim reset token</button>
        </div>
        <pre id="out" class="muted"></pre>
      </div>

      <div class="card">
        <div class="muted">Punya token?</div>
        <div class="row">
          <div>
            <label>Token</label>
            <input id="t" placeholder="token dari email" />
          </div>
          <div>
            <label>Password baru</label>
            <input id="npw" type="password" placeholder="••••••••" autocomplete="new-password" />
          </div>
        </div>
        <div style="margin-top:12px">
          <button class="btn-primary" onclick="confirmReset()">Set password</button>
        </div>
        <pre id="out2" class="muted"></pre>
      </div>

      <script>
        async function readJsonOrText(r){
          try { return await r.json(); }
          catch {
            const t = await r.text().catch(()=> '');
            return { ok:false, error: 'Server returned non-JSON ('+r.status+'). ' + (t ? t.slice(0,200) : '') };
          }
        }
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
          out.textContent = j.ok ? 'Jika email terdaftar, token dikirim.' : (j.error || 'gagal');
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
        subtitle: "Kelola alias & baca email masuk",
        rightHtml: `
          <a href="/admin" id="adminLink" class="pill" style="display:none">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
            </svg>
            Admin
          </a>
          <button class="danger" onclick="logout()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>
            </svg>
            Logout
          </button>
        `,
      })}

      <div class="card">
        <div class="row">
          <div>
            <label>👤 Akun Anda</label>
            <div id="me" style="margin-top:8px">
              <div class="spinner"></div>
              <span class="muted" style="margin-left:8px">Loading...</span>
            </div>
          </div>
          <div>
            <label>✉️ Buat Alias Baru (<b>@${domain}</b>)</label>
            <div style="display:grid;grid-template-columns:1fr auto;gap:10px;margin-top:8px">
              <input id="alias" placeholder="contoh: myname" />
              <button class="btn-primary" onclick="createAlias()">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
                </svg>
                Create
              </button>
            </div>
            <div id="aliasMsg" class="muted" style="margin-top:8px;font-size:13px"></div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="split">
          <div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
              <div>
                <b style="font-size:16px">📬 Your Aliases</b>
                <div class="muted" style="font-size:12px;margin-top:2px">
                  <span id="limitInfo">limit: —</span>
                </div>
              </div>
            </div>
            <div id="aliases"></div>
          </div>

          <div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:10px">
              <div>
                <b style="font-size:16px">📧 Inbox</b>
                <div class="muted" id="selAlias" style="font-size:12px;margin-top:2px">
                  Pilih alias untuk melihat email
                </div>
              </div>
              <button class="btn-ghost" onclick="loadEmails()" id="refreshBtn" disabled style="gap:4px">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
                  <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
                </svg>
                Refresh
              </button>
            </div>
            <div id="emails"></div>
          </div>
        </div>
      </div>

      <div class="card" id="emailView" style="display:none"></div>

      <script>
        let ME=null;
        let SELECTED=null;

        function esc(s){return (s||'').replace(/[&<>\"']/g, m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}

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
            '<div style="font-size:15px"><b>'+esc(ME.username)+'</b></div>'+
            '<div class="muted-dark" style="font-size:13px;margin-top:2px">'+esc(ME.email)+'</div>'+
            '<div style="margin-top:8px"><span class="badge" style="background:rgba(129,140,248,.15);border:1px solid rgba(129,140,248,.3);color:var(--accent)">'+esc(ME.role)+'</span></div>';

          document.getElementById('limitInfo').innerHTML = 'limit: <b>'+ME.alias_limit+'</b>';
          if(ME.role==='admin') document.getElementById('adminLink').style.display='inline-flex';
        }

        async function loadAliases(){
          const j = await api('/api/aliases');
          if(!j.ok){ alert(j.error||'gagal'); return; }
          const box = document.getElementById('aliases');
          box.innerHTML='';

          if(j.aliases.length===0){
            box.innerHTML=\`
              <div class="emptyState">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                  <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
                <div>Belum ada alias.</div>
                <div style="font-size:12px;margin-top:4px">Buat alias pertama Anda!</div>
              </div>
            \`;
            return;
          }

          for(const a of j.aliases){
            const div=document.createElement('div');
            div.className='aliasItem';
            const addr = a.local_part+'@${domain}';
            div.innerHTML =
              '<div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0">'+
                '<button class="btn-primary" onclick="selectAlias(\''+esc(a.local_part)+'\')" style="flex-shrink:0">'+
                  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'+
                    '<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>'+
                    '<polyline points="22,6 12,13 2,6"/>'+
                  '</svg>'+
                  'Open'+
                '</button>'+
                '<span class="aliasAddr" style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis">'+esc(addr)+'</span>'+
                (a.disabled?'<span class="badge" style="background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);color:var(--danger)">disabled</span>':'')+
              '</div>'+
              '<button onclick="delAlias(\''+esc(a.local_part)+'\')" class="danger" style="flex-shrink:0">'+
                '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'+
                  '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>'+
                '</svg>'+
                'Delete'+
              '</button>';
            box.appendChild(div);
          }
        }

        async function selectAlias(local){
          SELECTED=local;
          document.getElementById('selAlias').innerHTML = '<b>'+local+'@${domain}</b>';
          document.getElementById('refreshBtn').disabled=false;
          document.getElementById('emails').innerHTML='<div class="spinner"></div><span class="muted" style="margin-left:8px">Loading emails...</span>';
          await loadEmails();
        }

        async function loadEmails(){
          if(!SELECTED) return;
          const j = await api('/api/emails?alias='+encodeURIComponent(SELECTED));
          if(!j.ok){ alert(j.error||'gagal'); return; }
          const box=document.getElementById('emails');
          box.innerHTML='';

          if(j.emails.length===0){
            box.innerHTML=\`
              <div class="emptyState">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
                  <polyline points="22,6 12,13 2,6"/>
                </svg>
                <div>Inbox kosong</div>
                <div style="font-size:12px;margin-top:4px">Belum ada email masuk ke alias ini</div>
              </div>
            \`;
            return;
          }

          for(const m of j.emails){
            const d=document.createElement('div');
            d.className='emailItem';
            d.onclick=()=>openEmail(m.id);

            const subject = esc(m.subject||'(no subject)');
            const from = esc(m.from_addr);
            const date = esc(m.date||'');

            d.innerHTML =
              '<div class="emailHeader">'+
                '<div class="emailSubject">'+subject+'</div>'+
              '</div>'+
              '<div class="emailMeta">'+
                '<span class="emailFrom">'+from+'</span>'+
                '<span style="color:var(--border)">•</span>'+
                '<span class="emailDate">'+date+'</span>'+
              '</div>'+
              '<div class="emailActions" onclick="event.stopPropagation()">'+
                '<button class="btn-primary" onclick="openEmail(\''+m.id+'\')">'+
                  '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'+
                    '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>'+
                    '<circle cx="12" cy="12" r="3"/>'+
                  '</svg>'+
                  'View'+
                '</button>'+
                '<button onclick="delEmail(\''+m.id+'\')" class="danger">'+
                  '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'+
                    '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>'+
                  '</svg>'+
                  'Delete'+
                '</button>'+
              '</div>';
            box.appendChild(d);
          }
        }

        async function openEmail(id){
          const j = await api('/api/emails/'+encodeURIComponent(id));
          if(!j.ok){ alert(j.error||'gagal'); return; }

          const v=document.getElementById('emailView');
          v.style.display='block';

          v.innerHTML =
            '<div class="emailViewer">'+
              '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">'+
                '<h2 style="font-size:18px;color:var(--brand);margin:0">📧 Email Details</h2>'+
                '<button class="btn-ghost" onclick="document.getElementById(\'emailView\').style.display=\'none\'">'+
                  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'+
                    '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>'+
                  '</svg>'+
                  'Close'+
                '</button>'+
              '</div>'+
              '<div class="emailViewerHeader">'+
                '<div class="emailViewerSubject">'+esc(j.email.subject||'(no subject)')+'</div>'+
                '<div class="emailViewerMeta">'+
                  '<div><label>From:</label><span>'+esc(j.email.from_addr)+'</span></div>'+
                  '<div><label>To:</label><span>'+esc(j.email.to_addr)+'</span></div>'+
                  '<div><label>Date:</label><span>'+esc(j.email.date||'')+'</span></div>'+
                '</div>'+
              '</div>'+
              '<div id="msgBody"></div>'+
            '</div>';

          const body = document.getElementById('msgBody');

          if (j.email.html) {
            const iframe = document.createElement('iframe');
            iframe.setAttribute('sandbox','');
            iframe.setAttribute('referrerpolicy','no-referrer');
            iframe.className='emailViewerBody';
            iframe.srcdoc = j.email.html;

            const wrapper = document.createElement('div');
            wrapper.appendChild(iframe);

            const note = document.createElement('div');
            note.className = 'muted-dark';
            note.style.cssText = 'margin-top:12px;font-size:12px;text-align:center';
            note.innerHTML = '🔒 HTML displayed in sandboxed iframe (safe from XSS)';
            wrapper.appendChild(note);

            body.appendChild(wrapper);
          } else {
            const pre = document.createElement('pre');
            pre.className = 'emailViewerBody';
            pre.style.cssText = 'white-space:pre-wrap;word-break:break-word;font-family:inherit';
            pre.textContent = j.email.text || '(empty)';
            body.appendChild(pre);
          }

          v.scrollIntoView({behavior:'smooth',block:'start'});
        }

        async function createAlias(){
          const local = document.getElementById('alias').value.trim().toLowerCase();
          const msg=document.getElementById('aliasMsg');
          msg.innerHTML='<span class="spinner"></span> Creating...';

          try{
            const j = await api('/api/aliases', {
              method:'POST',
              headers:{'content-type':'application/json'},
              body:JSON.stringify({local})
            });

            if(j.ok){
              msg.innerHTML='✅ Alias created successfully!';
              document.getElementById('alias').value='';
              await loadMe();
              await loadAliases();
              setTimeout(()=>msg.innerHTML='',3000);
            }else{
              msg.innerHTML='❌ '+(j.error||'Failed to create alias');
            }
          }catch(e){
            msg.innerHTML='❌ '+e.message;
          }
        }

        async function delAlias(local){
          if(!confirm('Delete alias '+local+'@${domain}?')) return;
          const j = await api('/api/aliases/'+encodeURIComponent(local), {method:'DELETE'});
          if(!j.ok){ alert(j.error||'gagal'); return; }

          if(SELECTED===local){
            SELECTED=null;
            document.getElementById('selAlias').textContent='Pilih alias untuk melihat email';
            document.getElementById('emails').innerHTML='';
            document.getElementById('refreshBtn').disabled=true;
          }
          document.getElementById('emailView').style.display='none';
          await loadMe();
          await loadAliases();
        }

        async function delEmail(id){
          if(!confirm('Delete this email?')) return;
          const j = await api('/api/emails/'+encodeURIComponent(id), {method:'DELETE'});
          if(!j.ok){ alert(j.error||'gagal'); return; }
          document.getElementById('emailView').style.display='none';
          await loadEmails();
        }

        async function logout(){
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
        subtitle: "Kelola user & limit alias • @" + domain,
        rightHtml: `
          <a href="/app" class="pill">Inbox</a>
          <button class="danger" onclick="logout()">Logout</button>
        `,
      })}

      <div class="card">
        <b>Users</b>
        <div class="muted" style="margin-top:6px">Domain: <span class="kbd">@${domain}</span></div>
        <div id="users" style="margin-top:10px"></div>
      </div>

      <script>
        function esc(s){return (s||'').replace(/[&<>\"']/g, m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}

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
                '<div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">'+
                  (u.role==='admin' ? '<span class="pill">admin</span>' : '<span class="pill">user</span>')+
                  (u.disabled?'<span class="pill">disabled</span>':'')+
                  '<span class="pill">created: '+esc(u.created_at)+'</span>'+
                '</div>'+
              '</div>'+
              '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">'+
                '<input id="lim_'+esc(u.id)+'" value="'+u.alias_limit+'" style="width:120px" />'+
                '<button class="btn-primary" onclick="setLimit(\''+esc(u.id)+'\')">Set limit</button>'+
                '<button onclick="toggleUser(\''+esc(u.id)+'\','+(u.disabled?0:1)+')" class="danger">'+(u.disabled?'Enable':'Disable')+'</button>'+
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

// Auth/session helpers
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
  await env.DB.prepare(`DELETE FROM sessions WHERE token_hash = ?`)
    .bind(tokenHash)
    .run();
}

async function cleanupExpired(env) {
  const t = nowSec();
  try {
    await env.DB.prepare(`DELETE FROM sessions WHERE expires_at <= ?`).bind(t).run();
  } catch (e) {
    console.log("cleanup sessions error:", e?.message || String(e));
  }
  try {
    await env.DB.prepare(`DELETE FROM reset_tokens WHERE expires_at <= ?`).bind(t).run();
  } catch (e) {
    console.log("cleanup reset_tokens error:", e?.message || String(e));
  }
}

// Reset email (optional Resend)
async function sendResetEmail(env, toEmail, token) {
  if (!env.RESEND_API_KEY) return;

  const base = env.APP_BASE_URL || "";
  const link = base ? `${base}/reset#token=${encodeURIComponent(token)}` : "";

  const subject = "Reset password";
  const bodyHtml = `
    <div style="font-family:Arial,sans-serif">
      <p>Permintaan reset password.</p>
      <p><b>Token:</b> ${token}</p>
      ${link ? `<p>Atau klik: <a href="${link}">${link}</a></p>` : ""}
      <p>Jika bukan kamu, abaikan email ini.</p>
    </div>
  `;

  const from = env.RESET_FROM || `no-reply@${env.DOMAIN}`;

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
    console.log("Resend failed:", r.status, txt.slice(0, 300));
  }
}

// Worker entry
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
        // Auth
        if (path === "/api/auth/signup" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const username = String(body.username || "").trim().toLowerCase();
          const email = String(body.email || "").trim().toLowerCase();
          const pw = String(body.pw || "");

          if (!/^[a-z0-9_]{3,24}$/.test(username))
            return badRequest("Username 3-24, a-z0-9_");
          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
            return badRequest("Email tidak valid");
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
            if (msg.toUpperCase().includes("UNIQUE"))
              return badRequest("Username/email sudah dipakai");
            console.log("signup db error:", msg);
            return json({ ok: false, error: "DB error" }, 500);
          }

          const ttl = safeInt(env.SESSION_TTL_SECONDS, 1209600);
          const token = await createSession(env, id, ttl);

          return json(
            { ok: true },
            200,
            { "set-cookie": setCookieHeader("session", token, { maxAge: ttl, secure: cookieSecure }) }
          );
        }

        if (path === "/api/auth/login" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const id = String(body.id || "").trim().toLowerCase();
          const pw = String(body.pw || "");

          if (!id || !pw) return badRequest("Lengkapi data");

          const hasIters = await usersHasPassIters(env);
          let query = `SELECT id, username, email, pass_salt, pass_hash, role, alias_limit, disabled FROM users WHERE username = ? OR email = ?`;
          if (hasIters) {
            query = `SELECT id, username, email, pass_salt, pass_hash, pass_iters, role, alias_limit, disabled FROM users WHERE username = ? OR email = ?`;
          }

          const user = await env.DB.prepare(query).bind(id, id).first();

          if (!user || user.disabled) return unauthorized("Login gagal");

          const saltBytes = base64UrlToBytes(user.pass_salt);
          const userIters = user.pass_iters ? Number(user.pass_iters) : pbkdf2Iters(env);
          const hash = await pbkdf2HashBase64Url(pw, saltBytes, userIters);
          if (hash !== user.pass_hash) return unauthorized("Login gagal");

          const ttl = safeInt(env.SESSION_TTL_SECONDS, 1209600);
          const token = await createSession(env, user.id, ttl);

          return json(
            { ok: true },
            200,
            { "set-cookie": setCookieHeader("session", token, { maxAge: ttl, secure: cookieSecure }) }
          );
        }

        if (path === "/api/auth/logout" && request.method === "POST") {
          await destroySession(request, env);
          return json(
            { ok: true },
            200,
            { "set-cookie": setCookieHeader("session", "", { maxAge: 0, secure: cookieSecure }) }
          );
        }

        if (path === "/api/auth/reset/request" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");
          const email = String(body.email || "").trim().toLowerCase();
          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
            return badRequest("Email tidak valid");

          const user = await env.DB.prepare(
            `SELECT id, disabled FROM users WHERE email = ?`
          )
            .bind(email)
            .first();

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

          await env.DB.prepare(`DELETE FROM reset_tokens WHERE token_hash=?`)
            .bind(tokenHash)
            .run();

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

        // Aliases
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
          if (!validLocalPart(local)) return badRequest("Alias tidak valid (a-z0-9._+- max 64)");

          const cnt = await env.DB.prepare(
            `SELECT COUNT(*) as c FROM aliases WHERE user_id = ? AND disabled = 0`
          )
            .bind(me.id)
            .first();

          if ((cnt?.c || 0) >= me.alias_limit) return forbidden("Limit alias tercapai");

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
            if (msg.toUpperCase().includes("UNIQUE")) return badRequest("Alias sudah dipakai");
            return json({ ok: false, error: "DB error" }, 500);
          }

          return json({ ok: true });
        }

        if (path.startsWith("/api/aliases/") && request.method === "DELETE") {
          const local = decodeURIComponent(path.slice("/api/aliases/".length)).toLowerCase();
          if (!validLocalPart(local)) return badRequest("Alias invalid");

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
          if (!own) return forbidden("Alias bukan milikmu / disabled");

          const rows = await env.DB.prepare(
            `SELECT id, from_addr, to_addr, subject, date, created_at
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
          const row = await env.DB.prepare(
            `SELECT raw_key FROM emails WHERE id = ? AND user_id = ?`
          )
            .bind(id, me.id)
            .first();
          if (!row) return notFound();

          await env.DB.prepare(`DELETE FROM emails WHERE id = ? AND user_id = ?`)
            .bind(id, me.id)
            .run();

          if (row.raw_key && env.MAIL_R2) {
            ctx.waitUntil(env.MAIL_R2.delete(row.raw_key));
          }

          return json({ ok: true });
        }

        // Admin endpoints
        if (path === "/api/admin/users" && request.method === "GET") {
          if (me.role !== "admin") return forbidden("Forbidden");

          const rows = await env.DB.prepare(
            `SELECT id, username, email, role, alias_limit, disabled, created_at
             FROM users ORDER BY created_at DESC LIMIT 200`
          ).all();

          const users = (rows.results || []).map(u => ({
            ...u,
            created_at: new Date(u.created_at * 1000).toISOString()
          }));

          return json({ ok: true, users });
        }

        if (path.startsWith("/api/admin/users/") && request.method === "PATCH") {
          if (me.role !== "admin") return forbidden("Forbidden");
          const userId = decodeURIComponent(path.slice("/api/admin/users/".length));
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const alias_limit = body.alias_limit !== undefined ? safeInt(body.alias_limit, NaN) : undefined;
          const disabled = body.disabled !== undefined ? safeInt(body.disabled, NaN) : undefined;

          if (alias_limit !== undefined && (!Number.isFinite(alias_limit) || alias_limit < 0 || alias_limit > 1000)) {
            return badRequest("alias_limit invalid");
          }
          if (disabled !== undefined && !(disabled === 0 || disabled === 1)) {
            return badRequest("disabled invalid");
          }

          const sets = [];
          const binds = [];
          if (alias_limit !== undefined) { sets.push("alias_limit = ?"); binds.push(alias_limit); }
          if (disabled !== undefined) { sets.push("disabled = ?"); binds.push(disabled); }
          if (sets.length === 0) return badRequest("No fields");

          binds.push(userId);

          await env.DB.prepare(`UPDATE users SET ${sets.join(", ")} WHERE id = ?`)
            .bind(...binds)
            .run();

          return json({ ok: true });
        }

        return notFound();
      } catch (err) {
        console.log("api error:", err?.message || String(err));
        return json({ ok: false, error: String(err && err.message ? err.message : err) }, 500);
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

      const parser = new PostalMime.default();
      const rawEmail = new Response(message.raw);
      const ab = await rawEmail.arrayBuffer();
      const parsed = await parser.parse(ab);

      const id = crypto.randomUUID();
      const t = nowSec();

      const subject = parsed.subject || "";
      const date = parsed.date ? new Date(parsed.date).toISOString() : "";
      const fromAddr = (parsed.from && parsed.from.address) ? parsed.from.address : (message.from || "");
      const toAddr = message.to || "";

      const maxTextChars = safeInt(env.MAX_TEXT_CHARS, 200000);
      const text = (parsed.text || "").slice(0, maxTextChars);
      const htmlPart = (parsed.html || "").slice(0, maxTextChars);

      let raw_key = null;
      if (env.MAIL_R2) {
        raw_key = `emails/${id}.eml`;
        ctx.waitUntil(
          env.MAIL_R2.put(raw_key, ab, {
            httpMetadata: { contentType: "message/rfc822" },
          })
        );
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
      console.log("email handler error:", e && e.message ? e.message : e);
      message.setReject("Temporary processing error");
    }
  },
};
