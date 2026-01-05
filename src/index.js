// src/index.js
import * as PostalMime from "postal-mime";

/**
 * Cloudflare Email Routing + Email Worker + Web Inbox
 * Features:
 * - Signup/Login/Logout
 * - Reset password (opsional via Resend API)
 * - Alias management with per-user limit
 * - Admin dashboard: list users, set alias limit, disable user
 * - Email handler: accept via catch-all, store if alias registered else reject
 */

const encoder = new TextEncoder();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
  });
}

function html(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", ...headers },
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

function safeInt(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function base64Url(bytes) {
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256Base64Url(inputBytes) {
  const digest = await crypto.subtle.digest("SHA-256", inputBytes);
  return base64Url(new Uint8Array(digest));
}

async function pbkdf2HashBase64Url(password, saltBytes, iterations = 310000) {
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
      iterations,
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
    if (!ct.includes("application/json")) return null;
    return await request.json();
  } catch {
    return null;
  }
}

function validLocalPart(local) {
  // simple + aman: huruf angka . _ + - (1..64)
  return /^[a-z0-9][a-z0-9._+-]{0,63}$/.test(local);
}

function pageTemplate(title, body, extraHead = "") {
  return `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${title}</title>
  ${extraHead}
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#0b0f14;color:#e6edf3}
    a{color:#7dd3fc;text-decoration:none}
    .wrap{max-width:980px;margin:0 auto;padding:24px}
    .card{background:#101826;border:1px solid #1f2a37;border-radius:14px;padding:16px;margin:12px 0}
    input,button,select,textarea{font:inherit}
    input,select,textarea{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #243244;background:#0b1220;color:#e6edf3}
    button{padding:10px 12px;border-radius:10px;border:1px solid #243244;background:#132033;color:#e6edf3;cursor:pointer}
    button:hover{background:#162a45}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    .row3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
    .muted{color:#93a4b8}
    .top{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
    .pill{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid #243244;background:#0b1220;color:#93a4b8;font-size:12px}
    table{width:100%;border-collapse:collapse}
    th,td{padding:10px;border-bottom:1px solid #243244;text-align:left;vertical-align:top}
    .danger{border-color:#5b2230;background:#1a0f15}
  </style>
</head>
<body>
  <div class="wrap">
    ${body}
  </div>
</body>
</html>`;
}

const PAGES = {
  login() {
    return pageTemplate(
      "Login",
      `
      <div class="top">
        <div><b>Mail Portal</b> <span class="pill">Login</span></div>
        <div class="muted">Domain alias + inbox</div>
      </div>

      <div class="card">
        <div class="row">
          <div>
            <label>Username / Email</label>
            <input id="id" placeholder="sipar / sipar@gmail.com" />
          </div>
          <div>
            <label>Password</label>
            <input id="pw" type="password" placeholder="••••••••" />
          </div>
        </div>
        <div style="margin-top:12px;display:flex;gap:10px;align-items:center">
          <button onclick="login()">Login</button>
          <a href="/signup">Buat akun</a>
          <a href="/reset" class="muted">Lupa password?</a>
        </div>
        <pre id="out" class="muted"></pre>
      </div>

      <script>
        async function login(){
          const id = document.getElementById('id').value.trim();
          const pw = document.getElementById('pw').value;
          const out = document.getElementById('out');
          out.textContent = '...';
          const r = await fetch('/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id,pw})});
          const j = await r.json().catch(()=>({ok:false,error:'bad json'}));
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
      <div class="top">
        <div><b>Mail Portal</b> <span class="pill">Signup</span></div>
        <div class="muted">Alias email: <b>@${domain}</b></div>
      </div>

      <div class="card">
        <div class="row">
          <div>
            <label>Username</label>
            <input id="u" placeholder="sipar" />
          </div>
          <div>
            <label>Email (untuk reset password)</label>
            <input id="e" placeholder="sipar@gmail.com" />
          </div>
        </div>
        <div style="margin-top:12px">
          <label>Password</label>
          <input id="pw" type="password" placeholder="minimal 8 karakter" />
        </div>
        <div style="margin-top:12px;display:flex;gap:10px;align-items:center">
          <button onclick="signup()">Create account</button>
          <a href="/login" class="muted">Sudah punya akun?</a>
        </div>
        <pre id="out" class="muted"></pre>
      </div>

      <script>
        async function signup(){
          const username = document.getElementById('u').value.trim();
          const email = document.getElementById('e').value.trim();
          const pw = document.getElementById('pw').value;
          const out = document.getElementById('out');
          out.textContent = '...';
          const r = await fetch('/api/auth/signup',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username,email,pw})});
          const j = await r.json().catch(()=>({ok:false,error:'bad json'}));
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
      <div class="top">
        <div><b>Mail Portal</b> <span class="pill">Reset</span></div>
        <div class="muted">Kirim link reset ke email</div>
      </div>

      <div class="card">
        <label>Email akun</label>
        <input id="e" placeholder="sipar@gmail.com" />
        <div style="margin-top:12px;display:flex;gap:10px;align-items:center">
          <button onclick="reqReset()">Kirim reset link</button>
          <a href="/login" class="muted">Balik</a>
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
            <input id="npw" type="password" placeholder="••••••••" />
          </div>
        </div>
        <div style="margin-top:12px">
          <button onclick="confirmReset()">Set password</button>
        </div>
        <pre id="out2" class="muted"></pre>
      </div>

      <script>
        async function reqReset(){
          const email = document.getElementById('e').value.trim();
          const out = document.getElementById('out');
          out.textContent = '...';
          const r = await fetch('/api/auth/reset/request',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email})});
          const j = await r.json().catch(()=>({ok:false,error:'bad json'}));
          out.textContent = j.ok ? 'Jika email terdaftar, link/token reset dikirim.' : (j.error || 'gagal');
        }
        async function confirmReset(){
          const token = document.getElementById('t').value.trim();
          const newPw = document.getElementById('npw').value;
          const out = document.getElementById('out2');
          out.textContent = '...';
          const r = await fetch('/api/auth/reset/confirm',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({token,newPw})});
          const j = await r.json().catch(()=>({ok:false,error:'bad json'}));
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
      <div class="top">
        <div><b>Mail Portal</b> <span class="pill">Inbox</span></div>
        <div style="display:flex;gap:10px;align-items:center">
          <a href="/admin" id="adminLink" style="display:none">Admin</a>
          <button onclick="logout()">Logout</button>
        </div>
      </div>

      <div class="card">
        <div class="row">
          <div>
            <div class="muted">Akun</div>
            <div id="me">...</div>
          </div>
          <div>
            <div class="muted">Buat alias baru (@${domain})</div>
            <div class="row" style="grid-template-columns:1fr auto;gap:10px">
              <input id="alias" placeholder="contoh: sipar" />
              <button onclick="createAlias()">Create</button>
            </div>
            <div id="aliasMsg" class="muted"></div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="row">
          <div>
            <div style="display:flex;justify-content:space-between;align-items:center">
              <b>Aliases</b>
              <span class="muted" id="limitInfo"></span>
            </div>
            <div id="aliases"></div>
          </div>
          <div>
            <b>Emails</b>
            <div class="muted" id="selAlias">Pilih alias…</div>
            <div id="emails"></div>
          </div>
        </div>
      </div>

      <div class="card" id="emailView" style="display:none"></div>

      <script>
        let ME=null;
        let SELECTED=null;

        function esc(s){return (s||'').replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m]));}

        async function api(path, opts){
          const r = await fetch(path, opts);
          const j = await r.json().catch(()=>null);
          if(!j) throw new Error('bad json');
          return j;
        }

        async function loadMe(){
          const j = await api('/api/me');
          if(!j.ok){ location.href='/login'; return; }
          ME=j.user;
          document.getElementById('me').innerHTML =
            '<div><b>'+esc(ME.username)+'</b> ('+esc(ME.email)+')</div>'+
            '<div class="muted">role: '+esc(ME.role)+'</div>';
          document.getElementById('limitInfo').textContent = 'limit: '+ME.alias_limit;
          if(ME.role==='admin') document.getElementById('adminLink').style.display='inline';
        }

        async function loadAliases(){
          const j = await api('/api/aliases');
          if(!j.ok){ alert(j.error||'gagal'); return; }
          const box = document.getElementById('aliases');
          box.innerHTML='';
          if(j.aliases.length===0){
            box.innerHTML='<div class="muted">Belum ada alias.</div>';
            return;
          }
          for(const a of j.aliases){
            const div=document.createElement('div');
            div.style.display='flex';
            div.style.justifyContent='space-between';
            div.style.alignItems='center';
            div.style.padding='8px 0';
            div.style.borderBottom='1px solid #243244';
            const addr = a.local_part+'@${domain}';
            div.innerHTML =
              '<div><button onclick="selectAlias(\\''+esc(a.local_part)+'\\')">Open</button> '+
              '<span style="margin-left:8px">'+esc(addr)+'</span> '+
              (a.disabled?'<span class="pill">disabled</span>':'')+
              '</div>'+
              '<div><button onclick="delAlias(\\''+esc(a.local_part)+'\\')" class="danger">Delete</button></div>';
            box.appendChild(div);
          }
        }

        async function selectAlias(local){
          SELECTED=local;
          document.getElementById('selAlias').textContent = 'Alias: '+local+'@${domain}';
          await loadEmails();
        }

        async function loadEmails(){
          if(!SELECTED) return;
          const j = await api('/api/emails?alias='+encodeURIComponent(SELECTED));
          if(!j.ok){ alert(j.error||'gagal'); return; }
          const box=document.getElementById('emails');
          box.innerHTML='';
          if(j.emails.length===0){
            box.innerHTML='<div class="muted">Belum ada email masuk.</div>';
            return;
          }
          for(const m of j.emails){
            const d=document.createElement('div');
            d.style.padding='10px 0';
            d.style.borderBottom='1px solid #243244';
            d.innerHTML =
              '<div><b>'+esc(m.subject||'(no subject)')+'</b></div>'+
              '<div class="muted">From: '+esc(m.from_addr)+'</div>'+
              '<div class="muted">'+esc(m.date||'')+'</div>'+
              '<div style="margin-top:6px"><button onclick="openEmail(\\''+esc(m.id)+'\\')">View</button> '+
              '<button onclick="delEmail(\\''+esc(m.id)+'\\')" class="danger">Delete</button></div>';
            box.appendChild(d);
          }
        }

        async function openEmail(id){
          const j = await api('/api/emails/'+encodeURIComponent(id));
          if(!j.ok){ alert(j.error||'gagal'); return; }
          const v=document.getElementById('emailView');
          v.style.display='block';
          v.innerHTML =
            '<b>'+esc(j.email.subject||'(no subject)')+'</b>'+
            '<div class="muted">From: '+esc(j.email.from_addr)+'</div>'+
            '<div class="muted">To: '+esc(j.email.to_addr)+'</div>'+
            '<div class="muted">'+esc(j.email.date||'')+'</div>'+
            '<hr style="border:0;border-top:1px solid #243244;margin:12px 0" />'+
            (j.email.html ? ('<div>'+j.email.html+'</div>') : ('<pre style="white-space:pre-wrap">'+esc(j.email.text||'')+'</pre>'));
          v.scrollIntoView({behavior:'smooth'});
        }

        async function createAlias(){
          const local = document.getElementById('alias').value.trim().toLowerCase();
          const msg=document.getElementById('aliasMsg');
          msg.textContent='...';
          const j = await api('/api/aliases', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({local})});
          msg.textContent = j.ok ? 'Alias dibuat.' : (j.error||'gagal');
          if(j.ok){ document.getElementById('alias').value=''; await loadMe(); await loadAliases(); }
        }

        async function delAlias(local){
          if(!confirm('Hapus alias '+local+'@${domain} ?')) return;
          const j = await api('/api/aliases/'+encodeURIComponent(local), {method:'DELETE'});
          if(!j.ok){ alert(j.error||'gagal'); return; }
          if(SELECTED===local){ SELECTED=null; document.getElementById('selAlias').textContent='Pilih alias…'; document.getElementById('emails').innerHTML=''; }
          await loadMe(); await loadAliases();
        }

        async function delEmail(id){
          if(!confirm('Hapus email ini?')) return;
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
          await loadMe();
          await loadAliases();
        })();
      </script>
      `
    );
  },

  admin(domain) {
    return pageTemplate(
      "Admin",
      `
      <div class="top">
        <div><b>Admin</b> <span class="pill">Dashboard</span></div>
        <div style="display:flex;gap:10px;align-items:center">
          <a href="/app">Inbox</a>
          <button onclick="logout()">Logout</button>
        </div>
      </div>

      <div class="card">
        <b>Users</b>
        <div class="muted">Domain: @${domain}</div>
        <div id="users"></div>
      </div>

      <script>
        function esc(s){return (s||'').replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m]));}
        async function api(path, opts){
          const r = await fetch(path, opts);
          const j = await r.json().catch(()=>null);
          if(!j) throw new Error('bad json');
          return j;
        }

        async function loadUsers(){
          const j = await api('/api/admin/users');
          if(!j.ok){ alert(j.error||'gagal'); if(j.error==='Forbidden') location.href='/app'; return; }
          const box=document.getElementById('users');
          box.innerHTML='';
          for(const u of j.users){
            const div=document.createElement('div');
            div.style.padding='10px 0';
            div.style.borderBottom='1px solid #243244';
            div.innerHTML =
              '<div style="display:flex;justify-content:space-between;gap:10px;align-items:center">'+
              '<div>'+
              '<b>'+esc(u.username)+'</b> <span class="muted">('+esc(u.email)+')</span> '+
              (u.role==='admin' ? '<span class="pill">admin</span>' : '')+
              (u.disabled?'<span class="pill">disabled</span>':'')+
              '</div>'+
              '<div style="display:flex;gap:8px;align-items:center;min-width:320px">'+
              '<input id="lim_'+esc(u.id)+'" value="'+u.alias_limit+'" style="width:120px" />'+
              '<button onclick="setLimit(\\''+esc(u.id)+'\\')">Set limit</button>'+
              '<button onclick="toggleUser(\\''+esc(u.id)+'\\','+(u.disabled?0:1)+')" class="danger">'+(u.disabled?'Enable':'Disable')+'</button>'+
              '</div>'+
              '</div>'+
              '<div class="muted">created: '+esc(u.created_at)+'</div>';
            box.appendChild(div);
          }
        }

        async function setLimit(id){
          const v = document.getElementById('lim_'+id).value;
          const lim = parseInt(v,10);
          const j = await api('/api/admin/users/'+encodeURIComponent(id), {method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({alias_limit:lim})});
          if(!j.ok){ alert(j.error||'gagal'); return; }
          await loadUsers();
        }

        async function toggleUser(id, disabled){
          const j = await api('/api/admin/users/'+encodeURIComponent(id), {method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({disabled})});
          if(!j.ok){ alert(j.error||'gagal'); return; }
          await loadUsers();
        }

        async function logout(){
          await fetch('/api/auth/logout',{method:'POST'});
          location.href='/login';
        }

        loadUsers();
      </script>
      `
    );
  },
};

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
  await env.DB.prepare(`DELETE FROM sessions WHERE expires_at <= ?`).bind(t).run();
  await env.DB.prepare(`DELETE FROM reset_tokens WHERE expires_at <= ?`).bind(t).run();
}

async function sendResetEmail(env, toEmail, token) {
  // Mode 1 (recommended): Resend (transactional email).
  // Cloudflare tutorial: https://developers.cloudflare.com/workers/tutorials/send-emails-with-resend/ :contentReference[oaicite:6]{index=6}
  if (!env.RESEND_API_KEY) {
    // Kalau nggak set RESEND_API_KEY, kita tetap return ok (biar nggak bocorin email exist)
    return;
  }
  const base = env.APP_BASE_URL || "";
  const link = base ? `${base}/reset#token=${encodeURIComponent(token)}` : "";
  const subject = "Reset password";
  const bodyHtml = `
    <div>
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
    // jangan bocorkan error ke user, cukup log
    const txt = await r.text().catch(() => "");
    console.log("Resend failed:", r.status, txt.slice(0, 300));
  }
}

export default {
  async fetch(request, env, ctx) {
    ctx.waitUntil(cleanupExpired(env));

    const url = new URL(request.url);
    const path = url.pathname;

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

        const salt = crypto.getRandomValues(new Uint8Array(16));
        const pass_salt = base64Url(salt);
        const pass_hash = await pbkdf2HashBase64Url(pw, salt);

        const t = nowSec();
        const id = crypto.randomUUID();

        // first user becomes admin
        const c = await env.DB.prepare(`SELECT COUNT(*) as c FROM users`).first();
        const role = (c && c.c === 0) ? "admin" : "user";
        const aliasLimit = safeInt(env.DEFAULT_ALIAS_LIMIT, 3);

        try {
          await env.DB.prepare(
            `INSERT INTO users (id, username, email, pass_salt, pass_hash, role, alias_limit, disabled, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`
          )
            .bind(id, username, email, pass_salt, pass_hash, role, aliasLimit, t)
            .run();
        } catch (e) {
          const msg = String(e && e.message ? e.message : e);
          if (msg.includes("UNIQUE")) return badRequest("Username/email sudah dipakai");
          return json({ ok: false, error: "DB error" }, 500);
        }

        const ttl = safeInt(env.SESSION_TTL_SECONDS, 1209600);
        const token = await createSession(env, id, ttl);

        return json(
          { ok: true },
          200,
          { "set-cookie": setCookieHeader("session", token, { maxAge: ttl }) }
        );
      }

      if (path === "/api/auth/login" && request.method === "POST") {
        const body = await readJson(request);
        if (!body) return badRequest("JSON required");

        const id = String(body.id || "").trim().toLowerCase(); // username or email
        const pw = String(body.pw || "");

        if (!id || !pw) return badRequest("Lengkapi data");

        const user = await env.DB.prepare(
          `SELECT id, username, email, pass_salt, pass_hash, role, alias_limit, disabled
           FROM users WHERE username = ? OR email = ?`
        )
          .bind(id, id)
          .first();

        if (!user || user.disabled) return unauthorized("Login gagal");

        const saltBytes = Uint8Array.from(atob(user.pass_salt.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
        const hash = await pbkdf2HashBase64Url(pw, saltBytes);
        if (hash !== user.pass_hash) return unauthorized("Login gagal");

        const ttl = safeInt(env.SESSION_TTL_SECONDS, 1209600);
        const token = await createSession(env, user.id, ttl);

        return json(
          { ok: true },
          200,
          { "set-cookie": setCookieHeader("session", token, { maxAge: ttl }) }
        );
      }

      if (path === "/api/auth/logout" && request.method === "POST") {
        await destroySession(request, env);
        return json(
          { ok: true },
          200,
          { "set-cookie": setCookieHeader("session", "", { maxAge: 0 }) }
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

        // Selalu balas ok (anti user-enumeration)
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

        const salt = crypto.getRandomValues(new Uint8Array(16));
        const pass_salt = base64Url(salt);
        const pass_hash = await pbkdf2HashBase64Url(newPw, salt);

        await env.DB.prepare(`UPDATE users SET pass_salt=?, pass_hash=? WHERE id=?`)
          .bind(pass_salt, pass_hash, rt.user_id)
          .run();
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

        // enforce limit
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
          if (msg.includes("UNIQUE")) return badRequest("Alias sudah dipakai");
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

        // check ownership
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

        // NOTE: html disimpan apa adanya dari parser; kalau mau aman,
        // sebaiknya sanitize sebelum render. Di UI ini, kita render langsung.
        // Untuk production, sanitize dulu.
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

        // format created_at
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
    }

    return notFound();
  },

  async email(message, env, ctx) {
    // Email Workers runtime API supports setReject / forward / reply. :contentReference[oaicite:7]{index=7}
    try {
      const domain = String(env.DOMAIN || "").toLowerCase();
      const to = String(message.to || "").toLowerCase();
      const [local, toDomain] = to.split("@");

      if (!local || !toDomain || toDomain !== domain) {
        message.setReject("Bad recipient");
        return;
      }

      // Lookup alias + user
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
        // Cloudflare limit global 25 MiB, tapi kita boleh bikin limit lebih kecil. :contentReference[oaicite:8]{index=8}
        message.setReject("Message too large");
        return;
      }

      // Parse email using postal-mime pattern similar to Cloudflare docs local-dev example. :contentReference[oaicite:9]{index=9}
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
        // store raw in background
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

      // Tidak perlu forward: ini jadi "web inbox".
      // Kalau kamu mau forward juga (mis. ke admin inbox), kamu bisa:
      // await message.forward("tujuan@yang-sudah-verified");
    } catch (e) {
      console.log("email handler error:", e && e.message ? e.message : e);
      // Fail-safe: jangan accept email yang error parsing/db
      message.setReject("Temporary processing error");
    }
  },
};
