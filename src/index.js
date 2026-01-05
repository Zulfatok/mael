// src/index.js
// Mail Portal with Org_Lemah Branding - Fixed Version
// Ready to deploy to Cloudflare Workers

import * as PostalMime from "postal-mime";

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

// ✅ FIXED: Better JSON parsing with validation
async function readJson(request) {
  try {
    const ct = request.headers.get("content-type") || "";
    if (!ct.includes("application/json")) return null;
    const text = await request.text();
    if (!text || text.trim() === "") return null;
    return JSON.parse(text);
  } catch (err) {
    console.error("JSON parse error:", err);
    return null;
  }
}

function validLocalPart(local) {
  return /^[a-z0-9][a-z0-9._+-]{0,63}$/.test(local);
}

// ✅ NEW: Modern page template with Org_Lemah branding
function pageTemplate(title, body, extraHead = "") {
  return `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${title}</title>
  ${extraHead}
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: #2d3748;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }

    .container {
      width: 100%;
      max-width: 480px;
      margin: 0 auto;
    }

    .logo-section {
      text-align: center;
      margin-bottom: 30px;
      animation: fadeInDown 0.6s ease-out;
    }

    .logo {
      width: 80px;
      height: 80px;
      background: white;
      border-radius: 20px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 10px 30px rgba(0,0,0,0.2);
      font-size: 36px;
      font-weight: 700;
      color: #667eea;
      margin-bottom: 16px;
    }

    .logo-text {
      font-size: 28px;
      font-weight: 700;
      color: white;
      text-shadow: 0 2px 10px rgba(0,0,0,0.2);
      margin-bottom: 8px;
    }

    .logo-subtitle {
      color: rgba(255,255,255,0.9);
      font-size: 14px;
    }

    .card {
      background: white;
      border-radius: 20px;
      padding: 32px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      animation: fadeInUp 0.6s ease-out;
      margin-bottom: 20px;
    }

    @keyframes fadeInDown {
      from { opacity: 0; transform: translateY(-20px); }
      to { opacity: 1; transform: translateY(0); }
    }

    @keyframes fadeInUp {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .card-title {
      font-size: 24px;
      font-weight: 700;
      color: #1a202c;
      margin-bottom: 8px;
    }

    .card-subtitle {
      color: #718096;
      font-size: 14px;
      margin-bottom: 24px;
    }

    .form-group {
      margin-bottom: 20px;
    }

    label {
      display: block;
      font-size: 14px;
      font-weight: 600;
      color: #4a5568;
      margin-bottom: 8px;
    }

    input, select, textarea {
      width: 100%;
      padding: 12px 16px;
      border: 2px solid #e2e8f0;
      border-radius: 12px;
      font-size: 15px;
      transition: all 0.3s ease;
      background: #f7fafc;
    }

    input:focus, select:focus, textarea:focus {
      outline: none;
      border-color: #667eea;
      background: white;
      box-shadow: 0 0 0 3px rgba(102,126,234,0.1);
    }

    button {
      width: 100%;
      padding: 14px 20px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 12px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s ease;
      box-shadow: 0 4px 12px rgba(102,126,234,0.4);
    }

    button:hover:not(:disabled) {
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(102,126,234,0.6);
    }

    button:active {
      transform: translateY(0);
    }

    button:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none;
    }

    .links {
      text-align: center;
      margin-top: 20px;
      font-size: 14px;
    }

    .links a {
      color: #667eea;
      text-decoration: none;
      font-weight: 600;
      transition: color 0.3s ease;
    }

    .links a:hover {
      color: #764ba2;
      text-decoration: underline;
    }

    .links .separator {
      color: #cbd5e0;
      margin: 0 12px;
    }

    .alert {
      padding: 12px 16px;
      border-radius: 12px;
      margin-top: 16px;
      font-size: 14px;
      animation: slideIn 0.3s ease-out;
    }

    @keyframes slideIn {
      from { opacity: 0; transform: translateY(-10px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .alert-error {
      background: #fed7d7;
      color: #c53030;
      border: 1px solid #fc8181;
    }

    .alert-success {
      background: #c6f6d5;
      color: #2f855a;
      border: 1px solid #68d391;
    }

    .alert-info {
      background: #bee3f8;
      color: #2c5282;
      border: 1px solid #63b3ed;
    }

    .spinner {
      border: 3px solid #f3f3f3;
      border-top: 3px solid #667eea;
      border-radius: 50%;
      width: 20px;
      height: 20px;
      animation: spin 1s linear infinite;
      display: inline-block;
      margin-right: 8px;
      vertical-align: middle;
    }

    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }

    @media (max-width: 640px) {
      body { padding: 16px; }
      .card { padding: 24px; }
      .card-title { font-size: 20px; }
      .logo { width: 64px; height: 64px; font-size: 28px; }
      .logo-text { font-size: 24px; }
    }
  </style>
</head>
<body>
  ${body}
</body>
</html>`;
}

const PAGES = {
  login() {
    return pageTemplate(
      "Login - Org_Lemah Mail",
      `
      <div class="container">
        <div class="logo-section">
          <div class="logo">OL</div>
          <div class="logo-text">Org_Lemah</div>
          <div class="logo-subtitle">Mail Portal System</div>
        </div>

        <div class="card">
          <h1 class="card-title">Selamat Datang</h1>
          <p class="card-subtitle">Masuk ke akun email portal Anda</p>

          <form onsubmit="login(event)">
            <div class="form-group">
              <label for="id">Username atau Email</label>
              <input id="id" type="text" placeholder="contoh: raja7 atau raja7@gmail.com" autocomplete="username" required />
            </div>

            <div class="form-group">
              <label for="pw">Password</label>
              <input id="pw" type="password" placeholder="••••••••" autocomplete="current-password" required />
            </div>

            <button type="submit" id="loginBtn">Masuk</button>

            <div id="msg"></div>
          </form>

          <div class="links">
            <a href="/signup">Buat Akun Baru</a>
            <span class="separator">•</span>
            <a href="/reset">Lupa Password?</a>
          </div>
        </div>
      </div>

      <script>
        async function login(e) {
          e.preventDefault();
          const id = document.getElementById('id').value.trim();
          const pw = document.getElementById('pw').value;
          const btn = document.getElementById('loginBtn');
          const msg = document.getElementById('msg');

          btn.disabled = true;
          btn.innerHTML = '<span class="spinner"></span>Memproses...';
          msg.innerHTML = '';

          try {
            const r = await fetch('/api/auth/login', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ id, pw })
            });

            const contentType = r.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
              throw new Error('Server error (non-JSON response)');
            }

            const j = await r.json();

            if (j.ok) {
              msg.innerHTML = '<div class="alert alert-success">✅ Login berhasil! Mengalihkan...</div>';
              setTimeout(() => location.href = '/app', 1000);
            } else {
              msg.innerHTML = '<div class="alert alert-error">❌ ' + (j.error || 'Login gagal') + '</div>';
              btn.disabled = false;
              btn.innerHTML = 'Masuk';
            }
          } catch (err) {
            console.error('Login error:', err);
            msg.innerHTML = '<div class="alert alert-error">❌ Terjadi kesalahan: ' + err.message + '</div>';
            btn.disabled = false;
            btn.innerHTML = 'Masuk';
          }
        }
      </script>
      `
    );
  },

  signup(domain) {
    return pageTemplate(
      "Daftar - Org_Lemah Mail",
      `
      <div class="container">
        <div class="logo-section">
          <div class="logo">OL</div>
          <div class="logo-text">Org_Lemah</div>
          <div class="logo-subtitle">Mail Portal System</div>
        </div>

        <div class="card">
          <h1 class="card-title">Buat Akun Baru</h1>
          <p class="card-subtitle">Dapatkan email alias gratis @${domain}</p>

          <form onsubmit="signup(event)">
            <div class="form-group">
              <label for="u">Username</label>
              <input id="u" type="text" placeholder="contoh: raja7" pattern="[a-z0-9_]{3,24}" title="3-24 karakter, hanya huruf kecil, angka, dan underscore" autocomplete="username" required />
            </div>

            <div class="form-group">
              <label for="e">Email (untuk reset password)</label>
              <input id="e" type="email" placeholder="contoh: raja7@gmail.com" autocomplete="email" required />
            </div>

            <div class="form-group">
              <label for="pw">Password</label>
              <input id="pw" type="password" placeholder="Minimal 8 karakter" minlength="8" autocomplete="new-password" required />
            </div>

            <button type="submit" id="signupBtn">Buat Akun</button>

            <div id="msg"></div>
          </form>

          <div class="links">
            <a href="/login">Sudah punya akun? Masuk di sini</a>
          </div>
        </div>
      </div>

      <script>
        async function signup(e) {
          e.preventDefault();
          const username = document.getElementById('u').value.trim().toLowerCase();
          const email = document.getElementById('e').value.trim().toLowerCase();
          const pw = document.getElementById('pw').value;
          const btn = document.getElementById('signupBtn');
          const msg = document.getElementById('msg');

          if (!/^[a-z0-9_]{3,24}$/.test(username)) {
            msg.innerHTML = '<div class="alert alert-error">❌ Username harus 3-24 karakter (a-z, 0-9, _)</div>';
            return;
          }

          if (pw.length < 8) {
            msg.innerHTML = '<div class="alert alert-error">❌ Password minimal 8 karakter</div>';
            return;
          }

          btn.disabled = true;
          btn.innerHTML = '<span class="spinner"></span>Membuat akun...';
          msg.innerHTML = '';

          try {
            const r = await fetch('/api/auth/signup', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ username, email, pw })
            });

            const contentType = r.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
              const text = await r.text();
              console.error('Non-JSON response:', text.substring(0, 200));
              throw new Error('Server error (non-JSON response). Status: ' + r.status);
            }

            const j = await r.json();

            if (j.ok) {
              msg.innerHTML = '<div class="alert alert-success">✅ Akun berhasil dibuat! Mengalihkan...</div>';
              setTimeout(() => location.href = '/app', 1500);
            } else {
              msg.innerHTML = '<div class="alert alert-error">❌ ' + (j.error || 'Pendaftaran gagal') + '</div>';
              btn.disabled = false;
              btn.innerHTML = 'Buat Akun';
            }
          } catch (err) {
            console.error('Signup error:', err);
            msg.innerHTML = '<div class="alert alert-error">❌ Terjadi kesalahan: ' + err.message + '</div>';
            btn.disabled = false;
            btn.innerHTML = 'Buat Akun';
          }
        }
      </script>
      `
    );
  },

  reset() {
    return pageTemplate(
      "Reset Password - Org_Lemah Mail",
      `
      <div class="container">
        <div class="logo-section">
          <div class="logo">OL</div>
          <div class="logo-text">Org_Lemah</div>
          <div class="logo-subtitle">Mail Portal System</div>
        </div>

        <div class="card">
          <h1 class="card-title">Reset Password</h1>
          <p class="card-subtitle">Kami akan mengirim link reset ke email Anda</p>

          <form onsubmit="reqReset(event)">
            <div class="form-group">
              <label for="e">Email Akun</label>
              <input id="e" type="email" placeholder="email@example.com" required />
            </div>

            <button type="submit" id="resetBtn">Kirim Link Reset</button>

            <div id="msg"></div>
          </form>

          <div class="links">
            <a href="/login">Kembali ke Login</a>
          </div>
        </div>

        <div class="card">
          <h2 class="card-title">Punya Token?</h2>
          <p class="card-subtitle">Masukkan token dari email untuk reset password</p>

          <form onsubmit="confirmReset(event)">
            <div class="form-group">
              <label for="t">Token Reset</label>
              <input id="t" type="text" placeholder="Token dari email" required />
            </div>

            <div class="form-group">
              <label for="npw">Password Baru</label>
              <input id="npw" type="password" placeholder="Minimal 8 karakter" minlength="8" required />
            </div>

            <button type="submit" id="confirmBtn">Set Password Baru</button>

            <div id="msg2"></div>
          </form>
        </div>
      </div>

      <script>
        async function reqReset(e) {
          e.preventDefault();
          const email = document.getElementById('e').value.trim();
          const btn = document.getElementById('resetBtn');
          const msg = document.getElementById('msg');

          btn.disabled = true;
          btn.innerHTML = '<span class="spinner"></span>Mengirim...';
          msg.innerHTML = '';

          try {
            const r = await fetch('/api/auth/reset/request', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ email })
            });

            const j = await r.json();

            if (j.ok) {
              msg.innerHTML = '<div class="alert alert-info">ℹ️ Jika email terdaftar, link/token reset telah dikirim.</div>';
            } else {
              msg.innerHTML = '<div class="alert alert-error">❌ ' + (j.error || 'Gagal') + '</div>';
            }
          } catch (err) {
            msg.innerHTML = '<div class="alert alert-error">❌ ' + err.message + '</div>';
          }

          btn.disabled = false;
          btn.innerHTML = 'Kirim Link Reset';
        }

        async function confirmReset(e) {
          e.preventDefault();
          const token = document.getElementById('t').value.trim();
          const newPw = document.getElementById('npw').value;
          const btn = document.getElementById('confirmBtn');
          const msg = document.getElementById('msg2');

          btn.disabled = true;
          btn.innerHTML = '<span class="spinner"></span>Memproses...';
          msg.innerHTML = '';

          try {
            const r = await fetch('/api/auth/reset/confirm', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ token, newPw })
            });

            const j = await r.json();

            if (j.ok) {
              msg.innerHTML = '<div class="alert alert-success">✅ Password berhasil diubah! Silakan login.</div>';
              setTimeout(() => location.href = '/login', 2000);
            } else {
              msg.innerHTML = '<div class="alert alert-error">❌ ' + (j.error || 'Gagal') + '</div>';
              btn.disabled = false;
              btn.innerHTML = 'Set Password Baru';
            }
          } catch (err) {
            msg.innerHTML = '<div class="alert alert-error">❌ ' + err.message + '</div>';
            btn.disabled = false;
            btn.innerHTML = 'Set Password Baru';
          }
        }
      </script>
      `
    );
  },

  app(domain) {
    return pageTemplate(
      "Inbox - Org_Lemah Mail",
      `
      <div style="max-width:980px;margin:0 auto;padding:24px;color:#e6edf3">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;background:#101826;padding:20px;border-radius:14px">
          <div>
            <div style="font-size:24px;font-weight:700;color:#7dd3fc">Org_Lemah Mail</div>
            <div style="color:#93a4b8">Inbox</div>
          </div>
          <div style="display:flex;gap:10px">
            <a href="/admin" id="adminLink" style="display:none;color:#7dd3fc;text-decoration:none;padding:8px 16px;background:#132033;border-radius:10px">Admin</a>
            <button onclick="logout()" style="padding:8px 16px;background:#5b2230;color:white;border:none;border-radius:10px;cursor:pointer">Logout</button>
          </div>
        </div>

        <div style="background:#101826;padding:20px;border-radius:14px;margin-bottom:16px">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
            <div>
              <div style="color:#93a4b8;margin-bottom:8px">Akun</div>
              <div id="me" style="color:#e6edf3">...</div>
            </div>
            <div>
              <div style="color:#93a4b8;margin-bottom:8px">Buat alias baru (@${domain})</div>
              <div style="display:flex;gap:10px">
                <input id="alias" placeholder="contoh: myname" style="flex:1;padding:10px;border-radius:10px;border:1px solid #243244;background:#0b1220;color:#e6edf3" />
                <button onclick="createAlias()" style="padding:10px 16px;background:#132033;color:#e6edf3;border:1px solid #243244;border-radius:10px;cursor:pointer">Create</button>
              </div>
              <div id="aliasMsg" style="color:#93a4b8;margin-top:8px"></div>
            </div>
          </div>
        </div>

        <div style="background:#101826;padding:20px;border-radius:14px">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
            <div>
              <div style="display:flex;justify-content:space-between;margin-bottom:12px">
                <b style="color:#e6edf3">Aliases</b>
                <span style="color:#93a4b8" id="limitInfo"></span>
              </div>
              <div id="aliases"></div>
            </div>
            <div>
              <b style="color:#e6edf3">Emails</b>
              <div style="color:#93a4b8;margin:8px 0" id="selAlias">Pilih alias…</div>
              <div id="emails"></div>
            </div>
          </div>
        </div>

        <div id="emailView" style="display:none;background:#101826;padding:20px;border-radius:14px;margin-top:16px;color:#e6edf3"></div>
      </div>

      <script>
        let ME=null;
        let SELECTED=null;

        function esc(s){return (s||'').replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m]));}

        async function api(path, opts){
          const r = await fetch(path, opts);
          const contentType = r.headers.get('content-type');
          if(!contentType || !contentType.includes('application/json')){
            throw new Error('Server error');
          }
          return await r.json();
        }

        async function loadMe(){
          try {
            const j = await api('/api/me');
            if(!j.ok){ location.href='/login'; return; }
            ME=j.user;
            document.getElementById('me').innerHTML =
              '<div style="font-weight:600">'+esc(ME.username)+'</div>'+
              '<div style="color:#93a4b8;font-size:14px">'+esc(ME.email)+'</div>';
            document.getElementById('limitInfo').textContent = 'limit: '+ME.alias_limit;
            if(ME.role==='admin') document.getElementById('adminLink').style.display='inline';
          } catch(e) {
            console.error(e);
            location.href='/login';
          }
        }

        async function loadAliases(){
          try {
            const j = await api('/api/aliases');
            if(!j.ok){ alert(j.error||'gagal'); return; }
            const box = document.getElementById('aliases');
            box.innerHTML='';
            if(j.aliases.length===0){
              box.innerHTML='<div style="color:#93a4b8">Belum ada alias.</div>';
              return;
            }
            for(const a of j.aliases){
              const div=document.createElement('div');
              div.style.cssText='display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #243244';
              const addr = a.local_part+'@${domain}';
              div.innerHTML =
                '<div><button onclick="selectAlias(\\''+esc(a.local_part)+'\\')" style="padding:6px 12px;background:#132033;color:#e6edf3;border:none;border-radius:8px;cursor:pointer;margin-right:8px">Open</button>'+
                '<span style="color:#e6edf3">'+esc(addr)+'</span></div>'+
                '<button onclick="delAlias(\\''+esc(a.local_part)+'\\')" style="padding:6px 12px;background:#5b2230;color:#e6edf3;border:none;border-radius:8px;cursor:pointer">Delete</button>';
              box.appendChild(div);
            }
          } catch(e) {
            console.error(e);
          }
        }

        async function selectAlias(local){
          SELECTED=local;
          document.getElementById('selAlias').textContent = 'Alias: '+local+'@${domain}';
          await loadEmails();
        }

        async function loadEmails(){
          if(!SELECTED) return;
          try {
            const j = await api('/api/emails?alias='+encodeURIComponent(SELECTED));
            if(!j.ok){ alert(j.error||'gagal'); return; }
            const box=document.getElementById('emails');
            box.innerHTML='';
            if(j.emails.length===0){
              box.innerHTML='<div style="color:#93a4b8">Belum ada email masuk.</div>';
              return;
            }
            for(const m of j.emails){
              const d=document.createElement('div');
              d.style.cssText='padding:10px 0;border-bottom:1px solid #243244';
              d.innerHTML =
                '<div style="font-weight:600;color:#e6edf3">'+esc(m.subject||'(no subject)')+'</div>'+
                '<div style="color:#93a4b8;font-size:13px">From: '+esc(m.from_addr)+'</div>'+
                '<div style="color:#93a4b8;font-size:12px">'+esc(m.date||'')+'</div>'+
                '<div style="margin-top:6px"><button onclick="openEmail(\\''+esc(m.id)+'\\')" style="padding:6px 12px;background:#132033;color:#e6edf3;border:none;border-radius:8px;cursor:pointer;margin-right:8px">View</button>'+
                '<button onclick="delEmail(\\''+esc(m.id)+'\\')" style="padding:6px 12px;background:#5b2230;color:#e6edf3;border:none;border-radius:8px;cursor:pointer">Delete</button></div>';
              box.appendChild(d);
            }
          } catch(e) {
            console.error(e);
          }
        }

        async function openEmail(id){
          try {
            const j = await api('/api/emails/'+encodeURIComponent(id));
            if(!j.ok){ alert(j.error||'gagal'); return; }
            const v=document.getElementById('emailView');
            v.style.display='block';
            v.innerHTML =
              '<div style="font-size:20px;font-weight:600;margin-bottom:8px">'+esc(j.email.subject||'(no subject)')+'</div>'+
              '<div style="color:#93a4b8;font-size:14px">From: '+esc(j.email.from_addr)+'</div>'+
              '<div style="color:#93a4b8;font-size:14px">To: '+esc(j.email.to_addr)+'</div>'+
              '<div style="color:#93a4b8;font-size:14px;margin-bottom:16px">'+esc(j.email.date||'')+'</div>'+
              '<hr style="border:0;border-top:1px solid #243244;margin:16px 0" />'+
              (j.email.html ? ('<div style="background:#0b1220;padding:16px;border-radius:10px">'+j.email.html+'</div>') : ('<pre style="white-space:pre-wrap;background:#0b1220;padding:16px;border-radius:10px">'+esc(j.email.text||'')+'</pre>'));
            v.scrollIntoView({behavior:'smooth'});
          } catch(e) {
            console.error(e);
          }
        }

        async function createAlias(){
          const local = document.getElementById('alias').value.trim().toLowerCase();
          const msg=document.getElementById('aliasMsg');
          msg.textContent='...';
          try {
            const j = await api('/api/aliases', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({local})});
            msg.textContent = j.ok ? '✅ Alias dibuat.' : '❌ '+(j.error||'gagal');
            if(j.ok){ document.getElementById('alias').value=''; await loadMe(); await loadAliases(); }
          } catch(e) {
            msg.textContent = '❌ '+e.message;
          }
        }

        async function delAlias(local){
          if(!confirm('Hapus alias '+local+'@${domain} ?')) return;
          try {
            const j = await api('/api/aliases/'+encodeURIComponent(local), {method:'DELETE'});
            if(!j.ok){ alert(j.error||'gagal'); return; }
            if(SELECTED===local){ SELECTED=null; document.getElementById('selAlias').textContent='Pilih alias…'; document.getElementById('emails').innerHTML=''; }
            await loadMe(); await loadAliases();
          } catch(e) {
            alert(e.message);
          }
        }

        async function delEmail(id){
          if(!confirm('Hapus email ini?')) return;
          try {
            const j = await api('/api/emails/'+encodeURIComponent(id), {method:'DELETE'});
            if(!j.ok){ alert(j.error||'gagal'); return; }
            document.getElementById('emailView').style.display='none';
            await loadEmails();
          } catch(e) {
            alert(e.message);
          }
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
      "Admin - Org_Lemah Mail",
      `
      <div style="max-width:980px;margin:0 auto;padding:24px;color:#e6edf3">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;background:#101826;padding:20px;border-radius:14px">
          <div>
            <div style="font-size:24px;font-weight:700;color:#7dd3fc">Admin Dashboard</div>
            <div style="color:#93a4b8">Org_Lemah Mail</div>
          </div>
          <div style="display:flex;gap:10px">
            <a href="/app" style="color:#7dd3fc;text-decoration:none;padding:8px 16px;background:#132033;border-radius:10px">Inbox</a>
            <button onclick="logout()" style="padding:8px 16px;background:#5b2230;color:white;border:none;border-radius:10px;cursor:pointer">Logout</button>
          </div>
        </div>

        <div style="background:#101826;padding:20px;border-radius:14px">
          <div style="font-size:18px;font-weight:600;margin-bottom:8px">Users</div>
          <div style="color:#93a4b8;margin-bottom:16px">Domain: @${domain}</div>
          <div id="users"></div>
        </div>
      </div>

      <script>
        function esc(s){return (s||'').replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m]));}

        async function api(path, opts){
          const r = await fetch(path, opts);
          const contentType = r.headers.get('content-type');
          if(!contentType || !contentType.includes('application/json')){
            throw new Error('Server error');
          }
          return await r.json();
        }

        async function loadUsers(){
          try {
            const j = await api('/api/admin/users');
            if(!j.ok){ alert(j.error||'gagal'); if(j.error==='Forbidden') location.href='/app'; return; }
            const box=document.getElementById('users');
            box.innerHTML='';
            for(const u of j.users){
              const div=document.createElement('div');
              div.style.cssText='padding:16px 0;border-bottom:1px solid #243244';
              div.innerHTML =
                '<div style="display:flex;justify-content:space-between;gap:10px;margin-bottom:8px">'+
                '<div>'+
                '<span style="font-weight:600;color:#e6edf3">'+esc(u.username)+'</span> '+
                '<span style="color:#93a4b8">('+esc(u.email)+')</span> '+
                (u.role==='admin' ? '<span style="background:#132033;padding:2px 8px;border-radius:12px;font-size:12px;color:#7dd3fc">admin</span>' : '')+
                (u.disabled?'<span style="background:#5b2230;padding:2px 8px;border-radius:12px;font-size:12px;color:#e6edf3">disabled</span>':'')+
                '</div>'+
                '<div style="display:flex;gap:8px">'+
                '<input id="lim_'+esc(u.id)+'" value="'+u.alias_limit+'" style="width:80px;padding:6px;border-radius:8px;border:1px solid #243244;background:#0b1220;color:#e6edf3" />'+
                '<button onclick="setLimit(\\''+esc(u.id)+'\\')" style="padding:6px 12px;background:#132033;color:#e6edf3;border:none;border-radius:8px;cursor:pointer">Set</button>'+
                '<button onclick="toggleUser(\\''+esc(u.id)+'\\','+(u.disabled?0:1)+')" style="padding:6px 12px;background:#5b2230;color:#e6edf3;border:none;border-radius:8px;cursor:pointer">'+(u.disabled?'Enable':'Disable')+'</button>'+
                '</div>'+
                '</div>'+
                '<div style="color:#93a4b8;font-size:13px">created: '+esc(u.created_at)+'</div>';
              box.appendChild(div);
            }
          } catch(e) {
            alert(e.message);
          }
        }

        async function setLimit(id){
          try {
            const v = document.getElementById('lim_'+id).value;
            const lim = parseInt(v,10);
            const j = await api('/api/admin/users/'+encodeURIComponent(id), {method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({alias_limit:lim})});
            if(!j.ok){ alert(j.error||'gagal'); return; }
            await loadUsers();
          } catch(e) {
            alert(e.message);
          }
        }

        async function toggleUser(id, disabled){
          try {
            const j = await api('/api/admin/users/'+encodeURIComponent(id), {method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({disabled})});
            if(!j.ok){ alert(j.error||'gagal'); return; }
            await loadUsers();
          } catch(e) {
            alert(e.message);
          }
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
  if (!env.RESEND_API_KEY) return;

  const base = env.APP_BASE_URL || "";
  const link = base ? `${base}/reset#token=${encodeURIComponent(token)}` : "";
  const subject = "Reset password - Org_Lemah Mail";
  const bodyHtml = `
    <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:20px">
      <div style="background:linear-gradient(135deg, #667eea 0%, #764ba2 100%);padding:30px;text-align:center;border-radius:10px 10px 0 0">
        <div style="background:white;width:60px;height:60px;margin:0 auto 12px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:700;color:#667eea">OL</div>
        <h1 style="color:white;margin:0">Org_Lemah Mail</h1>
      </div>
      <div style="background:#f7fafc;padding:30px;border-radius:0 0 10px 10px">
        <h2 style="color:#2d3748">Reset Password</h2>
        <p style="color:#4a5568">Anda menerima email ini karena ada permintaan reset password untuk akun Anda.</p>
        <div style="background:white;padding:15px;border-radius:8px;margin:20px 0;border:2px dashed #cbd5e0">
          <p style="color:#718096;margin:0 0 8px;font-size:14px">Token Reset:</p>
          <p style="font-family:monospace;font-size:16px;color:#2d3748;margin:0;word-break:break-all">${token}</p>
        </div>
        ${link ? `<p style="text-align:center"><a href="${link}" style="display:inline-block;background:linear-gradient(135deg, #667eea 0%, #764ba2 100%);color:white;padding:12px 24px;text-decoration:none;border-radius:8px;font-weight:600">Reset Password</a></p>` : ""}
        <p style="color:#718096;font-size:14px;margin-top:20px">Jika bukan Anda yang meminta reset password, abaikan email ini.</p>
      </div>
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

        const id = String(body.id || "").trim().toLowerCase();
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
