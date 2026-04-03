/**
 * Login page HTML template
 */

interface LoginPageParams {
  redirectUri: string;
  orgId?: string;
  error?: string;
  googleEnabled: boolean;
  googleRedirectUrl: string;
  lineworksRedirectUrl: string;
}

export function renderLoginPage(params: LoginPageParams): string {
  const { redirectUri, orgId, error, googleEnabled, googleRedirectUrl, lineworksRedirectUrl } =
    params;

  const errorHtml = error
    ? `<div class="error">${escapeHtml(error)}</div>`
    : "";

  const googleButtonHtml = googleEnabled
    ? `<a href="${escapeHtml(googleRedirectUrl)}" class="google-btn">
         <svg width="18" height="18" viewBox="0 0 18 18"><path fill="#4285F4" d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844a4.14 4.14 0 0 1-1.796 2.716v2.259h2.908c1.702-1.567 2.684-3.875 2.684-6.615Z"/><path fill="#34A853" d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18Z"/><path fill="#FBBC05" d="M3.964 10.71A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.997 8.997 0 0 0 0 9c0 1.452.348 2.827.957 4.042l3.007-2.332Z"/><path fill="#EA4335" d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58Z"/></svg>
         Sign in with Google
       </a>
       <div class="divider"><span>or</span></div>`
    : "";

  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - Logi</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f5f5f5;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 1rem;
    }
    .container {
      background: white;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      padding: 2rem;
      width: 100%;
      max-width: 400px;
    }
    h1 {
      font-size: 1.5rem;
      margin-bottom: 1.5rem;
      text-align: center;
      color: #333;
    }
    .error {
      background: #fef2f2;
      border: 1px solid #fecaca;
      color: #dc2626;
      padding: 0.75rem;
      border-radius: 6px;
      margin-bottom: 1rem;
      font-size: 0.875rem;
    }
    label {
      display: block;
      font-size: 0.875rem;
      font-weight: 500;
      color: #555;
      margin-bottom: 0.25rem;
    }
    input {
      width: 100%;
      padding: 0.625rem 0.75rem;
      border: 1px solid #ddd;
      border-radius: 6px;
      font-size: 1rem;
      margin-bottom: 1rem;
      outline: none;
      transition: border-color 0.2s;
    }
    input:focus { border-color: #3b82f6; }
    button {
      width: 100%;
      padding: 0.75rem;
      background: #3b82f6;
      color: white;
      border: none;
      border-radius: 6px;
      font-size: 1rem;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.2s;
    }
    button:hover { background: #2563eb; }
    .divider {
      display: flex;
      align-items: center;
      margin: 1.25rem 0;
      color: #999;
      font-size: 0.875rem;
    }
    .divider::before, .divider::after {
      content: '';
      flex: 1;
      border-top: 1px solid #e5e5e5;
    }
    .divider span { padding: 0 0.75rem; }
    .google-btn {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      width: 100%;
      padding: 0.75rem;
      background: white;
      border: 1px solid #ddd;
      border-radius: 6px;
      font-size: 1rem;
      color: #333;
      text-decoration: none;
      cursor: pointer;
      transition: background 0.2s;
    }
    .google-btn:hover { background: #f9fafb; }
    .lw-form { display: flex; gap: 0.5rem; }
    .lw-form input { margin-bottom: 0; flex: 1; }
    .lw-form button {
      width: auto;
      padding: 0.625rem 1rem;
      background: #00b900;
      white-space: nowrap;
      font-size: 0.875rem;
    }
    .lw-form button:hover { background: #009a00; }
    .pw-section { display: none; margin-top: 1rem; }
    .pw-toggle {
      display: block;
      margin: 1.25rem auto 0;
      padding: 0.5rem 1rem;
      background: none;
      border: 1px solid #ddd;
      border-radius: 6px;
      color: #888;
      font-size: 0.8rem;
      cursor: pointer;
      width: auto;
    }
    .pw-toggle:hover { background: #f9fafb; color: #555; }
    .clear-btn {
      display: block;
      margin: 1.25rem auto 0;
      padding: 0.5rem 1rem;
      background: none;
      border: 1px solid #ddd;
      border-radius: 6px;
      color: #999;
      font-size: 0.75rem;
      cursor: pointer;
      width: auto;
    }
    .clear-btn:hover { background: #f9fafb; color: #666; }
    .clear-msg {
      text-align: center;
      font-size: 0.75rem;
      color: #16a34a;
      margin-top: 0.5rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Logi Login</h1>
    ${errorHtml}
    ${googleButtonHtml}
    <label for="lw_address">LINE WORKS</label>
    <form class="lw-form" action="${escapeHtml(lineworksRedirectUrl)}" method="GET">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}">
      <input type="text" id="lw_address" name="address" placeholder="user@domain" autocomplete="on" autofocus>
      <button type="submit">Login</button>
    </form>
    <button class="pw-toggle" onclick="togglePwLogin()">パスワードログイン</button>
    <div id="pw-section" class="pw-section">
      <form method="POST" action="/auth/login">
        <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}">
        <label for="organization_id">Organization ID</label>
        <input type="text" id="organization_id" name="organization_id"
               value="${escapeHtml(orgId || "00000000-0000-0000-0000-000000000001")}" required>
        <label for="username">Username</label>
        <input type="text" id="username" name="username" autocomplete="username" required>
        <label for="password">Password</label>
        <input type="password" id="password" name="password" autocomplete="current-password" required>
        <button type="submit">Login</button>
      </form>
    </div>
    <button class="clear-btn" onclick="clearAllCookies()">Cookie をクリア</button>
    <div id="clear-msg" class="clear-msg" style="display:none">クリアしました。ページをリロードします...</div>
    <script>
    function togglePwLogin() {
      var s = document.getElementById('pw-section');
      s.style.display = s.style.display === 'none' ? 'block' : 'none';
    }
    function clearAllCookies() {
      var names = ['lw_domain', 'logi_auth_token', 'logi_auth'];
      var parts = location.hostname.split('.');
      var parent = parts.length > 2 ? '.' + parts.slice(-2).join('.') : location.hostname;
      names.forEach(function(n) {
        document.cookie = n + '=; path=/; max-age=0; secure; samesite=lax';
        document.cookie = n + '=; Domain=' + parent + '; path=/; max-age=0; secure; samesite=lax';
      });
      try { localStorage.removeItem('logi_auth'); localStorage.removeItem('logi_lw_domain'); } catch(e) {}
      document.getElementById('clear-msg').style.display = 'block';
      setTimeout(function() { location.reload(); }, 500);
    }
    </script>
  </div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
