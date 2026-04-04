/**
 * Top page HTML template
 * WOFF SDK auth + app navigation menu
 * LINE WORKS アプリ内ブラウザ向けモバイルファースト UI
 */

export interface AppEntry {
  name: string;
  url: string;
  icon: string;
  description: string;
}

export function renderTopPage(apps: AppEntry[], authWorkerOrigin: string): string {
  const appsJson = JSON.stringify(apps);
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Logi</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Hiragino Sans', sans-serif;
      background: #f0f2f5;
      min-height: 100dvh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .container {
      width: 100%;
      max-width: 400px;
    }
    .header {
      text-align: center;
      margin-bottom: 2rem;
    }
    .header h1 {
      font-size: 1.5rem;
      color: #1a1a1a;
      font-weight: 700;
    }
    .header p {
      font-size: 0.875rem;
      color: #6b7280;
      margin-top: 0.25rem;
    }

    /* Loading state */
    #loading {
      text-align: center;
      padding: 3rem 1rem;
    }
    #loading .spinner {
      width: 32px; height: 32px;
      border: 3px solid #e5e7eb;
      border-top: 3px solid #3b82f6;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 1rem;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    #loading .text {
      font-size: 0.875rem;
      color: #6b7280;
    }

    /* App grid */
    #menu { display: none; }
    #menu.visible { display: block; }
    .app-grid {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }
    .app-card {
      display: flex;
      align-items: center;
      gap: 1rem;
      background: white;
      border: 1px solid #e5e7eb;
      border-radius: 12px;
      padding: 1.25rem;
      text-decoration: none;
      color: inherit;
      transition: box-shadow 0.15s, transform 0.15s;
      -webkit-tap-highlight-color: transparent;
    }
    .app-card:active {
      transform: scale(0.98);
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .app-icon {
      width: 48px; height: 48px;
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.25rem;
      font-weight: 700;
      flex-shrink: 0;
    }
    .app-icon-carins { background: #dbeafe; color: #2563eb; }
    .app-icon-dtako { background: #fef3c7; color: #d97706; }
    .app-icon-items { background: #f0fdf4; color: #16a34a; }
    .app-icon-default { background: #f3f4f6; color: #6b7280; }
    .app-name {
      font-size: 1rem;
      font-weight: 600;
      color: #1a1a1a;
    }
    .app-desc {
      font-size: 0.75rem;
      color: #9ca3af;
      margin-top: 0.125rem;
    }
    .app-arrow {
      margin-left: auto;
      color: #d1d5db;
      font-size: 1.25rem;
    }

    /* Error */
    .error-box {
      background: #fef2f2;
      border: 1px solid #fecaca;
      color: #dc2626;
      padding: 1rem;
      border-radius: 8px;
      font-size: 0.875rem;
      text-align: center;
      margin-bottom: 1rem;
    }
    .error-box a { color: #dc2626; }

    .hidden { display: none !important; }
    .logout-btn {
      display: block;
      margin: 1.5rem auto 0;
      padding: 0.5rem 1rem;
      background: none;
      border: 1px solid #e5e7eb;
      border-radius: 6px;
      color: #9ca3af;
      font-size: 0.75rem;
      cursor: pointer;
      width: auto;
    }
    .logout-btn:hover { background: #f9fafb; color: #6b7280; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Logi</h1>
      <p id="org-name"></p>
    </div>

    <!-- Loading (shown during WOFF auth) -->
    <div id="loading">
      <div class="spinner"></div>
      <div class="text">認証中...</div>
    </div>

    <!-- Error -->
    <div id="error" class="error-box hidden"></div>

    <!-- App menu (shown after auth) -->
    <div id="menu">
      <div class="app-grid" id="app-grid"></div>
      <button class="logout-btn" onclick="window.location.replace('/logout')">Logout</button>
    </div>
  </div>

  <script>
    const AUTH_WORKER = ${JSON.stringify(authWorkerOrigin)};
    const APPS = ${appsJson};
    const AUTH_COOKIE = 'logi_auth_token';
    const AUTH_STORAGE = 'logi_auth';
    const LW_DOMAIN_KEY = 'logi_lw_domain';
    const LW_DOMAIN_COOKIE = 'lw_domain';

    function getParentDomain() {
      const parts = window.location.hostname.split('.');
      return parts.length > 2 ? '.' + parts.slice(-2).join('.') : window.location.hostname;
    }

    function getCookie(name) {
      const c = document.cookie.split('; ').find(c => c.startsWith(name + '='));
      return c ? c.split('=').slice(1).join('=') : null;
    }

    function setCookie(name, value, maxAge) {
      document.cookie = name + '=' + value + '; Domain=' + getParentDomain() + '; Path=/; Max-Age=' + maxAge + '; Secure; SameSite=Lax';
    }

    function clearCookie(name) {
      document.cookie = name + '=; Domain=' + getParentDomain() + '; Path=/; Max-Age=0; Secure; SameSite=Lax';
    }

    function saveLwDomain(domain) {
      localStorage.setItem(LW_DOMAIN_KEY, domain);
      setCookie(LW_DOMAIN_COOKIE, encodeURIComponent(domain), 30 * 24 * 60 * 60);
    }

    function getLwDomain() {
      return localStorage.getItem(LW_DOMAIN_KEY) || null;
    }

    /** Check if JWT cookie exists and is not expired */
    function getValidToken() {
      const token = getCookie(AUTH_COOKIE);
      if (!token) return null;
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        if (payload.exp > Math.floor(Date.now() / 1000)) {
          return { token, orgId: payload.org, expiresAt: payload.exp };
        }
      } catch {}
      return null;
    }

    function showError(msg) {
      document.getElementById('loading').classList.add('hidden');
      const el = document.getElementById('error');
      el.textContent = msg;
      el.classList.remove('hidden');
    }

    function showMenu() {
      document.getElementById('loading').classList.add('hidden');
      const menu = document.getElementById('menu');
      menu.classList.add('visible');

      const grid = document.getElementById('app-grid');
      grid.innerHTML = APPS.map(app => {
        let iconClass = 'app-icon-default';
        if (app.url.includes('carins')) iconClass = 'app-icon-carins';
        if (app.url.includes('ohishi2')) iconClass = 'app-icon-dtako';
        if (app.url.includes('items')) iconClass = 'app-icon-items';
        return '<a href="' + escapeHtml(app.url) + '" class="app-card">' +
          '<div class="app-icon ' + iconClass + '">' + escapeHtml(app.icon) + '</div>' +
          '<div><div class="app-name">' + escapeHtml(app.name) + '</div>' +
          '<div class="app-desc">' + escapeHtml(app.description) + '</div></div>' +
          '<div class="app-arrow">›</div></a>';
      }).join('');
    }

    function escapeHtml(s) {
      return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    /** WOFF SDK dynamic load */
    function loadWoffSdk() {
      return new Promise(function(resolve, reject) {
        if (typeof woff !== 'undefined') { resolve(); return; }
        var s = document.createElement('script');
        s.src = 'https://static.worksmobile.net/static/wm/woff/edge/3.6/sdk.js';
        s.onload = resolve;
        s.onerror = function() { reject(new Error('WOFF SDK load failed')); };
        document.head.appendChild(s);
      });
    }

    async function init() {
      var params = new URLSearchParams(window.location.search);
      var errorParam = params.get('error');
      if (errorParam === 'no_permission') {
        var el = document.getElementById('error');
        el.textContent = '権限がありません';
        el.classList.remove('hidden');
        history.replaceState(null, '', window.location.pathname);
      }
      var lwParam = params.get('lw');
      var isWoff = params.has('woff');

      // Save lw domain
      if (lwParam) {
        saveLwDomain(lwParam);
      }
      var domain = lwParam || getLwDomain();

      // 1. Already authenticated? Show menu immediately
      var existing = getValidToken();
      if (existing) {
        // Also save to localStorage for consistency
        localStorage.setItem(AUTH_STORAGE, JSON.stringify(existing));
        // Clean URL
        if (lwParam || isWoff) {
          history.replaceState(null, '', window.location.pathname);
        }
        showMenu();
        return;
      }

      // 2. WOFF auth
      if (isWoff && domain) {
        try {
          // Resolve WOFF ID from DB (same origin, no CORS)
          var configRes = await fetch(AUTH_WORKER + '/auth/woff-config?domain=' + encodeURIComponent(domain));
          if (configRes.ok) {
            var configData = await configRes.json();
            await loadWoffSdk();
            await woff.init({ woffId: configData.woffId });
            if (woff.isInClient()) {
              var accessToken = woff.getAccessToken();
              if (accessToken) {
                var authRes = await fetch(AUTH_WORKER + '/auth/woff', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    accessToken: accessToken,
                    domainId: domain,
                    redirectUri: window.location.origin
                  })
                });
                if (authRes.ok) {
                  var data = await authRes.json();
                  var expiresAt = Math.floor(new Date(data.expiresAt).getTime() / 1000);
                  // Set JWT cookie on parent domain
                  setCookie(AUTH_COOKIE, data.token, 86400);
                  // Also store in localStorage (for top page reuse)
                  localStorage.setItem(AUTH_STORAGE, JSON.stringify({
                    token: data.token,
                    orgId: data.orgId,
                    expiresAt: expiresAt
                  }));
                  console.log('WOFF: AUTH SUCCESS');
                  history.replaceState(null, '', window.location.pathname);
                  showMenu();
                  return;
                }
              }
            }
          }
        } catch (e) {
          console.warn('WOFF auth failed, falling back to OAuth', e);
        }
      }

      // 3. OAuth fallback
      if (domain) {
        // Redirect to LINE WORKS OAuth directly
        var redirectUri = window.location.origin + '/top';
        window.location.href = AUTH_WORKER + '/oauth/lineworks/redirect?address=' +
          encodeURIComponent(domain) + '&redirect_uri=' + encodeURIComponent(redirectUri);
        return;
      }

      // 4. No domain → login page
      var redirectUri = window.location.origin + '/top';
      window.location.href = AUTH_WORKER + '/login?redirect_uri=' + encodeURIComponent(redirectUri);
    }

    init();
  </script>
</body>
</html>`;
}
