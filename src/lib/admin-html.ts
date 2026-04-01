/**
 * SSO Settings admin page HTML template
 * Single-page app with inline JS for JWT auth + API calls
 */

export function renderAdminSsoPage(frontendOrigins: string[] = []): string {
  const originsJson = JSON.stringify(frontendOrigins);
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SSO Settings - Logi Admin</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f5f5f5;
      padding: 1rem;
    }
    .page-wrapper {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 1rem;
      max-width: 1300px;
      margin: 1rem auto;
    }
    .container {
      background: white;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      padding: 2rem;
      max-width: 600px;
      width: 100%;
    }
    @media (min-width: 1200px) {
      .page-wrapper {
        flex-direction: row;
        align-items: flex-start;
      }
      .container {
        flex: 1;
        max-width: none;
      }
    }
    h1 { font-size: 1.5rem; margin-bottom: 1.5rem; color: #333; display: flex; align-items: center; gap: 0.75rem; }
    .back-link {
      display: inline-flex; align-items: center; gap: 0.375rem; font-size: 1rem; color: #3b82f6;
      text-decoration: none; margin-bottom: 1rem; font-weight: 500;
      padding: 0.5rem 0.75rem; border: 1px solid #3b82f6; border-radius: 6px;
    }
    .back-link:hover { background: #3b82f6; color: white; }
    h2 { font-size: 1.1rem; margin-bottom: 1rem; color: #555; }
    .error {
      background: #fef2f2; border: 1px solid #fecaca; color: #dc2626;
      padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.875rem;
    }
    .success {
      background: #f0fdf4; border: 1px solid #bbf7d0; color: #16a34a;
      padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.875rem;
    }
    .config-item {
      border: 1px solid #e5e7eb; border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem;
      display: flex; justify-content: space-between; align-items: center;
    }
    .config-info { flex: 1; }
    .config-info .provider { font-weight: 600; font-size: 1rem; }
    .config-info .detail { font-size: 0.875rem; color: #6b7280; margin-top: 0.25rem; }
    .badge {
      display: inline-block; padding: 0.125rem 0.5rem; border-radius: 9999px;
      font-size: 0.75rem; font-weight: 500;
    }
    .badge-green { background: #dcfce7; color: #166534; }
    .badge-gray { background: #f3f4f6; color: #6b7280; }
    .config-actions { display: flex; gap: 0.5rem; }
    .btn {
      padding: 0.5rem 1rem; border: none; border-radius: 6px; font-size: 0.875rem;
      font-weight: 500; cursor: pointer; transition: background 0.2s;
    }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-primary { background: #3b82f6; color: white; }
    .btn-primary:hover:not(:disabled) { background: #2563eb; }
    .btn-gray { background: #f3f4f6; color: #374151; }
    .btn-gray:hover:not(:disabled) { background: #e5e7eb; }
    .btn-red { background: #fef2f2; color: #dc2626; }
    .btn-red:hover:not(:disabled) { background: #fecaca; }
    .btn-sm { padding: 0.375rem 0.75rem; font-size: 0.8rem; }
    label { display: block; font-size: 0.875rem; font-weight: 500; color: #555; margin-bottom: 0.25rem; }
    input, select, textarea {
      width: 100%; padding: 0.625rem 0.75rem; border: 1px solid #ddd;
      border-radius: 6px; font-size: 1rem; margin-bottom: 1rem; outline: none;
    }
    input:focus, select:focus, textarea:focus { border-color: #3b82f6; }
    textarea { font-family: monospace; font-size: 0.8rem; resize: vertical; min-height: 80px; }
    .toggle-row { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; }
    .toggle {
      position: relative; width: 44px; height: 24px; background: #d1d5db;
      border-radius: 12px; cursor: pointer; transition: background 0.2s;
    }
    .toggle.active { background: #22c55e; }
    .toggle::after {
      content: ''; position: absolute; top: 2px; left: 2px; width: 20px; height: 20px;
      background: white; border-radius: 50%; transition: transform 0.2s;
    }
    .toggle.active::after { transform: translateX(20px); }
    .divider { border-top: 1px solid #e5e7eb; margin: 1.5rem 0; }
    .form-actions { display: flex; justify-content: flex-end; gap: 0.5rem; }
    .empty { color: #9ca3af; font-size: 0.875rem; padding: 1rem 0; }
    .hint { font-size: 0.75rem; color: #16a34a; margin-top: -0.75rem; margin-bottom: 1rem; }
    .loading { text-align: center; padding: 2rem; color: #9ca3af; }
    .modal-overlay {
      position: fixed; inset: 0; background: rgba(0,0,0,0.5);
      display: flex; align-items: center; justify-content: center; z-index: 50;
    }
    .modal {
      background: white; border-radius: 8px; padding: 1.5rem;
      max-width: 400px; width: 90%;
    }
    .modal h3 { margin-bottom: 1rem; }
    .modal-actions { display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1.5rem; }
    .hidden { display: none; }
    .desc { font-size: 0.8rem; color: #6b7280; margin-bottom: 1.5rem; line-height: 1.5; }
    .field-desc { font-size: 0.75rem; color: #9ca3af; margin-top: -0.75rem; margin-bottom: 0.75rem; }
    .url-list { margin-top: 0.5rem; }
    .url-row {
      display: flex; align-items: center; gap: 0.5rem; margin-top: 0.25rem;
      background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 4px; padding: 0.375rem 0.5rem;
    }
    .url-row code { flex: 1; font-size: 0.75rem; color: #374151; word-break: break-all; }
    .btn-copy {
      padding: 0.25rem 0.5rem; border: 1px solid #d1d5db; border-radius: 4px;
      background: white; font-size: 0.7rem; cursor: pointer; white-space: nowrap;
    }
    .btn-copy:hover { background: #f3f4f6; }
  </style>
</head>
<body>
  <div class="page-wrapper">
  <div class="container">
    <a href="${frontendOrigins[0] || 'javascript:history.back()'}" class="back-link">\u2190 \u623b\u308b</a>
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <h1>SSO \u30d7\u30ed\u30d0\u30a4\u30c0\u8a2d\u5b9a</h1>
      <button class="btn btn-gray btn-sm" onclick="logout()">\u30ed\u30b0\u30a2\u30a6\u30c8</button>
    </div>
    <div id="user-info" style="font-size:0.8rem;color:#6b7280;margin-bottom:1rem;"></div>
    <p class="desc">
      \u5916\u90e8 SSO \u30d7\u30ed\u30d0\u30a4\u30c0\uff08LINE WORKS \u7b49\uff09\u3092\u767b\u9332\u3059\u308b\u3068\u3001\u30ed\u30b0\u30a4\u30f3\u753b\u9762\u304b\u3089\u30d7\u30ed\u30d0\u30a4\u30c0\u7d4c\u7531\u3067\u8a8d\u8a3c\u3067\u304d\u307e\u3059\u3002<br>
      \u4e8b\u524d\u306b\u30d7\u30ed\u30d0\u30a4\u30c0\u306e Developer Console \u3067 OAuth \u30a2\u30d7\u30ea\u3092\u4f5c\u6210\u3057\u3001Redirect URI \u3092\u8a2d\u5b9a\u3057\u3066\u304f\u3060\u3055\u3044\u3002
    </p>
    <div class="url-list" style="margin-bottom:1rem;">
      <div style="font-size:0.75rem;color:#6b7280;margin-bottom:0.25rem;">Redirect URI\uff08Developer Console \u306b\u8a2d\u5b9a\uff09:</div>
      <div class="url-row"><code>https://auth.mtamaramu.com/oauth/lineworks/callback</code><button class="btn-copy" onclick="copyUrl(this, 'https://auth.mtamaramu.com/oauth/lineworks/callback')">\u30b3\u30d4\u30fc</button></div>
    </div>
    <div id="join-url-section" class="url-list hidden" style="margin-bottom:1rem;">
      <div style="font-size:0.75rem;color:#6b7280;margin-bottom:0.25rem;">\u53c2\u52a0\u30ea\u30af\u30a8\u30b9\u30c8URL:</div>
      <div id="join-url-row" class="url-row"></div>
    </div>

    <div id="msg"></div>

    <!-- Config list -->
    <div id="config-list">
      <div class="loading">\u8aad\u307f\u8fbc\u307f\u4e2d...</div>
    </div>

    <div class="divider"></div>

    <!-- Add/Edit form -->
    <h2 id="form-title">\u65b0\u898f\u30d7\u30ed\u30d0\u30a4\u30c0\u8ffd\u52a0</h2>
    <form id="sso-form" onsubmit="return false;">
      <label for="provider">\u30d7\u30ed\u30d0\u30a4\u30c0</label>
      <select id="provider">
        <option value="">\u9078\u629e...</option>
        <option value="lineworks">LINE WORKS</option>
      </select>

      <label for="clientId">Client ID</label>
      <div class="field-desc">Developer Console \u3067\u767a\u884c\u3055\u308c\u305f OAuth Client ID</div>
      <input type="text" id="clientId" placeholder="Client ID">

      <label for="clientSecret">Client Secret</label>
      <div class="field-desc">Developer Console \u3067\u767a\u884c\u3055\u308c\u305f OAuth Client Secret\uff08\u6697\u53f7\u5316\u3057\u3066\u4fdd\u5b58\u3055\u308c\u307e\u3059\uff09</div>
      <input type="password" id="clientSecret" placeholder="Client Secret">
      <div id="secret-hint" class="hint hidden">\u8a2d\u5b9a\u6e08\u307f \u2014 \u7a7a\u6b04\u306e\u307e\u307e\u306a\u3089\u5909\u66f4\u3057\u307e\u305b\u3093</div>

      <label for="externalOrgId">\u5916\u90e8\u7d44\u7e54ID</label>
      <div class="field-desc">LINE WORKS \u306e\u5834\u5408\u306f\u30c9\u30e1\u30a4\u30f3\u540d\uff08\u30ed\u30b0\u30a4\u30f3\u6642\u306b user@<strong>\u3053\u306e\u5024</strong> \u3067\u7167\u5408\uff09</div>
      <input type="text" id="externalOrgId" placeholder="\u4f8b: ohishiunyusouko">

      <label for="woffId">WOFF ID\uff08\u4efb\u610f\uff09</label>
      <div class="field-desc">
        LINE WORKS Developer Console \u2192 WOFF \u30a2\u30d7\u30ea \u3067\u767b\u9332\u3002
        \u8a2d\u5b9a\u3059\u308b\u3068\u30a2\u30d7\u30ea\u5185\u3067 OAuth \u540c\u610f\u753b\u9762\u306a\u3057\u306b\u30ed\u30b0\u30a4\u30f3\u3067\u304d\u307e\u3059\u3002
      </div>
      <input type="text" id="woffId" placeholder="WOFF App \u767b\u9332\u5f8c\u306b\u767a\u884c\u3055\u308c\u308b ID">
      <div id="woff-endpoint-hint" class="field-desc hidden" style="margin-top:-0.5rem;">
        WOFF \u30a2\u30d7\u30ea\u306e\u30a8\u30f3\u30c9\u30dd\u30a4\u30f3\u30c8URL\u306b\u4ee5\u4e0b\u3092\u8a2d\u5b9a:
        <div id="woff-endpoint-urls" class="url-list" style="margin-top:0.25rem;"></div>
      </div>

      <div class="toggle-row">
        <label>\u6709\u52b9</label>
        <div id="enabled-toggle" class="toggle active" onclick="toggleEnabled()"></div>
      </div>

      <div class="form-actions">
        <button id="cancel-btn" class="btn btn-gray hidden" onclick="resetForm()">\u30ad\u30e3\u30f3\u30bb\u30eb</button>
        <button id="save-btn" class="btn btn-primary" onclick="handleSave()" disabled>\u8ffd\u52a0</button>
      </div>
    </form>
  </div>

  <!-- Bot Config section -->
  <div class="container">
    <h1>Bot \u8a2d\u5b9a</h1>
    <p class="desc">
      LINE WORKS Bot \u306e\u8a8d\u8a3c\u60c5\u5831\u3092\u7ba1\u7406\u3057\u307e\u3059\u3002Developer Console \u3067 Bot \u3092\u4f5c\u6210\u3057\u3001<br>
      Client ID / Secret\u3001Service Account\u3001Private Key\u3001Bot ID \u3092\u767b\u9332\u3057\u3066\u304f\u3060\u3055\u3044\u3002
    </p>

    <div id="bot-msg"></div>

    <div id="bot-config-list">
      <div class="loading">\u8aad\u307f\u8fbc\u307f\u4e2d...</div>
    </div>

    <div class="divider"></div>

    <h2 id="bot-form-title">\u65b0\u898f Bot \u8ffd\u52a0</h2>
    <form id="bot-form" onsubmit="return false;">
      <input type="hidden" id="bot-edit-id" value="">

      <label for="bot-name">\u540d\u524d</label>
      <div class="field-desc">\u7ba1\u7406\u7528\u306e\u8b58\u5225\u540d\uff08\u4f8b: \u304a\u3072\u3057 Bot\uff09</div>
      <input type="text" id="bot-name" placeholder="Bot \u540d">

      <label for="bot-clientId">Client ID</label>
      <input type="text" id="bot-clientId" placeholder="Developer Console \u306e Client ID">

      <label for="bot-clientSecret">Client Secret</label>
      <input type="password" id="bot-clientSecret" placeholder="Client Secret">
      <div id="bot-secret-hint" class="hint hidden">\u8a2d\u5b9a\u6e08\u307f \u2014 \u7a7a\u6b04\u306e\u307e\u307e\u306a\u3089\u5909\u66f4\u3057\u307e\u305b\u3093</div>

      <label for="bot-serviceAccount">Service Account</label>
      <div class="field-desc">Developer Console \u3067\u767a\u884c\u3055\u308c\u305f Service Account ID</div>
      <input type="text" id="bot-serviceAccount" placeholder="xxxxx.serviceaccount@xxx">

      <label for="bot-privateKey">Private Key (PEM)</label>
      <div class="field-desc">Developer Console \u3067\u30c0\u30a6\u30f3\u30ed\u30fc\u30c9\u3057\u305f\u79d8\u5bc6\u9375\uff08\u6697\u53f7\u5316\u3057\u3066\u4fdd\u5b58\uff09</div>
      <textarea id="bot-privateKey" rows="4" placeholder="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"></textarea>
      <div id="bot-pk-hint" class="hint hidden">\u8a2d\u5b9a\u6e08\u307f \u2014 \u7a7a\u6b04\u306e\u307e\u307e\u306a\u3089\u5909\u66f4\u3057\u307e\u305b\u3093</div>

      <label for="bot-botId">Bot ID</label>
      <div class="field-desc">LINE WORKS Bot \u306e\u56fa\u6709 ID</div>
      <input type="text" id="bot-botId" placeholder="Bot ID">

      <div class="toggle-row">
        <label>\u6709\u52b9</label>
        <div id="bot-enabled-toggle" class="toggle active" onclick="toggleBotEnabled()"></div>
      </div>

      <div class="form-actions">
        <button id="bot-cancel-btn" class="btn btn-gray hidden" onclick="resetBotForm()">\u30ad\u30e3\u30f3\u30bb\u30eb</button>
        <button id="bot-save-btn" class="btn btn-primary" onclick="handleBotSave()" disabled>\u8ffd\u52a0</button>
      </div>
    </form>
  </div>
  </div>

  <!-- Bot delete confirmation modal -->
  <div id="bot-delete-modal" class="modal-overlay hidden">
    <div class="modal">
      <h3>Bot \u524a\u9664\u78ba\u8a8d</h3>
      <p>Bot\u300c<span id="bot-delete-target"></span>\u300d\u306e\u8a2d\u5b9a\u3092\u524a\u9664\u3057\u307e\u3059\u304b\uff1f</p>
      <div class="modal-actions">
        <button class="btn btn-gray" onclick="closeBotDeleteModal()">\u30ad\u30e3\u30f3\u30bb\u30eb</button>
        <button class="btn btn-red" onclick="handleBotDelete()">\u524a\u9664</button>
      </div>
    </div>
  </div>

  <!-- Delete confirmation modal -->
  <div id="delete-modal" class="modal-overlay hidden">
    <div class="modal">
      <h3>\u524a\u9664\u78ba\u8a8d</h3>
      <p>\u30d7\u30ed\u30d0\u30a4\u30c0\u300c<span id="delete-target"></span>\u300d\u306e\u8a2d\u5b9a\u3092\u524a\u9664\u3057\u307e\u3059\u304b\uff1f</p>
      <div class="modal-actions">
        <button class="btn btn-gray" onclick="closeDeleteModal()">\u30ad\u30e3\u30f3\u30bb\u30eb</button>
        <button class="btn btn-red" onclick="handleDelete()">\u524a\u9664</button>
      </div>
    </div>
  </div>

  <script>
    let token = null;
    let editing = false;
    let enabled = true;
    let deleteProvider = '';
    const frontendOrigins = ${originsJson};

    // Auth: read JWT from cookie (set by /admin/sso/callback)
    function initAuth() {
      const adminMatch = document.cookie.match(/sso_admin_token=([^;]+)/);
      const sharedMatch = document.cookie.match(/logi_auth_token=([^;]+)/);
      token = (adminMatch && adminMatch[1]) || (sharedMatch && sharedMatch[1]) || null;
      if (!token) {
        window.location.replace('/admin/sso');
        return;
      }
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        const providerLabels = { google: 'Google', lineworks: 'LINE WORKS', password: 'Password' };
        const provider = payload.provider || '';
        const username = payload.username || '';
        const label = providerLabels[provider] || provider || '';
        const el = document.getElementById('user-info');
        if (el && (username || label)) {
          el.textContent = username + (label ? ' (via ' + label + ')' : '');
        }
        // Show join URL from org_slug in JWT
        if (payload.org_slug) {
          var joinUrl = window.location.origin + '/join/' + encodeURIComponent(payload.org_slug);
          var section = document.getElementById('join-url-section');
          var row = document.getElementById('join-url-row');
          if (section && row) {
            row.innerHTML = '<code>' + escapeHtml(joinUrl) + '</code><button class="btn-copy" onclick="copyUrl(this, \\'' + escapeAttr(joinUrl) + '\\')">\u30b3\u30d4\u30fc</button>';
            section.classList.remove('hidden');
          }
        }
      } catch (e) {}
    }

    function logout() {
      window.location.replace('/logout');
    }

    async function api(path, body) {
      const res = await fetch(path, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token,
        },
        body: body ? JSON.stringify(body) : '{}',
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        const msg = data.error || 'API error';
        if (msg.includes('permission_denied') || msg.includes('Admin role required')) {
          window.location.replace('/top');
          return;
        }
        throw new Error(msg);
      }
      return data;
    }

    function showMsg(text, type) {
      const el = document.getElementById('msg');
      el.className = type;
      el.textContent = text;
      if (type === 'success') {
        setTimeout(() => { el.className = ''; el.textContent = ''; }, 3000);
      }
    }

    function clearMsg() {
      const el = document.getElementById('msg');
      el.className = '';
      el.textContent = '';
    }

    async function loadConfigs() {
      try {
        const data = await api('/api/sso/list');
        renderConfigs(data.configs || []);
      } catch (e) {
        document.getElementById('config-list').innerHTML =
          '<div class="error">' + escapeHtml(e.message) + '</div>';
      }
    }

    function updateJoinUrl(configs) {
      var section = document.getElementById('join-url-section');
      // Skip if already shown by initAuth (from JWT org_slug)
      if (section && !section.classList.contains('hidden')) return;
      var row = document.getElementById('join-url-row');
      var orgId = '';
      for (var i = 0; i < configs.length; i++) {
        if (configs[i].externalOrgId) { orgId = configs[i].externalOrgId; break; }
      }
      if (orgId) {
        var joinUrl = window.location.origin + '/join/' + encodeURIComponent(orgId);
        row.innerHTML = '<code>' + escapeHtml(joinUrl) + '</code><button class="btn-copy" onclick="copyUrl(this, \\'' + escapeAttr(joinUrl) + '\\')">\u30b3\u30d4\u30fc</button>';
        section.classList.remove('hidden');
      } else {
        section.classList.add('hidden');
      }
    }

    function renderConfigs(configs) {
      const el = document.getElementById('config-list');
      updateJoinUrl(configs);
      if (configs.length === 0) {
        el.innerHTML = '<div class="empty">SSO \u30d7\u30ed\u30d0\u30a4\u30c0\u304c\u672a\u8a2d\u5b9a\u3067\u3059</div>';
        return;
      }
      el.innerHTML = configs.map(c => {
        const oauthUrls = c.externalOrgId && c.enabled ? frontendOrigins.map(origin =>
          \`<div class="url-row"><code>\${escapeHtml(origin)}/?lw=\${escapeHtml(c.externalOrgId)}</code><button class="btn-copy" onclick="copyUrl(this, '\${escapeAttr(origin)}/?lw=\${escapeAttr(c.externalOrgId)}')">\u30b3\u30d4\u30fc</button></div>\`
        ).join('') : '';
        const topOrigin = window.location.origin;
        const woffUrls = c.woffId && c.externalOrgId && c.enabled ?
          \`<div class="url-row"><code>\${escapeHtml(topOrigin)}/top?lw=\${escapeHtml(c.externalOrgId)}&woff</code><button class="btn-copy" onclick="copyUrl(this, '\${escapeAttr(topOrigin)}/top?lw=\${escapeAttr(c.externalOrgId)}&woff')">\u30b3\u30d4\u30fc</button></div>\`
          : '';
        return \`
        <div class="config-item" style="flex-direction:column;align-items:stretch;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div class="config-info">
              <div class="provider">\${escapeHtml(c.provider)}</div>
              <div class="detail">\${escapeHtml(c.externalOrgId)} \u30fb Client ID: \${escapeHtml(c.clientId)}\${c.woffId ? ' \u30fb WOFF: ' + escapeHtml(c.woffId) : ''}</div>
            </div>
            <span class="badge \${c.enabled ? 'badge-green' : 'badge-gray'}">\${c.enabled ? '\u6709\u52b9' : '\u7121\u52b9'}</span>
            <div class="config-actions">
              <button class="btn btn-gray btn-sm" onclick="editConfig(\${escapeAttr(JSON.stringify(c))})">\u7de8\u96c6</button>
              <button class="btn btn-red btn-sm" onclick="confirmDelete('\${escapeAttr(c.provider)}')">\u524a\u9664</button>
            </div>
          </div>
          \${oauthUrls ? '<div class="url-list"><div style="font-size:0.75rem;color:#6b7280;margin-bottom:0.25rem;">OAuth \u30ed\u30b0\u30a4\u30f3URL:</div>' + oauthUrls + '</div>' : ''}
          \${woffUrls ? '<div class="url-list"><div style="font-size:0.75rem;color:#6b7280;margin-bottom:0.25rem;">WOFF \u30ed\u30b0\u30a4\u30f3URL\uff08\u30a2\u30d7\u30ea\u5185\u30fb\u540c\u610f\u753b\u9762\u306a\u3057\uff09:</div>' + woffUrls + '</div>' : ''}
        </div>
      \`}).join('');
    }

    function editConfig(config) {
      editing = true;
      document.getElementById('form-title').textContent = '\u30d7\u30ed\u30d0\u30a4\u30c0\u7de8\u96c6';
      document.getElementById('provider').value = config.provider;
      document.getElementById('provider').disabled = true;
      document.getElementById('clientId').value = config.clientId;
      document.getElementById('clientSecret').value = '';
      document.getElementById('clientSecret').placeholder =
        config.hasClientSecret ? '\u8a2d\u5b9a\u6e08\u307f\uff08\u5909\u66f4\u3059\u308b\u5834\u5408\u306e\u307f\u5165\u529b\uff09' : 'Client Secret';
      document.getElementById('secret-hint').classList.toggle('hidden', !config.hasClientSecret);
      document.getElementById('externalOrgId').value = config.externalOrgId;
      document.getElementById('woffId').value = config.woffId || '';
      enabled = config.enabled;
      updateToggle();
      document.getElementById('cancel-btn').classList.remove('hidden');
      document.getElementById('save-btn').textContent = '\u66f4\u65b0';
      validateForm();
      updateWoffEndpointHint();
    }

    function resetForm() {
      editing = false;
      document.getElementById('form-title').textContent = '\u65b0\u898f\u30d7\u30ed\u30d0\u30a4\u30c0\u8ffd\u52a0';
      document.getElementById('provider').value = '';
      document.getElementById('provider').disabled = false;
      document.getElementById('clientId').value = '';
      document.getElementById('clientSecret').value = '';
      document.getElementById('clientSecret').placeholder = 'Client Secret';
      document.getElementById('secret-hint').classList.add('hidden');
      document.getElementById('externalOrgId').value = '';
      document.getElementById('woffId').value = '';
      enabled = true;
      updateToggle();
      document.getElementById('cancel-btn').classList.add('hidden');
      document.getElementById('save-btn').textContent = '\u8ffd\u52a0';
      validateForm();
      updateWoffEndpointHint();
      clearMsg();
    }

    function toggleEnabled() {
      enabled = !enabled;
      updateToggle();
    }

    function updateToggle() {
      document.getElementById('enabled-toggle').classList.toggle('active', enabled);
    }

    function validateForm() {
      const provider = document.getElementById('provider').value;
      const clientId = document.getElementById('clientId').value;
      const clientSecret = document.getElementById('clientSecret').value;
      const externalOrgId = document.getElementById('externalOrgId').value;
      const valid = provider && clientId && externalOrgId && (editing || clientSecret);
      document.getElementById('save-btn').disabled = !valid;
    }

    async function handleSave() {
      const btn = document.getElementById('save-btn');
      btn.disabled = true;
      btn.textContent = '\u4fdd\u5b58\u4e2d...';
      clearMsg();

      try {
        await api('/api/sso/upsert', {
          provider: document.getElementById('provider').value,
          clientId: document.getElementById('clientId').value,
          clientSecret: document.getElementById('clientSecret').value,
          externalOrgId: document.getElementById('externalOrgId').value,
          woffId: document.getElementById('woffId').value,
          enabled: enabled,
        });
        showMsg('\u4fdd\u5b58\u3057\u307e\u3057\u305f', 'success');
        resetForm();
        await loadConfigs();
      } catch (e) {
        showMsg(e.message, 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = editing ? '\u66f4\u65b0' : '\u8ffd\u52a0';
      }
    }

    function confirmDelete(provider) {
      deleteProvider = provider;
      document.getElementById('delete-target').textContent = provider;
      document.getElementById('delete-modal').classList.remove('hidden');
    }

    function closeDeleteModal() {
      document.getElementById('delete-modal').classList.add('hidden');
      deleteProvider = '';
    }

    async function handleDelete() {
      clearMsg();
      try {
        await api('/api/sso/delete', { provider: deleteProvider });
        showMsg('\u524a\u9664\u3057\u307e\u3057\u305f', 'success');
        closeDeleteModal();
        await loadConfigs();
      } catch (e) {
        showMsg(e.message, 'error');
        closeDeleteModal();
      }
    }

    async function copyUrl(btn, url) {
      try {
        await navigator.clipboard.writeText(url);
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = orig; }, 2000);
      } catch (e) {
        showMsg('\u30b3\u30d4\u30fc\u5931\u6557: ' + e.message, 'error');
      }
    }

    function escapeHtml(s) {
      return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
    function escapeAttr(s) {
      return String(s).replace(/'/g,"\\\\'").replace(/"/g,'&quot;');
    }

    function updateWoffEndpointHint() {
      const orgId = document.getElementById('externalOrgId').value.trim();
      const woffId = document.getElementById('woffId').value.trim();
      const hint = document.getElementById('woff-endpoint-hint');
      const urlsEl = document.getElementById('woff-endpoint-urls');
      if (woffId && orgId) {
        const url = window.location.origin + '/top?lw=' + encodeURIComponent(orgId) + '&woff';
        urlsEl.innerHTML = '<div class="url-row"><code>' + escapeHtml(url) + '</code><button class="btn-copy" onclick="copyUrl(this, \\'' + escapeAttr(url) + '\\')">\u30b3\u30d4\u30fc</button></div>';
        hint.classList.remove('hidden');
      } else {
        hint.classList.add('hidden');
      }
    }

    // ========== Bot Config ==========
    let botEditing = false;
    let botEnabled = true;
    let botDeleteId = '';

    async function loadBotConfigs() {
      try {
        const data = await api('/api/bot-config/list');
        renderBotConfigs(data.configs || []);
      } catch (e) {
        document.getElementById('bot-config-list').innerHTML =
          '<div class="error">' + escapeHtml(e.message) + '</div>';
      }
    }

    function renderBotConfigs(configs) {
      const el = document.getElementById('bot-config-list');
      if (configs.length === 0) {
        el.innerHTML = '<div class="empty">Bot \u304c\u672a\u8a2d\u5b9a\u3067\u3059</div>';
        return;
      }
      el.innerHTML = configs.map(c => \`
        <div class="config-item" style="flex-direction:column;align-items:stretch;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div class="config-info">
              <div class="provider">\${escapeHtml(c.name)}</div>
              <div class="detail">Bot ID: \${escapeHtml(c.botId)} \u30fb \${escapeHtml(c.provider)}</div>
            </div>
            <span class="badge \${c.enabled ? 'badge-green' : 'badge-gray'}">\${c.enabled ? '\u6709\u52b9' : '\u7121\u52b9'}</span>
            <div class="config-actions">
              \${c.enabled ? '<a href="/admin/rich-menu?bot=' + encodeURIComponent(c.id) + '" class="btn btn-primary btn-sm">Rich Menu</a>' : ''}
              <button class="btn btn-gray btn-sm" onclick="editBotConfig(\${escapeAttr(JSON.stringify(c))})">\u7de8\u96c6</button>
              <button class="btn btn-red btn-sm" onclick="confirmBotDelete('\${escapeAttr(c.id)}', '\${escapeAttr(c.name)}')">\u524a\u9664</button>
            </div>
          </div>
        </div>
      \`).join('');
    }

    function editBotConfig(config) {
      botEditing = true;
      document.getElementById('bot-form-title').textContent = 'Bot \u7de8\u96c6';
      document.getElementById('bot-edit-id').value = config.id;
      document.getElementById('bot-name').value = config.name;
      document.getElementById('bot-clientId').value = config.clientId;
      document.getElementById('bot-clientSecret').value = '';
      document.getElementById('bot-clientSecret').placeholder =
        config.hasClientSecret ? '\u8a2d\u5b9a\u6e08\u307f\uff08\u5909\u66f4\u3059\u308b\u5834\u5408\u306e\u307f\u5165\u529b\uff09' : 'Client Secret';
      document.getElementById('bot-secret-hint').classList.toggle('hidden', !config.hasClientSecret);
      document.getElementById('bot-serviceAccount').value = config.serviceAccount;
      document.getElementById('bot-privateKey').value = '';
      document.getElementById('bot-privateKey').placeholder =
        config.hasPrivateKey ? '\u8a2d\u5b9a\u6e08\u307f\uff08\u5909\u66f4\u3059\u308b\u5834\u5408\u306e\u307f\u5165\u529b\uff09' : '-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----';
      document.getElementById('bot-pk-hint').classList.toggle('hidden', !config.hasPrivateKey);
      document.getElementById('bot-botId').value = config.botId;
      botEnabled = config.enabled;
      updateBotToggle();
      document.getElementById('bot-cancel-btn').classList.remove('hidden');
      document.getElementById('bot-save-btn').textContent = '\u66f4\u65b0';
      validateBotForm();
    }

    function resetBotForm() {
      botEditing = false;
      document.getElementById('bot-form-title').textContent = '\u65b0\u898f Bot \u8ffd\u52a0';
      document.getElementById('bot-edit-id').value = '';
      document.getElementById('bot-name').value = '';
      document.getElementById('bot-clientId').value = '';
      document.getElementById('bot-clientSecret').value = '';
      document.getElementById('bot-clientSecret').placeholder = 'Client Secret';
      document.getElementById('bot-secret-hint').classList.add('hidden');
      document.getElementById('bot-serviceAccount').value = '';
      document.getElementById('bot-privateKey').value = '';
      document.getElementById('bot-privateKey').placeholder = '-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----';
      document.getElementById('bot-pk-hint').classList.add('hidden');
      document.getElementById('bot-botId').value = '';
      botEnabled = true;
      updateBotToggle();
      document.getElementById('bot-cancel-btn').classList.add('hidden');
      document.getElementById('bot-save-btn').textContent = '\u8ffd\u52a0';
      validateBotForm();
      clearBotMsg();
    }

    function toggleBotEnabled() {
      botEnabled = !botEnabled;
      updateBotToggle();
    }

    function updateBotToggle() {
      document.getElementById('bot-enabled-toggle').classList.toggle('active', botEnabled);
    }

    function validateBotForm() {
      const name = document.getElementById('bot-name').value;
      const clientId = document.getElementById('bot-clientId').value;
      const clientSecret = document.getElementById('bot-clientSecret').value;
      const serviceAccount = document.getElementById('bot-serviceAccount').value;
      const privateKey = document.getElementById('bot-privateKey').value;
      const botId = document.getElementById('bot-botId').value;
      const valid = name && clientId && serviceAccount && botId &&
        (botEditing || (clientSecret && privateKey));
      document.getElementById('bot-save-btn').disabled = !valid;
    }

    function showBotMsg(text, type) {
      const el = document.getElementById('bot-msg');
      el.className = type;
      el.textContent = text;
      if (type === 'success') {
        setTimeout(() => { el.className = ''; el.textContent = ''; }, 3000);
      }
    }

    function clearBotMsg() {
      const el = document.getElementById('bot-msg');
      el.className = '';
      el.textContent = '';
    }

    async function handleBotSave() {
      const btn = document.getElementById('bot-save-btn');
      btn.disabled = true;
      btn.textContent = '\u4fdd\u5b58\u4e2d...';
      clearBotMsg();

      try {
        await api('/api/bot-config/upsert', {
          id: document.getElementById('bot-edit-id').value || undefined,
          name: document.getElementById('bot-name').value,
          clientId: document.getElementById('bot-clientId').value,
          clientSecret: document.getElementById('bot-clientSecret').value,
          serviceAccount: document.getElementById('bot-serviceAccount').value,
          privateKey: document.getElementById('bot-privateKey').value,
          botId: document.getElementById('bot-botId').value,
          enabled: botEnabled,
        });
        showBotMsg('\u4fdd\u5b58\u3057\u307e\u3057\u305f', 'success');
        resetBotForm();
        await loadBotConfigs();
      } catch (e) {
        showBotMsg(e.message, 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = botEditing ? '\u66f4\u65b0' : '\u8ffd\u52a0';
      }
    }

    function confirmBotDelete(id, name) {
      botDeleteId = id;
      document.getElementById('bot-delete-target').textContent = name;
      document.getElementById('bot-delete-modal').classList.remove('hidden');
    }

    function closeBotDeleteModal() {
      document.getElementById('bot-delete-modal').classList.add('hidden');
      botDeleteId = '';
    }

    async function handleBotDelete() {
      clearBotMsg();
      try {
        await api('/api/bot-config/delete', { id: botDeleteId });
        showBotMsg('\u524a\u9664\u3057\u307e\u3057\u305f', 'success');
        closeBotDeleteModal();
        await loadBotConfigs();
      } catch (e) {
        showBotMsg(e.message, 'error');
        closeBotDeleteModal();
      }
    }

    // Init: SSO form
    document.getElementById('provider').addEventListener('change', validateForm);
    document.getElementById('clientId').addEventListener('input', validateForm);
    document.getElementById('clientSecret').addEventListener('input', validateForm);
    document.getElementById('externalOrgId').addEventListener('input', () => { validateForm(); updateWoffEndpointHint(); });
    document.getElementById('woffId').addEventListener('input', updateWoffEndpointHint);

    // Init: Bot form
    document.getElementById('bot-name').addEventListener('input', validateBotForm);
    document.getElementById('bot-clientId').addEventListener('input', validateBotForm);
    document.getElementById('bot-clientSecret').addEventListener('input', validateBotForm);
    document.getElementById('bot-serviceAccount').addEventListener('input', validateBotForm);
    document.getElementById('bot-privateKey').addEventListener('input', validateBotForm);
    document.getElementById('bot-botId').addEventListener('input', validateBotForm);

    initAuth();
    loadConfigs();
    loadBotConfigs();
  </script>
</body>
</html>`;
}
