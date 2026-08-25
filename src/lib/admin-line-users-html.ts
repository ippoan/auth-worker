/**
 * LINE ユーザー管理ページ HTML。
 *
 * - 招待: LINE Login の招待リンク (/oauth/line/redirect?redirect_uri=...&tenant_id=<現テナント>)
 *   を生成し、コピー可能リンク + QR (ブラウザ内生成、URL を外部に送らない) で表示。
 * - 一覧: line_user_id を持つ recipient を一覧 + 削除 (/api/line-users/*)。
 *
 * 認証は SSO 設定ページと同方針: 共通門番 __adminAuth (cookie → sessionStorage) で JS が読み、
 * 無ければ /admin/line-users にリダイレクト (= ログインへ)。
 */

import { renderAdminAuthScript } from "./admin-auth-script";

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function renderAdminLineUsersPage(
  redirectOrigins: string[],
  authOrigin: string,
  backUrl: string,
): string {
  const originsJson = JSON.stringify(redirectOrigins);
  const authOriginJson = JSON.stringify(authOrigin);
  const backHref = escapeHtml(backUrl);

  return `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LINE ユーザー管理</title>
<script src="https://cdn.jsdelivr.net/gh/davidshimjs/qrcodejs@04f46c6a0708418cb7b96fc563eacae0fbf77674/qrcode.min.js" integrity="sha384-3zSEDfvllQohrq0PHL1fOXJuC/jSOO34H46t6UQfobFOmxE5BpjjaIJY5F2/bMnU" crossorigin="anonymous"></script>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; background: #f5f6f8; color: #1a1a2e; }
  .wrap { max-width: 760px; margin: 0 auto; padding: 20px 16px 60px; }
  .nav { margin-bottom: 12px; }
  .nav a { color: #4f46e5; text-decoration: none; font-size: 14px; }
  h1 { font-size: 22px; margin: 8px 0 4px; }
  .muted { color: #6b7280; font-size: 13px; }
  .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 18px; margin-top: 16px; }
  .card h2 { font-size: 16px; margin: 0 0 12px; }
  label { display: block; font-size: 13px; color: #374151; margin: 10px 0 4px; }
  select, input { width: 100%; padding: 8px 10px; border: 1px solid #d1d5db; border-radius: 8px; font-size: 14px; }
  .invite-url { display: flex; gap: 8px; align-items: center; margin-top: 10px; }
  .invite-url code { flex: 1; background: #f3f4f6; padding: 8px 10px; border-radius: 8px; font-size: 12px; word-break: break-all; }
  .btn { border: none; border-radius: 8px; padding: 8px 14px; font-size: 14px; cursor: pointer; }
  .btn-copy { background: #4f46e5; color: #fff; white-space: nowrap; }
  .btn-red { background: #ef4444; color: #fff; }
  .btn-gray { background: #e5e7eb; color: #374151; }
  #qr { margin: 14px auto 0; width: 180px; height: 180px; display: flex; align-items: center; justify-content: center; }
  table { width: 100%; border-collapse: collapse; margin-top: 6px; }
  th, td { text-align: left; padding: 8px 6px; border-bottom: 1px solid #eee; font-size: 13px; }
  th { color: #6b7280; font-weight: 600; }
  .badge { font-size: 12px; padding: 2px 8px; border-radius: 999px; }
  .badge-on { background: #dcfce7; color: #166534; }
  .badge-off { background: #f3f4f6; color: #6b7280; }
  #msg { margin-top: 10px; font-size: 13px; }
  #msg.error { color: #b91c1c; }
  #msg.success { color: #166534; }
</style>
</head>
<body>
<div class="wrap">
  <div class="nav"><a href="${backHref}">&larr; 戻る</a></div>
  <h1>LINE ユーザー管理</h1>
  <p class="muted" id="user-info"></p>

  <div class="card">
    <h2>LINE 招待</h2>
    <p class="muted">この招待リンク／QR を LINE ユーザーに渡してください。スキャン → LINE ログインで、このテナントの受信者として登録されログインできるようになります。</p>
    <label for="redirect-select">ログイン後の遷移先 (redirect_uri)</label>
    <select id="redirect-select" onchange="rebuildInvite()"></select>
    <div class="invite-url">
      <code id="invite-url"></code>
      <button class="btn btn-copy" onclick="copyInvite(this)">コピー</button>
    </div>
    <div id="qr"></div>
  </div>

  <div class="card">
    <h2>LINE ユーザー一覧</h2>
    <p class="muted">このテナントに紐づく LINE Login 受信者です。</p>
    <table>
      <thead><tr><th>名前</th><th>LINE User ID</th><th>状態</th><th></th></tr></thead>
      <tbody id="list-body"><tr><td colspan="4" class="muted">読み込み中...</td></tr></tbody>
    </table>
    <div id="msg"></div>
  </div>
</div>

${renderAdminAuthScript()}
<script>
  var token = null;
  var tenantId = '';
  var AUTH_ORIGIN = ${authOriginJson};
  var redirectOrigins = ${originsJson};

  function escapeHtmlJs(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // JWT payload は base64url + UTF-8。atob だけだと日本語名が文字化けするので
  // base64url → base64 変換 + percent-decode で UTF-8 を正しく復元する。
  function decodeJwtPayload(tok) {
    var b64 = tok.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    var bin = atob(b64);
    var json = decodeURIComponent(bin.split('').map(function (c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(json);
  }

  function initAuth() {
    // #474: cookie (logi_auth_token) → sessionStorage の順で解決する共通門番。
    token = window.__adminAuth.requireToken(window.location.href);
    if (!token) return false;
    try {
      var payload = decodeJwtPayload(token);
      tenantId = payload.tenant_id || payload.org || '';
      var el = document.getElementById('user-info');
      if (el) el.textContent = (payload.name || payload.email || '') + (payload.org_slug ? ' (' + payload.org_slug + ')' : '');
    } catch (e) {}
    return true;
  }

  async function api(path, body) {
    var res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: body ? JSON.stringify(body) : '{}',
    });
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok || data.error) {
      var msg = data.error || 'API error';
      if (msg.indexOf('permission_denied') >= 0 || msg.indexOf('Admin role') >= 0) { window.location.replace('/top'); return; }
      throw new Error(msg);
    }
    return data;
  }

  function inviteUrl() {
    var sel = document.getElementById('redirect-select');
    var redirect = sel && sel.value ? sel.value : (AUTH_ORIGIN + '/top');
    return AUTH_ORIGIN + '/oauth/line/redirect?redirect_uri=' + encodeURIComponent(redirect) +
      '&tenant_id=' + encodeURIComponent(tenantId);
  }

  var qrInstance = null;
  function rebuildInvite() {
    var url = inviteUrl();
    document.getElementById('invite-url').textContent = url;
    var qrEl = document.getElementById('qr');
    qrEl.innerHTML = '';
    if (window.QRCode) {
      qrInstance = new window.QRCode(qrEl, { text: url, width: 180, height: 180, correctLevel: window.QRCode.CorrectLevel.M });
    } else {
      qrEl.innerHTML = '<span class="muted">QR を読み込めませんでした (リンクをコピーして共有してください)</span>';
    }
  }

  function copyInvite(btn) {
    navigator.clipboard.writeText(inviteUrl()).then(function () {
      var orig = btn.textContent; btn.textContent = 'コピー済'; setTimeout(function () { btn.textContent = orig; }, 1500);
    });
  }

  function showMsg(text, type) {
    var el = document.getElementById('msg'); el.className = type || ''; el.textContent = text;
    if (type === 'success') setTimeout(function () { el.className = ''; el.textContent = ''; }, 3000);
  }

  async function loadList() {
    var body = document.getElementById('list-body');
    try {
      var data = await api('/api/line-users/list');
      var rows = (data && data.recipients) || [];
      if (rows.length === 0) {
        body.innerHTML = '<tr><td colspan="4" class="muted">LINE ユーザーがいません（上の招待リンクから登録してください）</td></tr>';
        return;
      }
      body.innerHTML = rows.map(function (r) {
        var badge = r.enabled ? '<span class="badge badge-on">有効</span>' : '<span class="badge badge-off">無効</span>';
        return '<tr>' +
          '<td>' + escapeHtmlJs(r.name) + '</td>' +
          '<td><code style="font-size:11px">' + escapeHtmlJs(r.lineUserId) + '</code></td>' +
          '<td>' + badge + '</td>' +
          '<td><button class="btn btn-red" data-id="' + escapeHtmlJs(r.id) + '" onclick="del(this)">削除</button></td>' +
          '</tr>';
      }).join('');
    } catch (e) {
      body.innerHTML = '<tr><td colspan="4" class="error">' + escapeHtmlJs(e.message) + '</td></tr>';
    }
  }

  async function del(btn) {
    if (!confirm('この LINE ユーザーを削除しますか？')) return;
    try {
      await api('/api/line-users/delete', { id: btn.getAttribute('data-id') });
      showMsg('削除しました', 'success');
      loadList();
    } catch (e) { showMsg(e.message, 'error'); }
  }

  (function () {
    if (!initAuth()) return;
    var sel = document.getElementById('redirect-select');
    sel.innerHTML = redirectOrigins.map(function (o) {
      // 遷移先は各アプリの /auth/callback (auth-client の AuthCallback ルート規約)。
      // 旧 /top はアプリ側に存在せず 404 になっていた (auth-worker 自身のみ /top を持つ)。
      // consumer app は pages/auth/callback.vue で AuthCallback を描画し #token を消費する。
      var v = o + '/auth/callback';
      return '<option value="' + escapeHtmlJs(v) + '">' + escapeHtmlJs(v) + '</option>';
    }).join('');
    rebuildInvite();
    loadList();
  })();
</script>
</body>
</html>`;
}
