/**
 * /admin/notify — recipient / group management for notify system.
 *
 * 4 tabs:
 *   1. LINE WORKS から追加 — proxy of GET /notify/lineworks/users, bulk POST /notify/recipients/bulk
 *   2. Recipients — list + edit enabled flag + delete (GET/PUT/DELETE /notify/recipients)
 *   3. Groups — list + CRUD + add/remove members (/notify/groups/*)
 *   4. ログイン状況 — proxy of GET /notify/lineworks/login-activity?days=N
 *      (Refs #540。LINE WORKS のログイン・メッセージ送信・掲示板既読を合成した最終活動日時と
 *      その根拠 (last_login_source) を N 日しきい値で確認する用途。根拠で絞り込める。
 *      リマインド送信等の自動アクションは対象外、一覧確認のみ)
 *
 * Auth: 共通門番 `__adminAuth` (cookie `logi_auth_token` → sessionStorage `auth_token`)。
 * どちらも無ければ /login へ (Refs #474)。
 */

import { renderAdminAuthScript } from "./admin-auth-script";

/**
 * login-activity の `last_login_source` → 根拠列の表示ラベル。キーは rust-alc-api
 * `lineworks_login_activity.rs` の `activity_source` が返すリテラルと一致させること
 * (絞り込み select の option value もここから作る)。表に無い値・欠落は「—」。
 */
export const LOGIN_SOURCE_LABELS = {
  auth: "ログイン",
  message: "メッセージ送信",
  board: "掲示板既読",
} as const;

export function renderAdminNotifyPage(alcApiOrigin: string): string {
  const apiJson = JSON.stringify(alcApiOrigin);
  const sourceOptions = Object.entries(LOGIN_SOURCE_LABELS)
    .map(([value, label]) => `<option value="${value}">${label}</option>`)
    .join("");
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>通知管理 - Admin</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; padding: 1rem; }
    .container { background: #fff; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 1.5rem; max-width: 1000px; margin: 1rem auto; }
    h1 { font-size: 1.4rem; margin-bottom: 1rem; color: #333; }
    h2 { font-size: 1.05rem; margin-bottom: 0.75rem; color: #555; }
    .back-link { display: inline-flex; align-items: center; gap: 0.375rem; font-size: 0.9rem; color: #3b82f6; text-decoration: none; margin-bottom: 1rem; padding: 0.4rem 0.75rem; border: 1px solid #3b82f6; border-radius: 6px; }
    .back-link:hover { background: #3b82f6; color: #fff; }
    .tabs { display: flex; gap: 0.25rem; border-bottom: 2px solid #e5e7eb; margin-bottom: 1rem; }
    .tab { padding: 0.625rem 1rem; border: 0; background: transparent; cursor: pointer; font-size: 0.9rem; color: #6b7280; border-bottom: 3px solid transparent; margin-bottom: -2px; }
    .tab.active { color: #3b82f6; border-bottom-color: #3b82f6; font-weight: 600; }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-bottom: 0.75rem; }
    th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #e5e7eb; vertical-align: middle; }
    th { background: #f9fafb; font-weight: 600; color: #555; }
    .btn { padding: 0.4rem 0.75rem; border: 0; border-radius: 6px; font-size: 0.85rem; font-weight: 500; cursor: pointer; transition: background 0.2s; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-primary { background: #3b82f6; color: #fff; }
    .btn-primary:hover:not(:disabled) { background: #2563eb; }
    .btn-gray { background: #f3f4f6; color: #374151; }
    .btn-gray:hover:not(:disabled) { background: #e5e7eb; }
    .btn-red { background: #fef2f2; color: #dc2626; }
    .btn-red:hover:not(:disabled) { background: #fecaca; }
    .btn-sm { padding: 0.3rem 0.6rem; font-size: 0.8rem; }
    .row { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; margin-bottom: 0.5rem; }
    input[type=text], input[type=email], select, textarea { padding: 0.4rem 0.6rem; border: 1px solid #ddd; border-radius: 6px; font-size: 0.85rem; }
    .alert { padding: 0.6rem 0.75rem; border-radius: 6px; margin-bottom: 0.75rem; font-size: 0.85rem; }
    .alert-error { background: #fef2f2; border: 1px solid #fecaca; color: #dc2626; }
    .alert-warn { background: #fffbeb; border: 1px solid #fde68a; color: #92400e; }
    .alert-success { background: #f0fdf4; border: 1px solid #bbf7d0; color: #16a34a; }
    .muted { color: #9ca3af; }
    .chip { display: inline-block; padding: 0.125rem 0.5rem; border-radius: 9999px; font-size: 0.7rem; font-weight: 500; margin-right: 0.25rem; }
    .chip-green { background: #dcfce7; color: #166534; }
    .chip-gray { background: #f3f4f6; color: #6b7280; }
  </style>
</head>
<body>
  <div class="container">
    <a href="/top" class="back-link">← 戻る</a>
    <h1>通知管理</h1>

    <div id="alert"></div>

    <div class="tabs">
      <button class="tab active" data-tab="lineworks">LINE WORKS から追加</button>
      <button class="tab" data-tab="recipients">受信者一覧</button>
      <button class="tab" data-tab="groups">グループ管理</button>
      <button class="tab" data-tab="login-activity">ログイン状況</button>
    </div>

    <div id="tab-lineworks" class="tab-panel active">
      <div class="row">
        <button id="lw-reload" class="btn btn-gray btn-sm">再読み込み</button>
        <label>グループに追加: <select id="lw-group"></select></label>
        <button id="lw-bulk" class="btn btn-primary btn-sm">選択を一括登録</button>
      </div>
      <table>
        <thead>
          <tr>
            <th style="width:2rem;"><input type="checkbox" id="lw-select-all"></th>
            <th>名前</th><th>メール</th><th>LINE WORKS User ID</th><th>状態</th>
          </tr>
        </thead>
        <tbody id="lw-body"><tr><td colspan="5" class="muted">読み込み中...</td></tr></tbody>
      </table>
    </div>

    <div id="tab-recipients" class="tab-panel">
      <table>
        <thead>
          <tr><th>名前</th><th>プロバイダ</th><th>ID</th><th>有効</th><th></th></tr>
        </thead>
        <tbody id="rec-body"><tr><td colspan="5" class="muted">読み込み中...</td></tr></tbody>
      </table>
    </div>

    <div id="tab-groups" class="tab-panel">
      <div class="row">
        <input type="text" id="group-name" placeholder="新しいグループ名">
        <input type="text" id="group-desc" placeholder="説明 (任意)">
        <button id="group-create" class="btn btn-primary btn-sm">作成</button>
      </div>
      <table>
        <thead>
          <tr><th>名前</th><th>説明</th><th>メンバー数</th><th></th></tr>
        </thead>
        <tbody id="group-body"><tr><td colspan="4" class="muted">読み込み中...</td></tr></tbody>
      </table>
    </div>

    <div id="tab-login-activity" class="tab-panel">
      <p class="muted" style="margin-bottom:0.5rem;">LINE WORKS のログイン・メッセージ送信・掲示板既読のうち最も新しい日時 (最終活動) と、その根拠を確認します。確認のみ・自動送信はしません。モバイルアプリはセッションを保持するため「記録なし」でも未使用とは限りません。</p>
      <div class="row">
        <button id="la-reload" class="btn btn-gray btn-sm">再読み込み</button>
        <label>N日以上ログインなし: <input type="number" id="la-days" value="3" min="0" style="width:4rem;"></label>
        <label>根拠: <select id="la-source"><option value="">すべて</option>${sourceOptions}<option value="none">記録なし</option></select></label>
      </div>
      <table>
        <thead>
          <tr><th>名前</th><th>メール</th><th>最終活動</th><th>根拠</th><th>状態</th></tr>
        </thead>
        <tbody id="la-body"><tr><td colspan="5" class="muted">読み込み中...</td></tr></tbody>
      </table>
    </div>
  </div>

${renderAdminAuthScript()}
<script>
(function(){
  var ALC_API = ${apiJson};
  // #474: cookie (logi_auth_token) → sessionStorage の順で解決する共通門番。
  var token = window.__adminAuth.requireToken('/admin/notify/callback');
  if (!token) return;

  function api(path, opts) {
    opts = opts || {};
    opts.headers = Object.assign({}, opts.headers || {}, {
      'Authorization': 'Bearer ' + token,
      'Content-Type': opts.body ? 'application/json' : undefined,
    });
    // #434: rust 直叩きは tenant header 不在で 401 になる。同一オリジンの
    // /admin/notify/api/* forward proxy 経由で叩く (auth-worker が JWT 検証 +
    // X-Tenant-ID 注入して rust へ転送する)。
    return fetch('/admin/notify/api' + path, opts);
  }
  function esc(s) { return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
  function showAlert(kind, msg) {
    document.getElementById('alert').innerHTML = '<div class="alert alert-' + kind + '">' + esc(msg) + '</div>';
    if (kind !== 'error') setTimeout(function(){ document.getElementById('alert').innerHTML = ''; }, 5000);
  }

  // --- Tabs ---
  document.querySelectorAll('.tab').forEach(function(btn){
    btn.addEventListener('click', function(){
      document.querySelectorAll('.tab').forEach(function(b){ b.classList.remove('active'); });
      btn.classList.add('active');
      document.querySelectorAll('.tab-panel').forEach(function(p){ p.classList.remove('active'); });
      document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
      if (btn.dataset.tab === 'recipients') loadRecipients();
      else if (btn.dataset.tab === 'groups') loadGroups();
      else if (btn.dataset.tab === 'lineworks') loadLineworksUsers();
      else if (btn.dataset.tab === 'login-activity') loadLoginActivity();
    });
  });

  // --- LINE WORKS users ---
  async function loadLineworksUsers() {
    var body = document.getElementById('lw-body');
    body.innerHTML = '<tr><td colspan="5" class="muted">読み込み中...</td></tr>';
    var res = await api('/notify/lineworks/users');
    if (res.status === 403) {
      var err = await res.json().catch(function(){ return {}; });
      body.innerHTML = '<tr><td colspan="5"><div class="alert alert-warn">LINE WORKS Developer Console で <b>directory.read</b> scope を Service Account に追加してください。追加後、トークンは scope 別にキャッシュされるので次回呼び出しから反映されます。</div></td></tr>';
      return;
    }
    if (!res.ok) {
      body.innerHTML = '<tr><td colspan="5" class="alert alert-error">読み込み失敗: HTTP ' + res.status + '</td></tr>';
      return;
    }
    var users = await res.json();
    if (!Array.isArray(users) || users.length === 0) {
      body.innerHTML = '<tr><td colspan="5" class="muted">LINE WORKS ユーザーがいません</td></tr>';
      return;
    }
    body.innerHTML = users.map(function(u, idx){
      var badge = u.already_registered
        ? '<span class="chip chip-green">登録済</span>'
        : '<span class="chip chip-gray">未登録</span>';
      var disabled = u.already_registered ? 'disabled' : '';
      return '<tr>' +
        '<td><input type="checkbox" class="lw-row" data-idx="' + idx + '" ' + disabled + '></td>' +
        '<td>' + esc(u.user_name) + '</td>' +
        '<td>' + esc(u.email) + '</td>' +
        '<td><code>' + esc(u.user_id) + '</code></td>' +
        '<td>' + badge + '</td>' +
        '</tr>';
    }).join('');
    // store for bulk
    window.__lwUsers = users;
  }

  document.getElementById('lw-reload').addEventListener('click', loadLineworksUsers);
  document.getElementById('lw-select-all').addEventListener('change', function(ev){
    document.querySelectorAll('.lw-row').forEach(function(cb){
      if (!cb.disabled) cb.checked = ev.target.checked;
    });
  });

  document.getElementById('lw-bulk').addEventListener('click', async function(){
    var users = window.__lwUsers || [];
    var selected = [];
    document.querySelectorAll('.lw-row:checked').forEach(function(cb){
      var u = users[Number(cb.dataset.idx)];
      if (u) selected.push({
        name: u.user_name || u.email || u.user_id,
        provider: 'lineworks',
        lineworks_user_id: u.user_id,
        email: u.email || null,
      });
    });
    if (selected.length === 0) { showAlert('warn', '1 件も選択されていません'); return; }
    var groupSelect = document.getElementById('lw-group');
    var group_ids = groupSelect.value ? [groupSelect.value] : [];
    var res = await api('/notify/recipients/bulk', {
      method: 'POST',
      body: JSON.stringify({ recipients: selected, group_ids: group_ids }),
    });
    if (!res.ok) { showAlert('error', '一括登録失敗: HTTP ' + res.status); return; }
    var body = await res.json();
    var skipped = body.skipped || [];
    var summary = '登録完了: ' + body.created + ' 件追加 / ' + body.updated + ' 件更新';
    if (skipped.length === 0) {
      showAlert('success', summary);
    } else {
      var reasonLabel = {
        missing_lineworks_user_id: 'LINE WORKS user_id 欠落',
        db_error: 'DB エラー (FK 違反等。再ログインしてやり直してください)',
      };
      var alertEl = document.getElementById('alert');
      alertEl.innerHTML = '';
      var div = document.createElement('div');
      div.className = 'alert alert-warn';
      div.appendChild(document.createTextNode(summary + ' / ' + skipped.length + ' 件スキップ'));
      var ul = document.createElement('ul');
      ul.style.margin = '0.5rem 0 0 1.5rem';
      ul.style.fontSize = '0.85em';
      skipped.forEach(function(s){
        var u = selected[s.index];
        var name = u ? (u.name || u.email || u.lineworks_user_id) : ('行 ' + s.index);
        var label = reasonLabel[s.reason] || s.reason;
        var li = document.createElement('li');
        li.textContent = name + ': ' + label;
        ul.appendChild(li);
      });
      div.appendChild(ul);
      alertEl.appendChild(div);
    }
    loadLineworksUsers();
  });

  // --- Recipients ---
  async function loadRecipients() {
    var body = document.getElementById('rec-body');
    body.innerHTML = '<tr><td colspan="5" class="muted">読み込み中...</td></tr>';
    var res = await api('/notify/recipients');
    if (!res.ok) { body.innerHTML = '<tr><td colspan="5" class="alert alert-error">HTTP ' + res.status + '</td></tr>'; return; }
    var recipients = await res.json();
    if (!Array.isArray(recipients) || recipients.length === 0) {
      body.innerHTML = '<tr><td colspan="5" class="muted">受信者がいません</td></tr>';
      return;
    }
    body.innerHTML = recipients.map(function(r){
      var id = r.lineworks_user_id || r.line_user_id || r.phone_number || r.email || '';
      var testBtn = '<button class="btn btn-gray btn-sm rec-test" data-id="' + r.id + '" data-name="' + esc(r.name) + '"' + (r.enabled ? '' : ' disabled title="有効化してから実行してください"') + '>テスト送信</button>';
      return '<tr>' +
        '<td>' + esc(r.name) + '</td>' +
        '<td>' + esc(r.provider) + '</td>' +
        '<td><code>' + esc(id) + '</code></td>' +
        '<td><input type="checkbox" class="rec-enable" data-id="' + r.id + '" ' + (r.enabled ? 'checked' : '') + '></td>' +
        '<td>' + testBtn + ' <button class="btn btn-red btn-sm rec-delete" data-id="' + r.id + '">削除</button></td>' +
        '</tr>';
    }).join('');
    document.querySelectorAll('.rec-enable').forEach(function(cb){
      cb.addEventListener('change', async function(){
        var res = await api('/notify/recipients/' + cb.dataset.id, {
          method: 'PUT',
          body: JSON.stringify({ enabled: cb.checked }),
        });
        if (!res.ok) { showAlert('error', '更新失敗'); cb.checked = !cb.checked; }
      });
    });
    document.querySelectorAll('.rec-test').forEach(function(btn){
      btn.addEventListener('click', async function(){
        var id = btn.dataset.id;
        var name = btn.dataset.name || '';
        if (!confirm(name + ' にテスト通知を送信しますか？')) return;
        btn.disabled = true;
        try {
          var message = '[テスト通知] これは通知機能の疎通確認メッセージです (' + new Date().toLocaleString('ja-JP') + ')';
          var res = await api('/notify/test-distribute', {
            method: 'POST',
            body: JSON.stringify({ message: message, recipient_ids: [id] }),
          });
          if (!res.ok) { showAlert('error', 'テスト送信失敗: HTTP ' + res.status); return; }
          var data = await res.json();
          if (data.sent > 0) {
            showAlert('success', 'テスト送信完了: ' + name + ' に配信しました');
          } else {
            showAlert('warn', 'テスト送信は試行されましたが配信できませんでした (sent=0, failed=' + (data.failed || 0) + ')');
          }
        } finally {
          btn.disabled = false;
        }
      });
    });
    document.querySelectorAll('.rec-delete').forEach(function(btn){
      btn.addEventListener('click', async function(){
        if (!confirm('この受信者を削除しますか？')) return;
        var res = await api('/notify/recipients/' + btn.dataset.id, { method: 'DELETE' });
        if (!res.ok) { showAlert('error', '削除失敗'); return; }
        loadRecipients();
      });
    });
  }

  // --- Groups ---
  async function loadGroups() {
    var body = document.getElementById('group-body');
    body.innerHTML = '<tr><td colspan="4" class="muted">読み込み中...</td></tr>';
    var res = await api('/notify/groups');
    if (!res.ok) { body.innerHTML = '<tr><td colspan="4" class="alert alert-error">HTTP ' + res.status + '</td></tr>'; return; }
    var groups = await res.json();
    // update the lineworks tab's group dropdown
    var sel = document.getElementById('lw-group');
    sel.innerHTML = '<option value="">(なし)</option>' + groups.map(function(g){
      return '<option value="' + g.id + '">' + esc(g.name) + '</option>';
    }).join('');
    if (!Array.isArray(groups) || groups.length === 0) {
      body.innerHTML = '<tr><td colspan="4" class="muted">グループがありません</td></tr>';
      return;
    }
    // fetch each group's members count
    var rows = await Promise.all(groups.map(async function(g){
      var mres = await api('/notify/groups/' + g.id + '/members');
      var count = mres.ok ? (await mres.json()).length : '?';
      return '<tr>' +
        '<td>' + esc(g.name) + '</td>' +
        '<td>' + esc(g.description || '') + '</td>' +
        '<td>' + count + '</td>' +
        '<td><button class="btn btn-red btn-sm group-delete" data-id="' + g.id + '">削除</button></td>' +
        '</tr>';
    }));
    body.innerHTML = rows.join('');
    document.querySelectorAll('.group-delete').forEach(function(btn){
      btn.addEventListener('click', async function(){
        if (!confirm('このグループを削除しますか？(メンバーリンクも削除されます)')) return;
        var res = await api('/notify/groups/' + btn.dataset.id, { method: 'DELETE' });
        if (!res.ok) { showAlert('error', '削除失敗'); return; }
        loadGroups();
      });
    });
  }

  document.getElementById('group-create').addEventListener('click', async function(){
    var name = document.getElementById('group-name').value.trim();
    var desc = document.getElementById('group-desc').value.trim();
    if (!name) { showAlert('warn', 'グループ名を入力してください'); return; }
    var res = await api('/notify/groups', {
      method: 'POST',
      body: JSON.stringify({ name: name, description: desc || null }),
    });
    if (!res.ok) { showAlert('error', '作成失敗: HTTP ' + res.status); return; }
    document.getElementById('group-name').value = '';
    document.getElementById('group-desc').value = '';
    showAlert('success', 'グループを作成しました');
    loadGroups();
  });

  // --- Login activity (#540) ---
  // 取得済みの行。null = 未取得・取得中・失敗 (この間は絞り込みを変えても描き直さない)。
  var laRows = null;
  var LA_SOURCE_LABELS = ${JSON.stringify(LOGIN_SOURCE_LABELS)};
  function laSourceLabel(source) {
    // 表に無い値・欠落 (rust 未反映) は「—」。prototype のキーを拾わないよう own property だけ見る。
    return Object.prototype.hasOwnProperty.call(LA_SOURCE_LABELS, source) ? LA_SOURCE_LABELS[source] : '—';
  }

  async function loadLoginActivity() {
    var body = document.getElementById('la-body');
    laRows = null;
    body.innerHTML = '<tr><td colspan="5" class="muted">読み込み中...</td></tr>';
    var days = document.getElementById('la-days').value;
    if (days === '' || Number(days) < 0) days = '3';
    var res = await api('/notify/lineworks/login-activity?days=' + encodeURIComponent(days));
    if (res.status === 403) {
      body.innerHTML = '<tr><td colspan="5"><div class="alert alert-warn">LINE WORKS Developer Console で <b>audit.read</b> scope を Service Account に追加してください。追加後、トークンは scope 別にキャッシュされるので次回呼び出しから反映されます。</div></td></tr>';
      return;
    }
    if (!res.ok) {
      body.innerHTML = '<tr><td colspan="5" class="alert alert-error">読み込み失敗: HTTP ' + res.status + '</td></tr>';
      return;
    }
    var rows = await res.json();
    laRows = Array.isArray(rows) ? rows : [];
    renderLoginActivity();
  }

  // 根拠の絞り込みを適用して描く。select の change からは再取得せずこれだけ呼ぶ。
  function renderLoginActivity() {
    if (laRows === null) return;
    var body = document.getElementById('la-body');
    if (laRows.length === 0) {
      body.innerHTML = '<tr><td colspan="5" class="muted">LINE WORKS ユーザーがいません</td></tr>';
      return;
    }
    var filter = document.getElementById('la-source').value;
    var rows = laRows.filter(function(r){
      if (filter === '') return true;
      if (filter === 'none') return !r.last_login_at;
      return r.last_login_source === filter;
    });
    if (rows.length === 0) {
      body.innerHTML = '<tr><td colspan="5" class="muted">該当するユーザーがいません</td></tr>';
      return;
    }
    body.innerHTML = rows.map(function(r){
      var lastLogin = r.last_login_at ? esc(r.last_login_at) : '<span class="muted">記録なし</span>';
      var badge = r.stale
        ? '<span class="chip chip-gray">' + (r.days_since_login == null ? '記録なし' : esc(String(r.days_since_login)) + '日') + '</span>'
        : '<span class="chip chip-green">直近</span>';
      return '<tr>' +
        '<td>' + esc(r.user_name || '') + '</td>' +
        '<td>' + esc(r.email || '') + '</td>' +
        '<td>' + lastLogin + '</td>' +
        '<td>' + esc(laSourceLabel(r.last_login_source)) + '</td>' +
        '<td>' + badge + '</td>' +
        '</tr>';
    }).join('');
  }

  document.getElementById('la-reload').addEventListener('click', loadLoginActivity);
  document.getElementById('la-days').addEventListener('change', loadLoginActivity);
  document.getElementById('la-source').addEventListener('change', renderLoginActivity);

  // initial load
  loadLineworksUsers();
  loadGroups();
})();
</script>
</body>
</html>`;
}
