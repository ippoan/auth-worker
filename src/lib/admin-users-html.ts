/**
 * User Management admin page HTML template
 * Single-page app with inline JS for JWT auth + API calls
 */

export function renderAdminUsersPage(): string {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ユーザー管理 - Admin</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f5f5f5;
      padding: 1rem;
    }
    .container {
      background: white;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      padding: 2rem;
      max-width: 800px;
      margin: 1rem auto;
    }
    h1 { font-size: 1.5rem; margin-bottom: 1.5rem; color: #333; }
    h2 { font-size: 1.1rem; margin-bottom: 1rem; color: #555; }
    .back-link {
      display: inline-flex; align-items: center; gap: 0.375rem; font-size: 1rem; color: #3b82f6;
      text-decoration: none; margin-bottom: 1rem; font-weight: 500;
      padding: 0.5rem 0.75rem; border: 1px solid #3b82f6; border-radius: 6px;
    }
    .back-link:hover { background: #3b82f6; color: white; }
    .error {
      background: #fef2f2; border: 1px solid #fecaca; color: #dc2626;
      padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.875rem;
    }
    .success {
      background: #f0fdf4; border: 1px solid #bbf7d0; color: #16a34a;
      padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.875rem;
    }
    table {
      width: 100%; border-collapse: collapse; margin-bottom: 1rem; font-size: 0.875rem;
    }
    th, td {
      text-align: left; padding: 0.625rem 0.75rem; border-bottom: 1px solid #e5e7eb;
    }
    th { background: #f9fafb; font-weight: 600; color: #555; }
    .badge {
      display: inline-block; padding: 0.125rem 0.5rem; border-radius: 9999px;
      font-size: 0.75rem; font-weight: 500;
    }
    .badge-blue { background: #dbeafe; color: #1d4ed8; }
    .badge-gray { background: #f3f4f6; color: #6b7280; }
    .badge-yellow { background: #fef9c3; color: #a16207; }
    .btn {
      padding: 0.5rem 1rem; border: none; border-radius: 6px; font-size: 0.875rem;
      font-weight: 500; cursor: pointer; transition: background 0.2s;
    }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-primary { background: #3b82f6; color: white; }
    .btn-primary:hover:not(:disabled) { background: #2563eb; }
    .btn-red { background: #fef2f2; color: #dc2626; }
    .btn-red:hover:not(:disabled) { background: #fecaca; }
    .btn-sm { padding: 0.375rem 0.75rem; font-size: 0.8rem; }
    .btn-gray { background: #f3f4f6; color: #374151; }
    .btn-gray:hover:not(:disabled) { background: #e5e7eb; }
    label { display: block; font-size: 0.875rem; font-weight: 500; color: #555; margin-bottom: 0.25rem; }
    input, select {
      width: 100%; padding: 0.625rem 0.75rem; border: 1px solid #ddd;
      border-radius: 6px; font-size: 1rem; margin-bottom: 1rem; outline: none;
    }
    input:focus, select:focus { border-color: #3b82f6; }
    .divider { border-top: 1px solid #e5e7eb; margin: 1.5rem 0; }
    .form-row { display: flex; gap: 0.75rem; align-items: flex-end; }
    .form-row .field { flex: 1; }
    .form-row .field-sm { flex: 0 0 120px; }
    .empty { color: #9ca3af; font-size: 0.875rem; padding: 1rem 0; }
    .loading { text-align: center; padding: 2rem; color: #9ca3af; }
  </style>
</head>
<body>
  <div class="container">
    <a href="/top" class="back-link">← 戻る</a>
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <h1>ユーザー管理</h1>
      <button class="btn btn-gray btn-sm" onclick="logout()">ログアウト</button>
    </div>
    <div id="user-info" style="font-size:0.8rem;color:#6b7280;margin-bottom:1rem;"></div>
    <div id="msg"></div>

    <!-- Users list -->
    <h2>登録済みユーザー</h2>
    <div id="users-list"><div class="loading">読み込み中...</div></div>

    <div class="divider"></div>

    <!-- Invitations list -->
    <h2>追加済み（未ログイン）</h2>
    <div id="invitations-list"><div class="loading">読み込み中...</div></div>

    <div class="divider"></div>

    <!-- Invite form -->
    <h2>ユーザー追加</h2>
    <form id="invite-form" onsubmit="return false;">
      <div class="form-row">
        <div class="field">
          <label for="email">メールアドレス</label>
          <input type="email" id="email" placeholder="user@example.com" required>
        </div>
        <div class="field-sm">
          <label for="role">権限</label>
          <select id="role">
            <option value="admin">管理者</option>
            <option value="viewer">閲覧者</option>
          </select>
        </div>
      </div>
      <button class="btn btn-primary" onclick="inviteUser()">追加する</button>
    </form>
  </div>

<script>
  const TOKEN_KEY = 'sso_admin_token';

  function getToken() {
    const admin = document.cookie.match(/sso_admin_token=([^;]+)/);
    if (admin) return admin[1];
    const shared = document.cookie.match(/logi_auth_token=([^;]+)/);
    return shared ? shared[1] : null;
  }

  function logout() {
    document.cookie = 'sso_admin_token=; path=/admin; max-age=0';
    window.location.href = '/login';
  }

  function showMsg(text, type) {
    const el = document.getElementById('msg');
    el.className = type;
    el.textContent = text;
    setTimeout(() => { el.textContent = ''; el.className = ''; }, 5000);
  }

  function parseJwt(token) {
    try {
      const b = token.split('.')[1];
      return JSON.parse(atob(b.replace(/-/g, '+').replace(/_/g, '/')));
    } catch { return null; }
  }

  async function api(path, method, body) {
    const token = getToken();
    if (!token) { window.location.href = '/login'; return null; }
    const opts = {
      method: method || 'POST',
      headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
    };
    if (body) opts.body = JSON.stringify(body);
    const resp = await fetch(path, opts);
    if (resp.status === 401) { window.location.href = '/login'; return null; }
    if (resp.status === 403) { showMsg('権限がありません', 'error'); return null; }
    return resp.json();
  }

  async function loadUsers() {
    const data = await api('/api/users/list');
    const el = document.getElementById('users-list');
    if (!data || !data.users || data.users.length === 0) {
      el.innerHTML = '<div class="empty">ユーザーがいません</div>';
      return;
    }
    let html = '<table><thead><tr><th>名前</th><th>メール</th><th>権限</th><th>登録日</th><th></th></tr></thead><tbody>';
    for (const u of data.users) {
      const date = new Date(u.created_at).toLocaleDateString('ja-JP');
      const badge = u.role === 'admin' ? 'badge-blue' : 'badge-gray';
      const label = u.role === 'admin' ? '管理者' : '閲覧者';
      html += '<tr>';
      html += '<td>' + esc(u.name) + '</td>';
      html += '<td>' + esc(u.email) + '</td>';
      html += '<td><span class="badge ' + badge + '">' + label + '</span></td>';
      html += '<td>' + date + '</td>';
      html += '<td><button class="btn btn-red btn-sm" onclick="deleteUser(\\'' + u.id + '\\')">削除</button></td>';
      html += '</tr>';
    }
    html += '</tbody></table>';
    el.innerHTML = html;
  }

  async function loadInvitations() {
    const data = await api('/api/users/invitations');
    const el = document.getElementById('invitations-list');
    if (!data || !data.invitations || data.invitations.length === 0) {
      el.innerHTML = '<div class="empty">追加済みの未ログインユーザーはいません</div>';
      return;
    }
    let html = '<table><thead><tr><th>メール</th><th>権限</th><th>追加日</th><th></th></tr></thead><tbody>';
    for (const inv of data.invitations) {
      const date = new Date(inv.created_at).toLocaleDateString('ja-JP');
      const badge = inv.role === 'admin' ? 'badge-blue' : 'badge-gray';
      const label = inv.role === 'admin' ? '管理者' : '閲覧者';
      html += '<tr>';
      html += '<td>' + esc(inv.email) + '</td>';
      html += '<td><span class="badge ' + badge + '">' + label + '</span></td>';
      html += '<td>' + date + '</td>';
      html += '<td><button class="btn btn-red btn-sm" onclick="deleteInvitation(\\'' + inv.id + '\\')">取消</button></td>';
      html += '</tr>';
    }
    html += '</tbody></table>';
    el.innerHTML = html;
  }

  async function inviteUser() {
    const email = document.getElementById('email').value.trim();
    const role = document.getElementById('role').value;
    if (!email) { showMsg('メールアドレスを入力してください', 'error'); return; }
    const data = await api('/api/users/invite', 'POST', { email, role });
    if (data && !data.error) {
      showMsg(email + ' を追加しました', 'success');
      document.getElementById('email').value = '';
      loadInvitations();
    } else if (data) {
      showMsg(data.error, 'error');
    }
  }

  async function deleteInvitation(id) {
    if (!confirm('この追加を取り消しますか？')) return;
    const data = await api('/api/users/invite/delete', 'POST', { id });
    if (data && !data.error) {
      showMsg('取り消しました', 'success');
      loadInvitations();
    }
  }

  async function deleteUser(id) {
    if (!confirm('このユーザーを削除しますか？この操作は取り消せません。')) return;
    const data = await api('/api/users/delete', 'POST', { id });
    if (data && !data.error) {
      showMsg('ユーザーを削除しました', 'success');
      loadUsers();
    } else if (data) {
      showMsg(data.error, 'error');
    }
  }

  function esc(s) {
    const d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  // Init
  const token = getToken();
  if (token) {
    const claims = parseJwt(token);
    if (claims) {
      document.getElementById('user-info').textContent = claims.email + ' (' + (claims.role === 'admin' ? '管理者' : '閲覧者') + ')';
    }
    loadUsers();
    loadInvitations();
  }
</script>
</body>
</html>`;
}
