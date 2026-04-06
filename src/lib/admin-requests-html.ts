/**
 * Admin access requests management page HTML
 */

export function renderAdminRequestsPage(): string {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>参加リクエスト管理</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; padding: 1rem; }
    .container { max-width: 800px; margin: 0 auto; }
    h1 { font-size: 1.3rem; color: #333; margin-bottom: 1rem; }
    .tabs { display: flex; gap: 0.5rem; margin-bottom: 1rem; }
    .tab { padding: 8px 16px; border: none; border-radius: 8px; cursor: pointer; font-size: 0.9rem; background: #e0e0e0; }
    .tab.active { background: #1a73e8; color: white; }
    .card { background: white; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); padding: 1rem; margin-bottom: 0.75rem; }
    .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
    .user-info { display: flex; align-items: center; gap: 0.75rem; }
    .avatar { width: 40px; height: 40px; border-radius: 50%; background: #e0e0e0; object-fit: cover; }
    .user-details h3 { font-size: 0.95rem; color: #333; }
    .user-details p { font-size: 0.8rem; color: #666; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    .badge-pending { background: #fff3cd; color: #856404; }
    .badge-approved { background: #d4edda; color: #155724; }
    .badge-declined { background: #f8d7da; color: #721c24; }
    .badge-google { background: #e8f0fe; color: #1967d2; }
    .badge-lineworks { background: #e6f9ec; color: #00a63e; }
    .actions { display: flex; gap: 0.5rem; margin-top: 0.5rem; }
    .btn { padding: 6px 12px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.85rem; }
    .btn-approve { background: #00c73c; color: white; }
    .btn-decline { background: #d93025; color: white; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    select { padding: 4px 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 0.85rem; }
    .meta { font-size: 0.75rem; color: #999; margin-top: 0.25rem; }
    .empty { text-align: center; color: #999; padding: 2rem; }
    .loading { text-align: center; color: #666; padding: 2rem; }
    .nav { margin-bottom: 1rem; }
    .nav a { color: #1a73e8; text-decoration: none; font-size: 0.9rem; }
  </style>
</head>
<body>
  <div class="container">
    <div class="nav"><a href="/admin/sso">&larr; SSO 設定</a></div>
    <h1>参加リクエスト管理</h1>
    <div class="tabs">
      <button class="tab active" data-filter="pending">保留中</button>
      <button class="tab" data-filter="approved">承認済み</button>
      <button class="tab" data-filter="declined">却下済み</button>
      <button class="tab" data-filter="">全て</button>
    </div>
    <div id="list"><div class="loading">読み込み中...</div></div>
  </div>
  <script>
    let currentFilter = 'pending';

    function getToken() {
      // sessionStorage (primary)
      var t = sessionStorage.getItem('auth_token');
      if (t) return t;
      // cookie fallback (migration)
      var m = document.cookie.match(/sso_admin_token=([^;]+)/) ||
              document.cookie.match(/logi_auth_token=([^;]+)/);
      if (m && m[1]) {
        sessionStorage.setItem('auth_token', m[1]);
        return m[1];
      }
      return null;
    }

    async function apiCall(endpoint, body) {
      const token = getToken();
      if (!token) { window.location.href = '/admin/requests/callback'; return null; }
      const res = await fetch('/api/access-requests/' + endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
        body: JSON.stringify(body),
      });
      return res.json();
    }

    function escapeHtml(str) {
      const div = document.createElement('div');
      div.textContent = str || '';
      return div.innerHTML;
    }

    function providerBadge(provider) {
      if (provider === 'google') return '<span class="badge badge-google">Google</span>';
      if (provider === 'lineworks') return '<span class="badge badge-lineworks">LINE WORKS</span>';
      return '<span class="badge">' + escapeHtml(provider) + '</span>';
    }

    function statusBadge(status) {
      const cls = 'badge-' + status;
      const labels = { pending: '保留中', approved: '承認済み', declined: '却下済み' };
      return '<span class="badge ' + cls + '">' + (labels[status] || status) + '</span>';
    }

    async function loadRequests() {
      const list = document.getElementById('list');
      list.innerHTML = '<div class="loading">読み込み中...</div>';

      const data = await apiCall('list', { status_filter: currentFilter });
      if (!data) return;

      if (data.error) {
        list.innerHTML = '<div class="empty">' + escapeHtml(data.error) + '</div>';
        return;
      }

      const requests = data.requests || [];
      if (requests.length === 0) {
        list.innerHTML = '<div class="empty">リクエストはありません</div>';
        return;
      }

      list.innerHTML = requests.map(function(r) {
        const avatarSrc = r.avatarUrl || 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><circle cx="20" cy="20" r="20" fill="%23e0e0e0"/><text x="20" y="26" text-anchor="middle" fill="%23999" font-size="16">' + (r.displayName || r.email || '?').charAt(0) + '</text></svg>';
        let actions = '';
        if (r.status === 'pending') {
          actions = '<div class="actions">' +
            '<select id="role-' + r.id + '"><option value="member">メンバー</option><option value="admin">管理者</option></select>' +
            '<button class="btn btn-approve" onclick="approve(\\'' + r.id + '\\')">承認</button>' +
            '<button class="btn btn-decline" onclick="decline(\\'' + r.id + '\\')">却下</button>' +
            '</div>';
        }
        let meta = '';
        if (r.reviewedAt) {
          meta = '<div class="meta">レビュー: ' + escapeHtml(r.reviewedAt) + (r.role ? ' (ロール: ' + escapeHtml(r.role) + ')' : '') + '</div>';
        }
        return '<div class="card">' +
          '<div class="card-header">' +
            '<div class="user-info">' +
              '<img class="avatar" src="' + avatarSrc + '" onerror="this.style.display=\\'none\\'">' +
              '<div class="user-details">' +
                '<h3>' + escapeHtml(r.displayName || r.email) + '</h3>' +
                '<p>' + escapeHtml(r.email) + '</p>' +
              '</div>' +
            '</div>' +
            '<div>' + statusBadge(r.status) + ' ' + providerBadge(r.provider) + '</div>' +
          '</div>' +
          '<div class="meta">' + escapeHtml(r.createdAt) + '</div>' +
          meta +
          actions +
        '</div>';
      }).join('');
    }

    async function approve(id) {
      const role = document.getElementById('role-' + id).value;
      const data = await apiCall('approve', { request_id: id, role: role });
      if (data && !data.error) loadRequests();
      else if (data) alert(data.error);
    }

    async function decline(id) {
      if (!confirm('このリクエストを却下しますか？')) return;
      const data = await apiCall('decline', { request_id: id });
      if (data && !data.error) loadRequests();
      else if (data) alert(data.error);
    }

    // Tab switching
    document.querySelectorAll('.tab').forEach(function(tab) {
      tab.addEventListener('click', function() {
        document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
        tab.classList.add('active');
        currentFilter = tab.dataset.filter;
        loadRequests();
      });
    });

    loadRequests();
  </script>
</body>
</html>`;
}
