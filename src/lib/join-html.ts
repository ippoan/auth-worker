/**
 * HTML templates for the /join/:slug flow
 */

interface JoinPageParams {
  orgName: string;
  orgSlug: string;
  googleEnabled: boolean;
  authWorkerOrigin: string;
}

export function renderJoinPage(params: JoinPageParams): string {
  const { orgName, orgSlug, googleEnabled, authWorkerOrigin } = params;
  const callbackUri = `${authWorkerOrigin}/join/${orgSlug}/done`;

  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(orgName)} に参加</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .card { background: white; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); padding: 2rem; max-width: 400px; width: 90%; text-align: center; }
    h1 { font-size: 1.2rem; color: #333; margin-bottom: 0.5rem; }
    .org-name { font-size: 1.5rem; font-weight: bold; color: #1a73e8; margin-bottom: 1.5rem; }
    .btn { display: block; width: 100%; padding: 12px; border: none; border-radius: 8px; font-size: 1rem; cursor: pointer; text-decoration: none; margin-bottom: 0.75rem; transition: opacity 0.2s; }
    .btn:hover { opacity: 0.85; }
    .btn-google { background: #4285f4; color: white; }
    .btn-lw { background: #00c73c; color: white; }
    .lw-input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 8px; font-size: 1rem; margin-bottom: 0.5rem; }
    .divider { color: #999; margin: 1rem 0; font-size: 0.9rem; }
    .lw-section { text-align: left; }
    .lw-label { font-size: 0.85rem; color: #666; margin-bottom: 0.25rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>組織に参加リクエスト</h1>
    <div class="org-name">${escapeHtml(orgName)}</div>
    ${googleEnabled ? `<a class="btn btn-google" href="${authWorkerOrigin}/oauth/google/redirect?redirect_uri=${encodeURIComponent(callbackUri)}&join_org=${encodeURIComponent(orgSlug)}">Google アカウントで参加</a>` : ''}
    <div class="divider">または</div>
    <div class="lw-section">
      <div class="lw-label">LINE WORKS アドレス</div>
      <input type="text" class="lw-input" id="lwAddress" placeholder="例: tanaka@ohishi">
      <button class="btn btn-lw" onclick="loginWithLW()">LINE WORKS で参加</button>
    </div>
  </div>
  <script>
    function loginWithLW() {
      const address = document.getElementById('lwAddress').value.trim();
      if (!address) { alert('LINE WORKS アドレスを入力してください'); return; }
      const callbackUri = encodeURIComponent('${callbackUri}');
      window.location.href = '${authWorkerOrigin}/oauth/lineworks/redirect?address=' + encodeURIComponent(address) + '&redirect_uri=' + callbackUri + '&join_org=${encodeURIComponent(orgSlug)}';
    }
    document.getElementById('lwAddress').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') loginWithLW();
    });
  </script>
</body>
</html>`;
}

export function renderJoinDonePage(orgSlug: string): string {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>参加リクエスト</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .card { background: white; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); padding: 2rem; max-width: 400px; width: 90%; text-align: center; }
    .loading { color: #666; }
    .success { color: #00c73c; }
    .info { color: #1a73e8; }
    .error { color: #d93025; }
    h2 { font-size: 1.2rem; margin-bottom: 1rem; }
    p { font-size: 0.95rem; color: #555; margin-bottom: 0.5rem; }
  </style>
</head>
<body>
  <div class="card" id="content">
    <h2 class="loading">処理中...</h2>
  </div>
  <script>
    (async function() {
      const content = document.getElementById('content');
      const hash = window.location.hash;
      let token = null;

      if (hash && hash.includes('token=')) {
        const params = new URLSearchParams(hash.slice(1));
        token = params.get('token');
      }

      if (!token) {
        // Try cookie fallback (LINE WORKS in-app browser)
        const match = document.cookie.match(/logi_auth_token=([^;]+)/);
        if (match) token = match[1];
      }

      if (!token) {
        content.innerHTML = '<h2 class="error">認証エラー</h2><p>トークンが見つかりません。もう一度お試しください。</p>';
        return;
      }

      try {
        const res = await fetch('/api/access-requests/create', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token,
          },
          body: JSON.stringify({ org_slug: '${escapeHtml(orgSlug)}' }),
        });

        const data = await res.json();

        if (!res.ok) {
          content.innerHTML = '<h2 class="error">エラー</h2><p>' + (data.error || 'リクエストに失敗しました') + '</p>';
          return;
        }

        if (data.status === 'pending') {
          content.innerHTML = '<h2 class="success">リクエスト送信完了</h2><p><strong>' + escapeHtml(data.org_name) + '</strong> への参加リクエストを送信しました。</p><p>管理者の承認をお待ちください。</p>';
        } else if (data.status === 'already_member') {
          content.innerHTML = '<h2 class="info">既にメンバーです</h2><p>あなたは既にこの組織のメンバーです。</p>';
        } else if (data.status === 'already_pending') {
          content.innerHTML = '<h2 class="info">リクエスト送信済み</h2><p>既に参加リクエストが送信されています。管理者の承認をお待ちください。</p>';
        }
      } catch (err) {
        content.innerHTML = '<h2 class="error">エラー</h2><p>通信エラーが発生しました。</p>';
      }

      function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
      }
    })();
  </script>
</body>
</html>`;
}

export function renderJoinNotFoundPage(): string {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>組織が見つかりません</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .card { background: white; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); padding: 2rem; max-width: 400px; width: 90%; text-align: center; }
    h2 { font-size: 1.2rem; color: #d93025; margin-bottom: 1rem; }
    p { font-size: 0.95rem; color: #555; }
  </style>
</head>
<body>
  <div class="card">
    <h2>組織が見つかりません</h2>
    <p>指定された組織は存在しないか、無効になっています。</p>
  </div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
