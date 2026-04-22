/**
 * Staging config export/import admin page.
 *
 * Calls rust-alc-api /api/staging/export and /api/staging/import.
 * STAGING_MODE ガードはバックエンド側 (本番は 404)。
 */

export function renderAdminConfigPage(alcApiOrigin: string): string {
  const apiOriginEscaped = JSON.stringify(alcApiOrigin);
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>設定 Export / Import - Admin</title>
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
    h1 { font-size: 1.5rem; margin-bottom: 1rem; color: #333; }
    h2 { font-size: 1.1rem; margin: 1.5rem 0 0.75rem; color: #555; }
    p { color: #555; font-size: 0.9rem; margin-bottom: 0.75rem; line-height: 1.5; }
    .back-link {
      display: inline-flex; align-items: center; gap: 0.375rem; font-size: 1rem; color: #3b82f6;
      text-decoration: none; margin-bottom: 1rem; font-weight: 500;
      padding: 0.5rem 0.75rem; border: 1px solid #3b82f6; border-radius: 6px;
    }
    .back-link:hover { background: #3b82f6; color: white; }
    .alert {
      padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.875rem;
    }
    .alert-error { background: #fef2f2; border: 1px solid #fecaca; color: #dc2626; }
    .alert-success { background: #f0fdf4; border: 1px solid #bbf7d0; color: #16a34a; }
    .alert-warn { background: #fffbeb; border: 1px solid #fde68a; color: #92400e; }
    .meta {
      background: #f9fafb; border: 1px solid #e5e7eb; padding: 0.75rem;
      border-radius: 6px; margin-bottom: 1rem; font-size: 0.85rem; color: #555;
    }
    .meta strong { color: #333; }
    .btn {
      padding: 0.5rem 1rem; border: none; border-radius: 6px; font-size: 0.875rem;
      font-weight: 500; cursor: pointer; transition: background 0.2s;
    }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-primary { background: #3b82f6; color: white; }
    .btn-primary:hover:not(:disabled) { background: #2563eb; }
    .btn-gray { background: #f3f4f6; color: #374151; }
    .btn-gray:hover:not(:disabled) { background: #e5e7eb; }
    .row { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
    textarea {
      width: 100%; min-height: 8rem; padding: 0.5rem; border: 1px solid #ddd;
      border-radius: 6px; font-family: 'SFMono-Regular', Consolas, monospace;
      font-size: 0.8rem; margin-bottom: 0.5rem;
    }
    pre {
      background: #f9fafb; border: 1px solid #e5e7eb; padding: 0.75rem;
      border-radius: 6px; font-size: 0.8rem; overflow-x: auto; margin-top: 0.5rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <a href="/top" class="back-link">← 戻る</a>
    <h1>設定 Export / Import</h1>
    <p>
      現在のテナントの設定 (tenants, users, employees, devices, sso, bot, notify など) を JSON で出力・復元できます。
      staging 環境の Cloud Run sidecar PostgreSQL は揮発性なので、cold start で消えたデータの復元に使います。
      本番環境では 404 エラーで保護されています。
    </p>

    <div id="alert"></div>
    <div id="meta" class="meta" style="display:none;"></div>

    <h2>Export</h2>
    <p>現在のテナント設定を JSON ファイルとしてダウンロードします。</p>
    <div class="row">
      <button id="btn-export" class="btn btn-primary">Export 現在テナント</button>
    </div>

    <h2>Import</h2>
    <p>JSON ファイルを選択するか、下のテキストエリアに貼り付けて Import します (べき等)。</p>
    <div class="row" style="margin-bottom:0.5rem;">
      <input type="file" id="file-import" accept="application/json,.json">
    </div>
    <textarea id="json-import" placeholder='{"version":1,"exported_at":"...","tenant_id":"...","data":{...}}'></textarea>
    <div class="row">
      <button id="btn-import" class="btn btn-primary">Import 実行</button>
      <button id="btn-clear" class="btn btn-gray">クリア</button>
    </div>

    <div id="result"></div>
  </div>

<script>
  const ALC_API = ${apiOriginEscaped};

  function getToken() {
    return sessionStorage.getItem('auth_token');
  }

  function decodeJwtPayload(token) {
    try {
      const parts = token.split('.');
      if (parts.length < 2) return null;
      const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
      return JSON.parse(atob(padded));
    } catch (_e) {
      return null;
    }
  }

  function showAlert(kind, message) {
    const el = document.getElementById('alert');
    el.innerHTML = '<div class="alert alert-' + kind + '">' + message + '</div>';
  }

  function clearAlert() {
    document.getElementById('alert').innerHTML = '';
  }

  function renderMeta(payload) {
    const meta = document.getElementById('meta');
    if (!payload) {
      meta.style.display = 'none';
      return null;
    }
    meta.style.display = 'block';
    meta.innerHTML =
      '<div><strong>Tenant ID:</strong> ' + (payload.tenant_id || '?') + '</div>' +
      '<div><strong>Email:</strong> ' + (payload.email || '?') + '</div>' +
      '<div><strong>Role:</strong> ' + (payload.role || '?') + '</div>';
    return payload.tenant_id;
  }

  function init() {
    const token = getToken();
    if (!token) {
      const cb = encodeURIComponent(window.location.origin + '/admin/config/callback');
      window.location.replace('/login?redirect_uri=' + cb);
      return;
    }
    const payload = decodeJwtPayload(token);
    const tenantId = renderMeta(payload);
    if (!tenantId) {
      showAlert('error', 'JWT に tenant_id が含まれていません。再ログインしてください。');
      return;
    }
    document.getElementById('btn-export').addEventListener('click', () => doExport(tenantId, token));
    document.getElementById('btn-import').addEventListener('click', () => doImport(token));
    document.getElementById('btn-clear').addEventListener('click', () => {
      document.getElementById('json-import').value = '';
      document.getElementById('file-import').value = '';
      document.getElementById('result').innerHTML = '';
      clearAlert();
    });
    document.getElementById('file-import').addEventListener('change', (ev) => {
      const file = ev.target.files && ev.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        document.getElementById('json-import').value = String(reader.result || '');
      };
      reader.readAsText(file);
    });
  }

  async function doExport(tenantId, token) {
    clearAlert();
    const btn = document.getElementById('btn-export');
    btn.disabled = true;
    try {
      const res = await fetch(ALC_API + '/api/staging/export?tenant_id=' + encodeURIComponent(tenantId), {
        headers: { 'Authorization': 'Bearer ' + token },
      });
      if (res.status === 404) {
        showAlert('warn', '本番モードのため Export は無効化されています (STAGING_MODE=true の環境のみ)。');
        return;
      }
      if (!res.ok) {
        showAlert('error', 'Export 失敗: HTTP ' + res.status);
        return;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'staging-export-' + tenantId + '-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showAlert('success', 'Export 完了。ダウンロードを開始しました。');
    } catch (err) {
      showAlert('error', 'Export エラー: ' + (err && err.message ? err.message : String(err)));
    } finally {
      btn.disabled = false;
    }
  }

  async function doImport(token) {
    clearAlert();
    document.getElementById('result').innerHTML = '';
    const text = document.getElementById('json-import').value.trim();
    if (!text) {
      showAlert('error', 'JSON を貼り付けるかファイルを選択してください。');
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      showAlert('error', 'JSON パース失敗: ' + (err && err.message ? err.message : String(err)));
      return;
    }
    const btn = document.getElementById('btn-import');
    btn.disabled = true;
    try {
      const res = await fetch(ALC_API + '/api/staging/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
        body: JSON.stringify(parsed),
      });
      if (res.status === 404) {
        showAlert('warn', '本番モードのため Import は無効化されています (STAGING_MODE=true の環境のみ)。');
        return;
      }
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        showAlert('error', 'Import 失敗: HTTP ' + res.status);
        document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(body, null, 2) + '</pre>';
        return;
      }
      showAlert('success', 'Import 完了');
      document.getElementById('result').innerHTML = '<pre>' + JSON.stringify(body, null, 2) + '</pre>';
    } catch (err) {
      showAlert('error', 'Import エラー: ' + (err && err.message ? err.message : String(err)));
    } finally {
      btn.disabled = false;
    }
  }

  init();
</script>
</body>
</html>`;
}
