/**
 * Admin access requests page handlers (REST version)
 *
 * /admin/requests          — 静的 HTML 配信（認証は JS 側で sessionStorage チェック）
 * /admin/requests/callback — ログイン後の着地点。fragment → sessionStorage → /admin/requests へリダイレクト
 */

import type { Env } from "../index";
import { renderAdminRequestsPage } from "../lib/admin-requests-html";

/** GET /admin/requests — 常に HTML を返す（認証チェックは JS 側） */
export async function handleAdminRequestsPage(
  _request: Request,
  _env: Env,
): Promise<Response> {
  const html = renderAdminRequestsPage();
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

/** GET /admin/requests/callback — fragment から token を sessionStorage に保存して /admin/requests へ */
export async function handleAdminRequestsCallback(): Promise<Response> {
  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Redirecting...</title></head>
<body>
<script>
  const hash = window.location.hash;
  if (hash && hash.includes('token=')) {
    const params = new URLSearchParams(hash.slice(1));
    const token = params.get('token');
    if (token) {
      sessionStorage.setItem('auth_token', token);
      window.location.replace('/admin/requests');
    } else {
      window.location.replace('/admin/requests');
    }
  } else {
    window.location.replace('/admin/requests');
  }
</script>
</body></html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
