/**
 * Admin Users management page handlers
 *
 * /admin/users          — 静的 HTML 配信（認証は JS 側で sessionStorage チェック）
 * /admin/users/callback — ログイン後の着地点。fragment → sessionStorage → /admin/users へリダイレクト
 */

import type { Env } from "../index";
import { renderAdminUsersPage } from "../lib/admin-users-html";

/** GET /admin/users — 常に HTML を返す（認証チェックは JS 側） */
export async function handleAdminUsersPage(
  _request: Request,
  _env: Env,
): Promise<Response> {
  const html = renderAdminUsersPage();
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

/** GET /admin/users/callback — fragment から token を sessionStorage に保存して /admin/users へ */
export async function handleAdminUsersCallback(): Promise<Response> {
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
      window.location.replace('/admin/users');
    } else {
      window.location.replace('/admin/users');
    }
  } else {
    window.location.replace('/admin/users');
  }
</script>
</body></html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
