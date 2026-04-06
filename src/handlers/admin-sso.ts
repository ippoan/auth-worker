/**
 * Admin SSO settings page handlers
 *
 * /admin/sso          — 静的 HTML 配信（認証は JS 側で sessionStorage チェック）
 * /admin/sso/callback — ログイン後の着地点。fragment → sessionStorage → /admin/sso へリダイレクト
 */

import type { Env } from "../index";
import { renderAdminSsoPage } from "../lib/admin-html";

/** GET /admin/sso — 常に HTML を返す（認証チェックは JS 側） */
export async function handleAdminSsoPage(
  _request: Request,
  env: Env,
): Promise<Response> {
  // ALLOWED_REDIRECT_ORIGINS からフロントエンド URL を抽出（auth-worker 自身を除外）
  const frontendOrigins = (env.ALLOWED_REDIRECT_ORIGINS || "")
    .split(",")
    .map((s: string) => s.trim())
    .filter((s: string) => s && s !== env.AUTH_WORKER_ORIGIN);
  const html = renderAdminSsoPage(frontendOrigins);
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

/** GET /admin/sso/callback — fragment から token を sessionStorage に保存して /admin/sso へ */
export async function handleAdminSsoCallback(): Promise<Response> {
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
      window.location.replace('/admin/sso');
    } else {
      window.location.replace('/admin/sso');
    }
  } else {
    window.location.replace('/admin/sso');
  }
</script>
</body></html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
