/**
 * Admin Rich Menu page handlers
 *
 * /admin/rich-menu          — 静的 HTML 配信（認証は JS 側で sessionStorage チェック）
 * /admin/rich-menu/callback — ログイン後の着地点。fragment → sessionStorage → /admin/rich-menu へリダイレクト
 */

import type { Env } from "../index";
import { renderAdminRichMenuPage } from "../lib/admin-rich-menu-html";

/** GET /admin/rich-menu — 常に HTML を返す（認証チェックは JS 側） */
export async function handleAdminRichMenuPage(
  _request: Request,
  _env: Env,
): Promise<Response> {
  const html = renderAdminRichMenuPage();
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

/** GET /admin/rich-menu/callback — fragment から token を sessionStorage に保存して /admin/rich-menu へ */
export async function handleAdminRichMenuCallback(): Promise<Response> {
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
      window.location.replace('/admin/rich-menu');
    } else {
      window.location.replace('/admin/rich-menu');
    }
  } else {
    window.location.replace('/admin/rich-menu');
  }
</script>
</body></html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
