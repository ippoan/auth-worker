/**
 * Staging config Export / Import admin page
 *
 * /admin/config          — 静的 HTML 配信 (認証は JS 側で sessionStorage チェック)
 * /admin/config/callback — ログイン後の着地点。fragment → sessionStorage → /admin/config
 */

import type { Env } from "../index";
import { renderAdminConfigPage } from "../lib/admin-config-html";

/** GET /admin/config — 常に HTML を返す (認証チェックは JS 側) */
export async function handleAdminConfigPage(
  _request: Request,
  env: Env,
): Promise<Response> {
  const html = renderAdminConfigPage(env.ALC_API_ORIGIN);
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

/** GET /admin/config/callback — fragment から token を sessionStorage に保存して /admin/config へ */
export async function handleAdminConfigCallback(): Promise<Response> {
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
      window.location.replace('/admin/config');
    } else {
      window.location.replace('/admin/config');
    }
  } else {
    window.location.replace('/admin/config');
  }
</script>
</body></html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
