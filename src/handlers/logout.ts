/**
 * GET /logout — sessionStorage + cookie クリア → ログインページへリダイレクト
 *
 * sessionStorage はサーバーサイドからクリアできないため、
 * HTML ページを返して JS で実行する。
 */

import type { Env } from "../index";

export async function handleLogout(
  request: Request,
  _env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const redirectTo = url.searchParams.get("redirect_uri") || "/login";

  // Escape for safe embedding in JS string
  const safeRedirect = redirectTo.replace(/\\/g, "\\\\").replace(/'/g, "\\'").replace(/"/g, '\\"');

  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Logging out...</title></head>
<body>
<script>
  sessionStorage.removeItem('auth_token');
  localStorage.removeItem('logi_auth');
  // backward compat: clear cookies (no Domain attr = same-host)
  document.cookie = 'sso_admin_token=; Path=/admin; Max-Age=0; Secure; SameSite=Lax';
  document.cookie = 'logi_auth_token=; Path=/; Max-Age=0; Secure; SameSite=Lax';
  window.location.replace('${safeRedirect}');
</script>
</body></html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
