/**
 * Admin Rich Menu page handlers
 *
 * /admin/rich-menu          — cookie auth required, redirects to /login if missing
 * /admin/rich-menu/callback — login landing: fragment → cookie → /admin/rich-menu
 */

import type { Env } from "../index";
import { renderAdminRichMenuPage } from "../lib/admin-rich-menu-html";

const COOKIE_NAME = "sso_admin_token";

function getTokenFromCookie(request: Request): string | null {
  const cookie = request.headers.get("Cookie") || "";
  const adminMatch = cookie.match(new RegExp(`${COOKIE_NAME}=([^;]+)`));
  if (adminMatch?.[1]) return adminMatch[1];
  const sharedMatch = cookie.match(/logi_auth_token=([^;]+)/);
  return sharedMatch?.[1] ?? null;
}

/** GET /admin/rich-menu — cookie check → serve page or redirect to login */
export async function handleAdminRichMenuPage(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = getTokenFromCookie(request);
  console.log(JSON.stringify({ event: "admin_rich_menu_access", hasToken: !!token }));
  if (!token) {
    const callbackUri = `${env.AUTH_WORKER_ORIGIN}/admin/rich-menu/callback`;
    return Response.redirect(
      `${env.AUTH_WORKER_ORIGIN}/login?redirect_uri=${encodeURIComponent(callbackUri)}`,
      302,
    );
  }

  const html = renderAdminRichMenuPage();
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

/** GET /admin/rich-menu/callback — extract token from fragment → cookie → redirect */
export async function handleAdminRichMenuCallback(): Promise<Response> {
  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Redirecting...</title></head>
<body>
<script>
  const hash = window.location.hash;
  if (hash && hash.includes('token=')) {
    const params = new URLSearchParams(hash.slice(1));
    const token = params.get('token');
    const expiresAt = params.get('expires_at');
    if (token) {
      let maxAge = 86400;
      if (expiresAt) {
        const exp = Number(expiresAt);
        if (!isNaN(exp)) maxAge = Math.max(exp - Math.floor(Date.now() / 1000), 60);
      }
      document.cookie = '${COOKIE_NAME}=' + token + '; path=/admin; max-age=' + maxAge + '; secure; samesite=lax';
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
