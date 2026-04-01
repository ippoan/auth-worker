/**
 * Admin SSO settings page handlers
 *
 * /admin/sso          — cookie 認証必須。なければ /login へリダイレクト
 * /admin/sso/callback — ログイン後の着地点。fragment → cookie → /admin/sso へリダイレクト
 */

import type { Env } from "../index";
import { renderAdminSsoPage } from "../lib/admin-html";

const COOKIE_NAME = "sso_admin_token";

function getTokenFromCookie(request: Request): string | null {
  const cookie = request.headers.get("Cookie") || "";
  const adminMatch = cookie.match(new RegExp(`${COOKIE_NAME}=([^;]+)`));
  if (adminMatch?.[1]) return adminMatch[1];
  const sharedMatch = cookie.match(/logi_auth_token=([^;]+)/);
  return sharedMatch?.[1] ?? null;
}

/** GET /admin/sso — cookie チェック → ページ配信 or ログインリダイレクト */
export async function handleAdminSsoPage(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = getTokenFromCookie(request);
  console.log(JSON.stringify({ event: "admin_access", hasToken: !!token }));
  if (!token) {
    const origin = new URL(request.url).origin;
    const callbackUri = `${origin}/admin/sso/callback`;
    return Response.redirect(
      `${origin}/login?redirect_uri=${encodeURIComponent(callbackUri)}`,
      302,
    );
  }

  // サーバー側で権限チェック（チラ見え防止）
  try {
    const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/sso/configs`, {
      headers: { "Authorization": `Bearer ${token}` },
    });
    if (resp.status === 403) {
      return Response.redirect(`${env.AUTH_WORKER_ORIGIN}/top?error=no_permission`, 302);
    }
  } catch {
    // エラーはページを表示してクライアント側で処理
  }

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

/** GET /admin/sso/callback — fragment から token を cookie に保存して /admin/sso へ */
export async function handleAdminSsoCallback(): Promise<Response> {
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
