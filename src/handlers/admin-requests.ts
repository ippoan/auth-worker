/**
 * Admin access requests page handlers
 *
 * /admin/requests          — cookie 認証必須。なければ /login へリダイレクト
 * /admin/requests/callback — ログイン後の着地点。fragment → cookie → /admin/requests へリダイレクト
 */

import { createClient, ConnectError, Code } from "@connectrpc/connect";
import { AccessRequestService } from "@yhonda-ohishi-pub-dev/logi-proto";
import type { Env } from "../index";
import { renderAdminRequestsPage } from "../lib/admin-requests-html";
import { createTransportWithAuth } from "../lib/transport";

const COOKIE_NAME = "sso_admin_token";

function getTokenFromCookie(request: Request): string | null {
  const cookie = request.headers.get("Cookie") || "";
  const adminMatch = cookie.match(new RegExp(`${COOKIE_NAME}=([^;]+)`));
  if (adminMatch?.[1]) return adminMatch[1];
  const sharedMatch = cookie.match(/logi_auth_token=([^;]+)/);
  return sharedMatch?.[1] ?? null;
}

/** GET /admin/requests — cookie チェック → ページ配信 or ログインリダイレクト */
export async function handleAdminRequestsPage(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = getTokenFromCookie(request);
  if (!token) {
    const callbackUri = `${env.AUTH_WORKER_ORIGIN}/admin/requests/callback`;
    return Response.redirect(
      `${env.AUTH_WORKER_ORIGIN}/login?redirect_uri=${encodeURIComponent(callbackUri)}`,
      302,
    );
  }

  // サーバー側で権限チェック（チラ見え防止）
  try {
    const transport = createTransportWithAuth(env.GRPC_PROXY, token);
    const client = createClient(AccessRequestService, transport);
    await client.listAccessRequests({ statusFilter: "pending" });
  } catch (err) {
    if (err instanceof ConnectError && err.code === Code.PermissionDenied) {
      return Response.redirect(`${env.AUTH_WORKER_ORIGIN}/top?error=no_permission`, 302);
    }
  }

  const html = renderAdminRequestsPage();
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

/** GET /admin/requests/callback — fragment から token を cookie に保存して /admin/requests へ */
export async function handleAdminRequestsCallback(): Promise<Response> {
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
