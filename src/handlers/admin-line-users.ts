/**
 * LINE ユーザー管理ページ handlers
 *
 * /admin/line-users          — 静的 HTML 配信（認証は JS 側で sessionStorage チェック）
 * /admin/line-users/callback — ログイン後の着地点。fragment → sessionStorage → /admin/line-users
 */

import type { Env } from "../index";
import { renderAdminLineUsersPage } from "../lib/admin-line-users-html";
import { getAllowedOrigins } from "../lib/config";

/** GET /admin/line-users — 常に HTML を返す（認証チェックは JS 側） */
export async function handleAdminLineUsersPage(
  request: Request,
  env: Env,
): Promise<Response> {
  const allOrigins = (await getAllowedOrigins(env))
    .split(",")
    .map((s: string) => s.trim())
    .filter((s: string) => s);
  // 招待リンクの着地先候補（auth-worker 自身も /top があるので含める）
  const redirectOrigins = allOrigins.length > 0 ? allOrigins : [env.AUTH_WORKER_ORIGIN];

  const url = new URL(request.url);
  const fromParam = url.searchParams.get("from") ?? "";
  const backUrl = allOrigins.includes(fromParam) ? fromParam : "/top";

  const html = renderAdminLineUsersPage(redirectOrigins, env.AUTH_WORKER_ORIGIN, backUrl);
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

/** GET /admin/line-users/callback — fragment の token を sessionStorage に保存して戻る */
export async function handleAdminLineUsersCallback(): Promise<Response> {
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
      window.location.replace('/admin/line-users');
    } else {
      window.location.replace('/admin/line-users');
    }
  } else {
    window.location.replace('/admin/line-users');
  }
</script>
</body></html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
