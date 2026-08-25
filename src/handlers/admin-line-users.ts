/**
 * LINE ユーザー管理ページ handlers
 *
 * /admin/line-users          — 静的 HTML 配信（認証は JS 側の共通門番 = cookie → sessionStorage）
 * /admin/line-users/callback — ログイン後の着地点。fragment / cookie → sessionStorage → /admin/line-users
 */

import type { Env } from "../index";
import { renderAdminLineUsersPage } from "../lib/admin-line-users-html";
import { getAllowedOrigins } from "../lib/config";
import { renderAdminCallbackPage } from "../lib/admin-callback-html";

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
  return new Response(renderAdminCallbackPage("/admin/line-users"), {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
