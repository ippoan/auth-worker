/**
 * Admin SSO settings page handlers
 *
 * /admin/sso          — 静的 HTML 配信（認証は JS 側の共通門番 = cookie → sessionStorage）
 * /admin/sso/callback — ログイン後の着地点。fragment / cookie → sessionStorage → /admin/sso
 */

import type { Env } from "../index";
import { renderAdminSsoPage } from "../lib/admin-html";
import { getAllowedOrigins } from "../lib/config";
import { renderAdminCallbackPage } from "../lib/admin-callback-html";

/** GET /admin/sso — 常に HTML を返す（認証チェックは JS 側） */
export async function handleAdminSsoPage(
  request: Request,
  env: Env,
): Promise<Response> {
  // KV allowlist (origins:<env> ∪ origins:dev) からフロントエンド URL を抽出（auth-worker 自身を除外）
  const allOrigins = (await getAllowedOrigins(env))
    .split(",")
    .map((s: string) => s.trim())
    .filter((s: string) => s);
  const frontendOrigins = allOrigins.filter(
    (s: string) => s !== env.AUTH_WORKER_ORIGIN,
  );

  // ?from=<origin> を allowlist で完全一致検証してから戻るボタン href に使う（オープンリダイレクト防止）
  const url = new URL(request.url);
  const fromParam = url.searchParams.get("from") ?? "";
  const backUrl = allOrigins.includes(fromParam) ? fromParam : "/top";

  const html = renderAdminSsoPage(frontendOrigins, backUrl);
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

/** GET /admin/sso/callback — fragment から token を sessionStorage に保存して /admin/sso へ */
export async function handleAdminSsoCallback(): Promise<Response> {
  return new Response(renderAdminCallbackPage("/admin/sso"), {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
