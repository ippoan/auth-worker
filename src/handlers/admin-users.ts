/**
 * Admin Users management page handlers
 *
 * /admin/users          — 静的 HTML 配信（認証は JS 側の共通門番 = cookie → sessionStorage）
 * /admin/users/callback — ログイン後の着地点。fragment / cookie → sessionStorage → /admin/users
 */

import type { Env } from "../index";
import { renderAdminUsersPage } from "../lib/admin-users-html";
import { renderAdminCallbackPage } from "../lib/admin-callback-html";

/** GET /admin/users — 常に HTML を返す（認証チェックは JS 側） */
export async function handleAdminUsersPage(
  _request: Request,
  _env: Env,
): Promise<Response> {
  const html = renderAdminUsersPage();
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

/** GET /admin/users/callback — fragment から token を sessionStorage に保存して /admin/users へ */
export async function handleAdminUsersCallback(): Promise<Response> {
  return new Response(renderAdminCallbackPage("/admin/users"), {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
