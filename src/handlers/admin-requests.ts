/**
 * Admin access requests page handlers (REST version)
 *
 * /admin/requests          — 静的 HTML 配信（認証は JS 側の共通門番 = cookie → sessionStorage）
 * /admin/requests/callback — ログイン後の着地点。fragment / cookie → sessionStorage → /admin/requests
 */

import type { Env } from "../index";
import { renderAdminRequestsPage } from "../lib/admin-requests-html";
import { renderAdminCallbackPage } from "../lib/admin-callback-html";

/** GET /admin/requests — 常に HTML を返す（認証チェックは JS 側） */
export async function handleAdminRequestsPage(
  _request: Request,
  _env: Env,
): Promise<Response> {
  const html = renderAdminRequestsPage();
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

/** GET /admin/requests/callback — fragment から token を sessionStorage に保存して /admin/requests へ */
export async function handleAdminRequestsCallback(): Promise<Response> {
  return new Response(renderAdminCallbackPage("/admin/requests"), {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
