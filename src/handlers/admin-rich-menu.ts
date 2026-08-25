/**
 * Admin Rich Menu page handlers
 *
 * /admin/rich-menu          — 静的 HTML 配信（認証は JS 側の共通門番 = cookie → sessionStorage）
 * /admin/rich-menu/callback — ログイン後の着地点。fragment / cookie → sessionStorage → /admin/rich-menu
 */

import type { Env } from "../index";
import { renderAdminRichMenuPage } from "../lib/admin-rich-menu-html";
import { renderAdminCallbackPage } from "../lib/admin-callback-html";

/** GET /admin/rich-menu — 常に HTML を返す（認証チェックは JS 側） */
export async function handleAdminRichMenuPage(
  _request: Request,
  _env: Env,
): Promise<Response> {
  const html = renderAdminRichMenuPage();
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

/** GET /admin/rich-menu/callback — fragment から token を sessionStorage に保存して /admin/rich-menu へ */
export async function handleAdminRichMenuCallback(): Promise<Response> {
  return new Response(renderAdminCallbackPage("/admin/rich-menu"), {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
