/**
 * /admin/notify — notify recipient / group management
 *
 * /admin/notify          — 静的 HTML 配信 (認証は JS 側の共通門番 = cookie → sessionStorage)
 * /admin/notify/callback — ログイン後の着地点 (fragment / cookie → sessionStorage → /admin/notify)
 */

import type { Env } from "../index";
import { renderAdminNotifyPage } from "../lib/admin-notify-html";
import { renderAdminCallbackPage } from "../lib/admin-callback-html";

export async function handleAdminNotifyPage(
  _request: Request,
  env: Env,
): Promise<Response> {
  const html = renderAdminNotifyPage(env.ALC_API_ORIGIN);
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

export async function handleAdminNotifyCallback(): Promise<Response> {
  return new Response(renderAdminCallbackPage("/admin/notify"), {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
