/**
 * /admin/notify — notify recipient / group management
 *
 * /admin/notify          — 静的 HTML 配信 (認証は JS 側で sessionStorage チェック)
 * /admin/notify/callback — ログイン後の着地点 (fragment → sessionStorage → /admin/notify)
 */

import type { Env } from "../index";
import { renderAdminNotifyPage } from "../lib/admin-notify-html";

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
      window.location.replace('/admin/notify');
    } else {
      window.location.replace('/admin/notify');
    }
  } else {
    window.location.replace('/admin/notify');
  }
</script>
</body></html>`;
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
