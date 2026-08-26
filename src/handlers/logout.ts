/**
 * GET /logout — sessionStorage + cookie クリア → ログインページへリダイレクト
 *
 * sessionStorage はサーバーサイドからクリアできないため、
 * HTML ページを返して JS で実行する。
 *
 * **最後の遷移先は Cloudflare Access のログアウト経由になる** (Refs #477)。
 * `ACCESS_TEAM_DOMAIN` が設定されていて、戻り先が自分たちのホストの https URL で、
 * かつ **直前に `/logout` を通っていない**ときだけ chain する。理由・`returnTo` の
 * 実測制約・ループガードは `src/lib/access-logout.ts` に書いてある。
 */

import type { Env } from "../index";
import {
  accessLogoutChainMarkerCookie,
  hasAccessLogoutChainMarker,
  logoutNavigationTarget,
} from "../lib/access-logout";
import { clearAuthCookieVariants } from "../lib/cookies";

export async function handleLogout(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const redirectTo = url.searchParams.get("redirect_uri") || "/login";

  // cookie 破棄 (この応答の Set-Cookie) → Access ログアウト → 本来の戻り先、の順。
  // 逆順にすると Access から戻ってきた時点で cookie がまだ生きており、
  // `/oidc/authorize` が silent に通して「再ログイン」にならない。
  const { target: navigateTo } = logoutNavigationTarget(
    url.origin,
    url.hostname,
    redirectTo,
    env.ACCESS_TEAM_DOMAIN,
    hasAccessLogoutChainMarker(request),
  );

  // Escape for safe embedding in JS string
  const safeRedirect = navigateTo.replace(/\\/g, "\\\\").replace(/'/g, "\\'").replace(/"/g, '\\"');

  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Logging out...</title></head>
<body>
<script>
  sessionStorage.removeItem('auth_token');
  localStorage.removeItem('logi_auth');
  // backward compat: clear cookies (no Domain attr = same-host)
  document.cookie = 'sso_admin_token=; Path=/admin; Max-Age=0; Secure; SameSite=Lax';
  document.cookie = 'logi_auth_token=; Path=/; Max-Age=0; Secure; SameSite=Lax';
  window.location.replace('${safeRedirect}');
</script>
</body></html>`;

  const headers = new Headers({ "Content-Type": "text/html; charset=utf-8" });
  for (const c of clearAuthCookieVariants(new URL(request.url).hostname)) {
    headers.append("Set-Cookie", c);
  }
  // ループガードのマーカーは **chain したかどうかに関わらず張り直す**。
  // 見張りたいのは「Access を切ったか」ではなく「直前にも /logout に来たか」で、
  // ループ中は毎周ここを通るため、更新し続ける方が確実に止まる。
  headers.append("Set-Cookie", accessLogoutChainMarkerCookie());

  return new Response(html, { headers });
}
