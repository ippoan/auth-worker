import type { Env } from "../index";
import { getAllowedOrigins } from "../lib/config";
import { isAllowedRedirectUri } from "../lib/security";
import { authCookieReachesHost, AUTH_COOKIE } from "../lib/cookies";

/** GET /redirect?to=<target_url>
 *
 * sessionStorage / cookie からトークンを読み取り、ターゲットアプリへリダイレクト
 * する中間ページ。
 *
 * - target が共有 cookie (logi_auth_token, Domain=親ドメイン) の届く host なら、
 *   token を URL fragment に **載せず** cookie だけで渡す (アドレスバー / 履歴に
 *   token を出さない)。app 側は consumeFragment ではなく recoverFromCookie で受ける。
 * - 届かない host (例: `*.workers.dev` は public suffix で Domain cookie 不可) は
 *   従来どおり `?lw_callback#token=` の fragment で配布する (consumeFragment で受ける)。
 * - token がない場合は /login にリダイレクト。
 *
 * 同型の cookie-vs-fragment 分岐は google-callback.ts にもある (authCookieReachesHost)。
 */
export async function handleRedirect(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const target = url.searchParams.get("to");

  if (!target || !isAllowedRedirectUri(target, await getAllowedOrigins(env))) {
    return new Response("Invalid redirect target", { status: 400 });
  }

  // 共有 cookie が target host に届くか (= URL に token を出さず cookie で渡せるか)。
  const cookieHandoff = authCookieReachesHost(url.hostname, new URL(target).hostname);

  const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body>
<script>
(function() {
  var target = ${JSON.stringify(target)};
  var cookieHandoff = ${cookieHandoff ? "true" : "false"};
  var token = sessionStorage.getItem('auth_token');
  if (!token) {
    var m = document.cookie.match(/${AUTH_COOKIE}=([^;]+)/);
    if (m) token = decodeURIComponent(m[1]);
  }
  if (!token) {
    window.location.replace('/login?redirect_uri=' + encodeURIComponent(target));
    return;
  }
  if (cookieHandoff) {
    // 共有 cookie が target に届く → token を URL に出さず cookie で渡す。
    // sessionStorage 由来で親ドメイン cookie が未設定のケースに備え、ここで保証する。
    var host = window.location.hostname;
    var parts = host.split('.');
    var domain = parts.length > 2 ? '.' + parts.slice(-2).join('.') : host;
    document.cookie = '${AUTH_COOKIE}=' + token + '; Domain=' + domain + '; Path=/; Max-Age=86400; Secure; SameSite=Lax';
    window.location.replace(target);
  } else {
    var sep = target.includes('?') ? '&' : '?';
    window.location.replace(target + sep + 'lw_callback#token=' + encodeURIComponent(token));
  }
})();
</script>
</body></html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
