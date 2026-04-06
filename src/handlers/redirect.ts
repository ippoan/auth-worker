import type { Env } from "../index";
import { isAllowedRedirectUri } from "../lib/security";

/** GET /redirect?to=<target_url>
 *
 * sessionStorage からトークンを読み取り、ターゲットアプリに
 * URL フラグメント (#token=xxx) 付きでリダイレクトする中間ページ。
 * トークンがない場合は /login にリダイレクト。
 */
export async function handleRedirect(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const target = url.searchParams.get("to");

  if (!target || !isAllowedRedirectUri(target, env.ALLOWED_REDIRECT_ORIGINS)) {
    return new Response("Invalid redirect target", { status: 400 });
  }

  const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body>
<script>
(function() {
  var target = ${JSON.stringify(target)};
  var token = sessionStorage.getItem('auth_token');
  if (token) {
    window.location.replace(target + '#token=' + encodeURIComponent(token));
  } else {
    window.location.replace('/login?redirect_uri=' + encodeURIComponent(target));
  }
})();
</script>
</body></html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
