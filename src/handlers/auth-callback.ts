/**
 * GET /auth/callback — auth-worker 自身が LINE 招待などの遷移先 (redirect_uri) に
 * なった場合の着地点。
 *
 * 招待UI (admin-line-users) は遷移先を `<origin>/auth/callback` で一律に組む
 * (auth-client の AuthCallback ルート規約)。consumer app は `pages/auth/callback.vue`
 * で受けるが、auth-worker 自身の origin が遷移先になるケース (allowlist に自 origin が
 * 含まれる / 単一 origin fallback) では auth-worker 側にも同名ルートが必要
 * (無いと 404。Refs LINE ログインループ調査)。
 *
 * fragment (`#token=...`) の token を共有 cookie (`logi_auth_token`, Domain=親ドメイン)
 * に client-side で保存してから、server-gate 付きの `/top` へ遷移する。/top の
 * server-side ゲートは cookie の JWT を検証するため、cookie さえ載れば描画される。
 * `?to=<relative-path>` で着地先を上書き可 (open-redirect 防止のため `/` 始まりのみ許可)。
 */
export async function handleAuthCallback(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const toParam = url.searchParams.get("to");
  const dest = toParam && toParam.startsWith("/") ? toParam : "/top";

  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>認証中...</title></head>
<body>
<script>
(function () {
  var dest = ${JSON.stringify(dest)};
  var hash = window.location.hash;
  if (hash && hash.indexOf('token=') >= 0) {
    var params = new URLSearchParams(hash.slice(1));
    var token = params.get('token');
    if (token) {
      // 共有 cookie (Domain=親ドメイン) をセットして /top の server ゲートに渡す。
      var host = window.location.hostname;
      var parts = host.split('.');
      var domain = parts.length > 2 ? '.' + parts.slice(-2).join('.') : host;
      document.cookie = 'logi_auth_token=' + token + '; Domain=' + domain +
        '; Path=/; Max-Age=86400; Secure; SameSite=Lax';
      try { sessionStorage.setItem('auth_token', token); } catch (e) {}
    }
  }
  window.location.replace(dest);
})();
</script>
</body></html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
