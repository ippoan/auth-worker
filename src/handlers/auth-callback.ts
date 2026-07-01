/**
 * GET /auth/callback — auth-worker 自身が LINE 招待などの遷移先 (redirect_uri) に
 * なった場合の着地点。
 *
 * 招待UI (admin-line-users) は遷移先を `<origin>/auth/callback` で一律に組む
 * (auth-client の AuthCallback ルート規約)。consumer app は `pages/auth/callback.vue`
 * で受けるが、auth-worker 自身の origin が遷移先になるケースでは auth-worker 側にも
 * 同名ルートが必要 (無いと 404。Refs LINE ログインループ調査)。
 *
 * **セキュリティ設計 (重要)**: access token は `issueLineJwt` が **Set-Cookie**
 * (`logi_auth_token`, Domain=親ドメイン) で既にブラウザに配布済み。したがって本
 * ハンドラは:
 *   - URL fragment (`#token=...`) の token を **読まない / cookie に植えない**
 *     (fragment 由来 token の cookie 混入 = session fixation / cookie attribute
 *     injection、および inline script への反射 = XSS を回避)
 *   - `?to=` 等の **ユーザー入力を一切遷移先に反射しない** (open-redirect / XSS 回避)
 * fragment を URL から除去して、server-gate 付きの固定パス `/top` へ遷移するだけ。
 * `/top` の server-side ゲートが cookie の JWT を検証して描画する。
 */
export function handleAuthCallback(): Response {
  // 遷移先は固定 (/top)。ユーザー入力を反射しないため inline script は静的
  // (token も読まない = cookie で受領済み)。fragment は replaceState で URL から除去。
  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>認証中...</title></head>
<body>
<script>
(function () {
  // 認証 cookie は発行時に既にセット済み。URL の fragment を残さず /top へ遷移する
  // (fragment の値を読まない・cookie に書かない = XSS/session fixation 回避)。
  try { history.replaceState(null, "", "/top"); } catch (e) {}
  window.location.replace("/top");
})();
</script>
</body></html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
