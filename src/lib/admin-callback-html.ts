/**
 * admin ページのログイン着地点 (`/admin/<page>/callback`) 共通 HTML。
 *
 * Refs #474: 旧実装は **`location.hash` の `token=` しか見ず**、hash が無ければ
 * 何も保存せずに元ページへ戻していた。auth-worker 自身のホストへ戻るとき
 * `google-callback.ts` は fragment を付けず `Set-Cookie` だけで token を渡すので、
 * 「callback は素通し → ページの門番が token 無しと判定 → /login」の無限ループになる。
 *
 * ここでは fragment / cookie のどちらで届いても正常着地として扱う:
 *   1. fragment に token があれば sessionStorage へ (cookie が届かないホスト経由の従来経路)
 *   2. 無ければ cookie (`__adminAuth.readToken`) を sessionStorage にミラー
 *   3. どちらも無ければ従来どおり元ページへ戻す (門番が /login へ送る)
 */
import { renderAdminAuthScript } from "./admin-auth-script";

/**
 * @param targetPath ログイン後に戻すページの path (例: `/admin/notify`)
 */
export function renderAdminCallbackPage(targetPath: string): string {
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Redirecting...</title></head>
<body>
${renderAdminAuthScript()}
<script>
(function () {
  var target = ${JSON.stringify(targetPath)};
  var token = null;
  var hash = window.location.hash || '';
  if (hash.indexOf('token=') >= 0) {
    token = new URLSearchParams(hash.slice(1)).get('token');
  }
  // #474: fragment が無くても cookie で届いていれば正常着地。
  if (!token) token = window.__adminAuth.readToken();
  if (token) window.__adminAuth.rememberToken(token);
  window.location.replace(target);
})();
</script>
</body></html>`;
}
