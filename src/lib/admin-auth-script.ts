/**
 * admin ページ共通の門番 (client-side auth token 解決) スクリプト。
 *
 * Refs #474: admin 画面が Google ログイン無限ループに落ちた原因。
 *
 * `google-callback.ts` は **redirect 先が共有 cookie の届くホストなら token を
 * fragment に載せず `Set-Cookie` だけで返す** (`authCookieReachesHost`、アドレスバー /
 * 履歴に token を出さないための設計)。admin 系ページは全て auth-worker 自身のホスト
 * 上にあるので必ずこの分岐に入る。にもかかわらずページ JS の門番が
 * `sessionStorage.auth_token` を先に (notify に至っては専らそれだけを) 見ていたため、
 * cookie で届いた token を拾えず `/login` へ跳ね返し続けていた。
 *
 * ここで解決順を **cookie → sessionStorage** に統一する:
 *
 *   - cookie (`logi_auth_token`) が正。`cookies.ts` の `AUTH_COOKIE` を生成時に
 *     埋め込むので、ページ JS 側に cookie 名のハードコードを増やさない。
 *   - sessionStorage (`auth_token`) は後方互換 (fragment 配送のホスト / 旧タブ) として残す。
 *   - 同名 cookie が複数届くケース (host-only と Domain 付きの併存、Refs #387) に備えて
 *     **全候補**を走査し、期限切れでないものを選ぶ (先頭固定の正規表現では有効な
 *     cookie が古い方の陰に隠れる)。
 *   - 期限切れしか無ければ「無い」扱いにして `/login` へ送る (再ログインで新しい
 *     cookie が載るのでループしない)。署名不正の毒 cookie は client 側では判別
 *     できないので通し、API の 401 として各ページの既存ハンドリングに委ねる。
 *
 * 公開 API は `window.__adminAuth`:
 *   - `readToken()`      → string | null   (cookie → sessionStorage)
 *   - `requireToken(cb)` → string | null   (無ければ `/login?redirect_uri=<cb>` へ replace)
 *   - `rememberToken(t)` → void            (sessionStorage への後方互換ミラー)
 *   - `loginUrl(cb)`     → string
 */
import { AUTH_COOKIE, LEGACY_ADMIN_COOKIE } from "./cookies";

/** admin ページ JS から見た門番のグローバル名 */
export const ADMIN_AUTH_GLOBAL = "__adminAuth";

/**
 * 門番スクリプト本体 (`<script>` タグ込み)。各 admin ページ / callback ページの
 * HTML に、ページ固有 script より **前** に埋め込む。
 */
export function renderAdminAuthScript(): string {
  return `<script>
(function () {
  var COOKIE_NAME = ${JSON.stringify(AUTH_COOKIE)};
  var LEGACY_COOKIE_NAME = ${JSON.stringify(LEGACY_ADMIN_COOKIE)};

  /** JWT の exp (秒) を署名検証せず読む。読めなければ null (= 期限不明)。 */
  function expOf(token) {
    try {
      var parts = String(token).split('.');
      if (parts.length !== 3) return null;
      var b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      var payload = JSON.parse(atob(b64));
      return typeof payload.exp === 'number' ? payload.exp : null;
    } catch (e) {
      return null;
    }
  }

  /** 期限が読めて、かつ既に過ぎている時だけ true (期限不明は使える扱い)。 */
  function isExpired(token) {
    var exp = expOf(token);
    return exp !== null && exp * 1000 <= Date.now();
  }

  /** 同名 cookie の値を **全て** 返す (#387 の shadowing 対策)。 */
  function cookieValues(name) {
    var out = [];
    var pairs = String(document.cookie || '').split(';');
    for (var i = 0; i < pairs.length; i++) {
      var eq = pairs[i].indexOf('=');
      if (eq < 0) continue;
      if (pairs[i].slice(0, eq).trim() !== name) continue;
      var value = pairs[i].slice(eq + 1).trim();
      if (!value) continue;
      if (value.indexOf('%') >= 0) {
        try { value = decodeURIComponent(value); } catch (e) { /* raw のまま使う */ }
      }
      out.push(value);
    }
    return out;
  }

  function fromCookie() {
    var values = cookieValues(COOKIE_NAME).concat(cookieValues(LEGACY_COOKIE_NAME));
    for (var i = 0; i < values.length; i++) {
      if (!isExpired(values[i])) return values[i];
    }
    return null;
  }

  function fromSession() {
    try {
      var token = sessionStorage.getItem('auth_token');
      return token && !isExpired(token) ? token : null;
    } catch (e) {
      return null;
    }
  }

  /** cookie 優先 → sessionStorage (後方互換)。どちらも無ければ null。 */
  function readToken() {
    return fromCookie() || fromSession() || null;
  }

  /** sessionStorage への後方互換ミラー (cookie を読めないページ用)。 */
  function rememberToken(token) {
    try {
      if (token) sessionStorage.setItem('auth_token', token);
    } catch (e) { /* private mode 等では諦める */ }
  }

  function loginUrl(callback) {
    var cb = String(callback);
    if (cb.indexOf('://') < 0) cb = window.location.origin + cb;
    return '/login?redirect_uri=' + encodeURIComponent(cb);
  }

  /** token が無ければ /login へ飛ばして null を返す (呼び出し側は即 return する)。 */
  function requireToken(callback) {
    var token = readToken();
    if (token) {
      rememberToken(token);
      return token;
    }
    window.location.replace(loginUrl(callback));
    return null;
  }

  window.${ADMIN_AUTH_GLOBAL} = {
    readToken: readToken,
    requireToken: requireToken,
    rememberToken: rememberToken,
    loginUrl: loginUrl
  };
})();
</script>`;
}
