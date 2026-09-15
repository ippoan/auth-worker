/**
 * `logi_auth_token` (等) cookie を読んで期限内の JWT を選ぶ、ページ共通の
 * ブラウザ inline JS snippet。
 *
 * auth-worker の HTML ページは TS の中で文字列を組み立てて inline `<script>` に
 * 埋める作りで、実行時に npm package を import できない。そのため「同名 cookie を
 * 全部走査し、exp 内の JWT を選ぶ」ロジックが `/top` (`top-html.ts`) と admin 門番
 * (`admin-auth-script.ts`) の 2 本に別々に実装されていて、#529 の base64url 対応が
 * 片方にしか入らない、といった修正漏れが起きていた (Refs #475, #529, #531, #533,
 * ippoan/auth-worker#560)。ここに 1 本化し、以後の修正を 1 か所で済ませる。
 *
 * `decodeJwtPayload` は `packages/auth-client/src/jwt-core.mjs` の
 * `decodeJwtPayload` と同一仕様 (再実装ではなく、ブラウザ inline 用の写し)。
 * 仕様を変えるときは両方を直すこと。
 */
import { AUTH_COOKIE } from "./cookies";

/** ページ JS から見たグローバル名 (`window[AUTH_COOKIE_GLOBAL]`)。 */
export const AUTH_COOKIE_GLOBAL = "__ippoanAuthCookie";

/**
 * `<script>` タグ無しの JS 断片。ページ固有 script より **前** に埋める。
 *
 * `window[AUTH_COOKIE_GLOBAL]` として公開する API:
 *   - `decodeJwtPayload(token) → object | null`
 *   - `cookieValues(name) → string[]`
 *   - `findValidToken(names, nowSec) → string | null`
 *   - `isValidToken(token, nowSec) → boolean`
 *
 * cookie 名の既定は埋め込まない — 呼び出し側が `AUTH_COOKIE` 等の名前配列を渡す。
 * ES5 風 (`var` / function 宣言) で書く (admin 側の既存 snippet に合わせる)。
 * 埋め込み先がテンプレートリテラルなので、snippet 内では backtick と `${` を
 * 使わない。
 */
export function renderAuthCookieScript(): string {
  return `
(function () {
  /**
   * JWT payload (2番目のセグメント) を decode する。JWT は base64url
   * (jwt.ts の base64UrlEncodeStr が出す形式、-/_ を含みうる) だが、
   * ブラウザ標準の atob は標準base64しか読めず、payload に -/_ が乗ると
   * InvalidCharacterError を投げる (Refs #529)。サーバー側の
   * base64UrlDecodeUtf8 (jwt.ts) と同じ変換をクライアントにも持たせる。
   * 壊れていれば null。
   */
  function decodeJwtPayload(token) {
    try {
      var parts = String(token).split('.');
      if (parts.length !== 3) return null;
      var b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      // atob は latin1 解釈なので name 等の多バイト claim がそのままだと
      // mojibake になる。TextDecoder を挟んで UTF-8 として読み直す
      // (jwt.ts の base64UrlDecodeUtf8 と同型)。
      var binary = atob(b64);
      var bytes = Uint8Array.from(binary, function (c) { return c.charCodeAt(0); });
      return JSON.parse(new TextDecoder().decode(bytes));
    } catch (e) {
      return null;
    }
  }

  /**
   * 同名 cookie の値を **全て** 返す (#387 の shadowing 対策: host-only cookie と
   * Domain 付き cookie は別物としてブラウザが両方送るため、先頭だけ見ると
   * 有効な cookie が古い方の陰に隠れる)。
   */
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

  /** token が JWT として decode でき、かつ exp が nowSec より先なら true。 */
  function isValidToken(token, nowSec) {
    var p = decodeJwtPayload(token);
    return !!p && typeof p.exp === 'number' && p.exp > nowSec;
  }

  /**
   * names (配列) の順に cookie 候補を集め、有効な (decode でき、exp が
   * nowSec より先の) 最初の値を返す。無ければ null。
   */
  function findValidToken(names, nowSec) {
    var values = [];
    for (var i = 0; i < names.length; i++) {
      values = values.concat(cookieValues(names[i]));
    }
    for (var j = 0; j < values.length; j++) {
      if (isValidToken(values[j], nowSec)) return values[j];
    }
    return null;
  }

  window.${AUTH_COOKIE_GLOBAL} = {
    decodeJwtPayload: decodeJwtPayload,
    cookieValues: cookieValues,
    findValidToken: findValidToken,
    isValidToken: isValidToken
  };
})();
`;
}

// AUTH_COOKIE は呼び出し側 (top-html.ts / admin-auth-script.ts) が名前配列を
// 組み立てるときに使う想定の re-export。snippet 自体には cookie 名を埋め込まない。
export { AUTH_COOKIE };
