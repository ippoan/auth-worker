/**
 * Cookie helpers for logi_auth_token
 */

export const AUTH_COOKIE = "logi_auth_token";

/**
 * 旧 admin 画面が使っていた cookie 名 (Path=/admin)。現在は発行しておらず
 * `/logout` が破棄するだけだが、admin ページの門番 (`admin-auth-script.ts`) が
 * 後方互換で読むため定数として持つ (ページ JS 側にハードコードを増やさない)。
 */
export const LEGACY_ADMIN_COOKIE = "sso_admin_token";

/** Set-Cookie header value for auth token (24h, shared across subdomains) */
export function setAuthCookie(token: string, hostname: string): string {
  const domain = getParentDomain(hostname);
  return `${AUTH_COOKIE}=${token}; Domain=${domain}; Path=/; Max-Age=86400; Secure; SameSite=Lax`;
}

/** Set-Cookie header value to clear auth token */
export function clearAuthCookie(hostname: string): string {
  const domain = getParentDomain(hostname);
  return `${AUTH_COOKIE}=; Domain=${domain}; Path=/; Max-Age=0; Secure; SameSite=Lax`;
}

/** Extract parent domain from hostname (e.g. auth.ippoan.org → .ippoan.org) */
function getParentDomain(hostname: string): string {
  const parts = hostname.split(".");
  return parts.length > 2 ? "." + parts.slice(-2).join(".") : hostname;
}

/**
 * 共有 auth cookie (logi_auth_token, Domain=親ドメイン) が target host にも届くか。
 * true の場合、OAuth callback は token を URL fragment に載せず cookie だけで渡せる
 * (= アドレスバー/履歴に token を出さない)。false の場合は fragment 配布が必要
 * (例: `*.workers.dev` / `*.pages.dev` は public suffix で Domain cookie が設定不可)。
 *
 * 判定: auth-worker host と target host が同じ親ドメイン配下で、その親ドメインが
 * public suffix でないこと。
 */
const PUBLIC_SUFFIX_PARENTS = [".workers.dev", ".pages.dev"];

export function authCookieReachesHost(authHostname: string, targetHostname: string): boolean {
  const domain = getParentDomain(authHostname);
  if (!domain.startsWith(".")) return false; // 単一ラベル / localhost 等は共有 cookie 不可
  if (PUBLIC_SUFFIX_PARENTS.includes(domain)) return false; // public suffix → Domain cookie 拒否
  return targetHostname === domain.slice(1) || targetHostname.endsWith(domain);
}

/** Extract auth token from request Cookie header */
export function getAuthCookie(request: Request): string | null {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/logi_auth_token=([^;]+)/);
  return match?.[1] ?? null;
}

/**
 * 同名 cookie (logi_auth_token) を **全て** 返す (Refs #387)。
 *
 * host-only cookie と Domain 付き cookie は別物としてブラウザが両方送るため、
 * 古い方が先頭に来ると `getAuthCookie` (先頭のみ) では有効な cookie が
 * 陰に隠れる (shadowing)。login-gated ページは全候補を verify すること。
 */
export function getAuthCookies(request: Request): string[] {
  const cookie = request.headers.get("Cookie") || "";
  const out: string[] = [];
  const re = /logi_auth_token=([^;]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(cookie)) !== null) out.push(m[1]!);
  return out;
}

/**
 * 検証に落ちた cookie の自動破棄用 Set-Cookie 群 (Refs #387)。
 *
 * setAuthCookie は Domain=親ドメインで set するが、過去版や別経路が残した
 * host-only cookie も同時に破棄できるよう **Domain 付き / 無しの両方**を返す。
 * 毒 cookie (期限切れ / env claim 不一致 / 署名不正) を手動 logout に頼らず
 * 回収するため、login-gated ページの「cookie 有り + 検証全滅」応答に付ける。
 */
export function clearAuthCookieVariants(hostname: string): string[] {
  return [
    clearAuthCookie(hostname),
    `${AUTH_COOKIE}=; Path=/; Max-Age=0; Secure; SameSite=Lax`,
  ];
}
