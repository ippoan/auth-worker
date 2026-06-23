/**
 * Cookie helpers for logi_auth_token
 */

export const AUTH_COOKIE = "logi_auth_token";

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
