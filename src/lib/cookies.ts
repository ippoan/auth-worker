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

/** Extract auth token from request Cookie header */
export function getAuthCookie(request: Request): string | null {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/logi_auth_token=([^;]+)/);
  return match?.[1] ?? null;
}
