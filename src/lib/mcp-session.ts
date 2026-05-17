/**
 * MCP OAuth Provider — auth-worker 側ブラウザ sticky session cookie (issue #144)。
 *
 * 既存の `/mcp/authorize` → `/mcp/auth_callback` flow は client redirect で
 * auth code を発行するだけで、auth-worker 自身は browser session を保持しない。
 * 1-click pair (#144) では「ブラウザが auth.ippoan.org に対して `session_github_login`
 * を主張できる」状態が必要なので、ここで HMAC-signed session cookie を導入する。
 *
 * Scope はあくまで **pair 用の短命 session** (30 分)。既存 Google/LineWorks 等の
 * login 用 cookie とは完全に独立 (`logi_auth_token` などは別 path / 別 JWT)。
 *
 * Cookie 形式:
 *   `mcp_pair_session = <base64url(payload)>.<hmac>`
 *   payload = { github_login, iat, exp } (秒)
 *
 * 設定: `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`。
 */

export interface PairSessionPayload {
  github_login: string;
  iat: number; // seconds (Unix epoch)
  exp: number; // seconds (Unix epoch)
}

export const PAIR_SESSION_COOKIE_NAME = "mcp_pair_session";
export const PAIR_SESSION_TTL_SEC = 60 * 30; // 30 min

/**
 * HMAC-SHA256 で `<payloadB64>.<sig>` 形式に sign する。
 * `secret` が空なら throw (上位 handler で 503 を返す前提)。
 */
export async function signPairSession(
  github_login: string,
  secret: string,
  ttlSec: number = PAIR_SESSION_TTL_SEC,
): Promise<string> {
  if (!secret) throw new Error("SESSION_COOKIE_SECRET not configured");
  const now = Math.floor(Date.now() / 1000);
  const payload: PairSessionPayload = {
    github_login,
    iat: now,
    exp: now + ttlSec,
  };
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const sig = await hmacSign(payloadB64, secret);
  return `${payloadB64}.${sig}`;
}

/**
 * `<payloadB64>.<sig>` を verify + parse する。
 * 不正 / 期限切れ / secret 空 → null。
 */
export async function verifyPairSession(
  cookieValue: string,
  secret: string,
): Promise<PairSessionPayload | null> {
  if (!secret) return null;
  const dot = cookieValue.indexOf(".");
  if (dot === -1) return null;
  const payloadB64 = cookieValue.substring(0, dot);
  const sig = cookieValue.substring(dot + 1);
  const expected = await hmacSign(payloadB64, secret);
  if (!constantTimeEqual(sig, expected)) return null;
  let payload: PairSessionPayload;
  try {
    payload = JSON.parse(base64UrlDecode(payloadB64)) as PairSessionPayload;
  } catch {
    return null;
  }
  if (typeof payload.exp !== "number") return null;
  if (payload.exp <= Math.floor(Date.now() / 1000)) return null;
  if (typeof payload.github_login !== "string" || !payload.github_login) return null;
  return payload;
}

/**
 * `Cookie` header から `mcp_pair_session` の値を抽出する。
 * 複数 cookie が ; で区切られている前提。見つからなければ null。
 */
export function readPairSessionCookie(cookieHeader: string | null): string | null {
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(/;\s*/);
  for (const p of parts) {
    const eq = p.indexOf("=");
    if (eq === -1) continue;
    const name = p.substring(0, eq);
    if (name === PAIR_SESSION_COOKIE_NAME) {
      return p.substring(eq + 1);
    }
  }
  return null;
}

/** `Set-Cookie` 値を構築 (Secure/HttpOnly/SameSite=Lax)。 */
export function buildSetCookie(value: string, maxAgeSec: number = PAIR_SESSION_TTL_SEC): string {
  return `${PAIR_SESSION_COOKIE_NAME}=${value}; Path=/; Max-Age=${maxAgeSec}; Secure; HttpOnly; SameSite=Lax`;
}

async function hmacSign(data: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return base64UrlEncodeBytes(new Uint8Array(sig));
}

function base64UrlEncode(s: string): string {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] as number);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(data: string): string {
  const base64 = data.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  return atob(padded);
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
