/**
 * HS256 JWT verification (Web Crypto API).
 *
 * Used by /top server-side gate. JWT_SECRET is shared with rust-alc-api so
 * tokens issued there verify here.
 */

export interface JwtPayload {
  exp?: number;
  [key: string]: unknown;
}

/**
 * Verify an HS256 JWT. Returns the decoded payload on success, or null if
 * malformed, signed with the wrong secret, expired, or missing `exp`.
 *
 * Refs #218: `expectedEnv` を渡すと、payload に `env` claim がある場合に
 * 一致を強制する (= cross-env token replay 防止)。
 *   - `payload.env` が文字列で expectedEnv と不一致 → null (reject)
 *   - `payload.env` が無い (= 旧 token) → 通す (backward compat)
 *   - expectedEnv 自体が undefined → env チェック skip
 * deploy 後 1h で旧 token (env なし) は expire するので実質必須化と等価。
 */
export async function verifyJwt(
  token: string,
  secret: string,
  expectedEnv?: string,
): Promise<JwtPayload | null> {
  if (!secret) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const headerB64 = parts[0]!;
  const payloadB64 = parts[1]!;
  const signatureB64 = parts[2]!;

  let header: { alg?: string };
  try {
    header = JSON.parse(base64UrlDecode(headerB64));
  } catch {
    return null;
  }
  if (header.alg !== "HS256") return null;

  const expected = await hmacSign(`${headerB64}.${payloadB64}`, secret);
  if (!constantTimeEqual(signatureB64, expected)) return null;

  let payload: JwtPayload;
  try {
    payload = JSON.parse(base64UrlDecode(payloadB64)) as JwtPayload;
  } catch {
    return null;
  }

  if (typeof payload.exp !== "number") return null;
  if (payload.exp <= Math.floor(Date.now() / 1000)) return null;

  if (expectedEnv !== undefined && typeof payload.env === "string" && payload.env !== expectedEnv) {
    return null;
  }

  return payload;
}

/**
 * Sign an HS256 JWT (Web Crypto)。`verifyJwt` が受理する形式と対。
 *
 * Refs rust-alc-api#434: rust-alc-api は #441 で JWT 検証をやめた dumb backend に
 * なったため、/top + introspect が検証する cookie JWT は auth-worker が署名・所有
 * する。payload に `env` claim (= WORKER_ENV) を入れると cross-env replay を弾ける
 * (#218)。`exp` は呼び出し側が payload に含めて渡す。
 */
export async function signJwt(payload: JwtPayload, secret: string): Promise<string> {
  const headerB64 = base64UrlEncodeStr(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payloadB64 = base64UrlEncodeStr(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = await hmacSign(signingInput, secret);
  return `${signingInput}.${signature}`;
}

/**
 * JWT の payload を **署名検証せず** に decode する (UTF-8 safe)。再署名時に
 * 元 token の claims を取り出す用途 (検証自体は別途 `verifyJwt`)。malformed は null。
 */
export function decodeJwtPayload(token: string): JwtPayload | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(base64UrlDecodeUtf8(parts[1]!)) as JwtPayload;
  } catch {
    return null;
  }
}

async function hmacSign(data: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data),
  );
  return base64UrlEncodeBytes(new Uint8Array(signature));
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** UTF-8 文字列 → base64url (signJwt の header/payload encode 用)。 */
function base64UrlEncodeStr(s: string): string {
  return base64UrlEncodeBytes(new TextEncoder().encode(s));
}

/** base64url → UTF-8 文字列 (decodeJwtPayload 用、多バイト claim を保つ)。 */
function base64UrlDecodeUtf8(data: string): string {
  const base64 = data.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
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
