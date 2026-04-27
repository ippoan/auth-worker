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
 */
export async function verifyJwt(
  token: string,
  secret: string,
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

  return payload;
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
