/**
 * MCP OAuth Provider — HS256 JWT sign/verify for MCP access tokens.
 *
 * 既存 `src/lib/jwt.ts` は rust-alc-api 共有の `JWT_SECRET` で署名されたトークンを
 * verify する用途で、sign 関数を持たない。Phase 3 では MCP access_token を発行する
 * 必要があり、claims (sub / github_login / scope / aud / exp / iat) も MCP 固有なので
 * 専用 file として切る。
 *
 * - Algorithm: HS256 のみ (header.alg 厳格 check)
 * - Secret: `env.MCP_JWT_SECRET` (既存 JWT_SECRET と別管理)
 * - exp / iat は 秒単位 (Unix timestamp)
 * - audience は呼び出し側が `expectedAud` で strict 検証可能
 *
 * Phase 6 で `jwt.ts` と shared hmac/base64 helper を extract する候補。Phase 3 では
 * 最小 PR + 100% coverage 安定性を優先し self-contained 実装。
 */

export interface McpJwtPayload {
  sub: string;
  github_login: string;
  scope: string;
  aud: string;
  exp: number; // seconds (Unix epoch)
  iat: number; // seconds (Unix epoch)
}

/**
 * Sign HS256 JWT with `secret`. `exp` is computed as `now + ttlSec`. `iat` is `now`.
 * `secret` が falsy なら throw する (上位 handler が 500 を返す前提)。
 */
export async function signMcpJwt(
  claims: Omit<McpJwtPayload, "exp" | "iat">,
  secret: string,
  ttlSec: number,
): Promise<string> {
  if (!secret) throw new Error("MCP_JWT_SECRET not configured");
  const now = Math.floor(Date.now() / 1000);
  const payload: McpJwtPayload = {
    ...claims,
    iat: now,
    exp: now + ttlSec,
  };
  const headerB64 = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const signature = await hmacSign(`${headerB64}.${payloadB64}`, secret);
  return `${headerB64}.${payloadB64}.${signature}`;
}

/**
 * Verify HS256 JWT with `secret` and check `payload.aud` + `exp`。
 * `expectedAud`:
 *  - `string`        — 完全一致
 *  - `string[]`      — いずれかと完全一致
 *  - `(aud) => bool` — 任意の述語 (RFC 8707 で aud が URL かつ origin 一致など、
 *                      strict 同値判定にならないケース用)
 * 不正 (alg mismatch / signature 不一致 / expired / aud 不一致) → null。
 */
export async function verifyMcpJwt(
  token: string,
  secret: string,
  expectedAud: string | readonly string[] | ((aud: string) => boolean),
): Promise<McpJwtPayload | null> {
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

  let payload: McpJwtPayload;
  try {
    payload = JSON.parse(base64UrlDecode(payloadB64)) as McpJwtPayload;
  } catch {
    return null;
  }
  if (typeof payload.exp !== "number") return null;
  if (payload.exp <= Math.floor(Date.now() / 1000)) return null;
  if (typeof expectedAud === "function") {
    if (!expectedAud(payload.aud)) return null;
  } else {
    const allowed =
      typeof expectedAud === "string" ? [expectedAud] : expectedAud;
    if (!allowed.includes(payload.aud)) return null;
  }
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
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return base64UrlEncodeBytes(new Uint8Array(sig));
}

function base64UrlEncode(s: string): string {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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
