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

import { resolveSecret, type SecretBinding } from "./secret";

export interface McpJwtPayload {
  sub: string;
  /**
   * IdP ごとに片方のみセットされる (不変条件)。GitHub flow は `github_login`、
   * Google flow (issue: MCP OAuth に Google IdP を追加) は `email`。両方の consumer
   * は「自分が期待する方が無ければ deny」で扱うこと (相手 IdP の JWT を誤って
   * 受理しないため — 例: github_token を前提にする relay 系は `github_login` 必須)。
   */
  github_login?: string;
  email?: string;
  scope: string;
  aud: string;
  /**
   * 発行元 (`env.AUTH_WORKER_ORIGIN` — 例: `https://auth.ippoan.org` /
   * `https://auth-staging.ippoan.org`)。issue #432: `MCP_JWT_SECRET` は
   * prod/staging で同一の Secrets Store entry (`INTERNAL_SHARED_SECRET`) を
   * 指しており、この claim が無いと「どちらの環境が発行したか」を JWT 単体
   * からは一切区別できない (署名検証だけでは prod 発行と staging 発行が
   * 見分けられない)。prod で MCP OAuth Provider を有効化する際の監査・
   * 将来の環境別選択的失効の布石として **sign 側では必須付与**する。
   *
   * `verifyMcpJwt` / `verifyMcpJwtSignatureOnly` は **この claim をまだ検証
   * しない** (非破壊: 導入時点で既に飛び交っている iss 無しの旧トークンを
   * 引き続き受理する必要があるため)。値を要求する consumer 側の検証は
   * 別途の設計判断 (Refs #435)。
   *
   * 型としては optional — テストの fixture 生成箇所まで一律に必須化すると
   * このケース限りの機械的な差分が数十箇所に膨らむため。**実際に JWT を
   * mint する本番 handler 側は必ず明示的に渡すこと**(全 `signMcpJwt` 呼び
   * 出し箇所は本 PR で対応済み)。
   */
  iss?: string;
  exp: number; // seconds (Unix epoch)
  iat: number; // seconds (Unix epoch)
}

/**
 * `MCP_JWT_SECRET` binding shape (= 環境による 2 形態を共通化):
 *   - `string`            — `wrangler secret put` 由来 / vitest 用 plain binding
 *   - `SecretsStoreSecret` — account-level Secrets Store binding
 *                          (`[[secrets_store_secrets]]`、`.get()` で値取得)
 * Refs ippoan/ref-files-worker#6: ref-files-worker 側で同一 entry
 * `INTERNAL_SHARED_SECRET` を point している HS256 鍵に統合済。auth-worker も
 * 同 entry に bind することで、worker 同士の鍵 drift が構造的に消える。
 */
export type McpJwtSecretBinding = SecretBinding;

/**
 * Resolve `env.MCP_JWT_SECRET` binding to a plain string for HMAC use.
 *
 * - 文字列 (`wrangler secret` / vitest) → そのまま
 * - SecretsStoreSecret (`.get()` 持ち) → 解決して return
 * - 未 bind / `.get()` 失敗 → `null` (上位 handler は 500 / 503 を返す)
 *
 * 戻り値は **常に string | null** で、上位 handler は falsy check 1 回で
 * "set されているか" を判定できる (= 既存 `!env.MCP_JWT_SECRET` 系の置換)。
 */
export async function resolveMcpJwtSecret(
  binding: McpJwtSecretBinding,
): Promise<string | null> {
  return resolveSecret(binding);
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
  const base = await verifyMcpJwtSignatureOnly(token, secret);
  if (!base) return null;
  if (base.exp <= Math.floor(Date.now() / 1000)) return null;
  if (typeof expectedAud === "function") {
    if (!expectedAud(base.aud)) return null;
  } else {
    const allowed =
      typeof expectedAud === "string" ? [expectedAud] : expectedAud;
    if (!allowed.includes(base.aud)) return null;
  }
  return base;
}

/**
 * Verify HS256 JWT signature + schema (`alg`, claim shape) but **skip** `exp`
 * and `aud` checks. Used by `/mcp/jwt/pickup`: the binary may present an
 * expired-but-genuine JWT to recover a freshly minted pair that the user's
 * `/mcp/elevate` flow just stashed in KV. The KV entry itself is bound to
 * `payload.sub` and is one-shot, so accepting an expired signature here does
 * not widen the trust surface beyond "this caller once held a valid token
 * signed by `MCP_JWT_SECRET`".
 *
 * 不正 (alg mismatch / signature 不一致 / parse error) → null。`exp` / `aud` の
 * 値はそのまま返るので caller 側でログに使ってよい。
 */
export async function verifyMcpJwtSignatureOnly(
  token: string,
  secret: string,
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
  if (typeof payload.sub !== "string" || !payload.sub) return null;
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
