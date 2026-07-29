/**
 * MCP OAuth Provider — Authorization Code grant (RFC 6749 §4.1) intermediate state.
 *
 * Phase 5 で `/authorize` (browser redirect) → GitHub OAuth → `/mcp/auth_callback`
 * → `/mcp/token (grant_type=authorization_code)` の中継で 2 種類の record を扱う:
 *
 *  - `auth:request:{id}` → `AuthRequestRecord`
 *      `/authorize` で生成し、GitHub OAuth round-trip 中の context を保持。
 *      callback 完了で削除される。TTL 10 分 (= GitHub OAuth UI で迷っても余裕)。
 *
 *  - `auth:code:{code}` → `AuthCodeRecord`
 *      callback 完了で発行する auth code。client が `/mcp/token` で交換すると即削除。
 *      TTL 5 分 (RFC 6749 §4.1.2 の推奨上限以下)。
 *
 * いずれも single-use 設計。consume 時は delete-first で race window を最小化。
 */

import type { Env } from "../index";

export const AUTH_REQUEST_TTL_SEC = 60 * 10; // 10 min (GitHub OAuth round-trip)
export const AUTH_CODE_TTL_SEC = 60 * 5; // 5 min (RFC 6749 §4.1.2)

/** `/authorize` で生成、GitHub OAuth round-trip 中に保持する context。 */
export interface AuthRequestRecord {
  /** UUID v4 — state HMAC に埋め込む */
  id: string;
  client_id: string;
  redirect_uri: string;
  /** PKCE S256 challenge (base64url) */
  code_challenge: string;
  /** RFC 7636 §4.2: 実装は S256 のみ */
  code_challenge_method: "S256";
  /** client が指定した state (callback redirect でそのまま返す) */
  client_state: string;
  /** 任意 scope (space separated)。空文字 OK */
  scope: string;
  /**
   * RFC 8707 Resource Indicator (MCP Authorization spec 2025-06-18 で必須化)。
   * MCP client (Anthropic Claude.ai 等) が `/authorize` の `resource` query で
   * 送る canonical MCP server URI (例 `https://mcp-staging.ippoan.org`)。
   * `/mcp/token` で aud=resource な access_token を発行するために伝播する。
   * legacy client (Rust binary device flow など) が送らないケースを許容するため
   * optional。
   */
  resource?: string;
  /**
   * RFC 9207 (issue #449): authorization response (callback の redirect back) に
   * 載せる `iss` 値。surface で issuer が異なる (既定 = `AUTH_WORKER_ORIGIN`、
   * Google IdP surface = `<origin>/mcp/google` — issue #438) ため `/authorize`
   * 時点の surface を記録する。旧 record (フィールド無し) は callback 側で
   * `AUTH_WORKER_ORIGIN` に fallback。
   */
  iss?: string;
  expires_at: number;
}

/** `/mcp/auth_callback` 完了で発行、`/mcp/token` で交換される auth code 状態。 */
export interface AuthCodeRecord {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: "S256";
  /**
   * IdP ごとに片方のみセットされる (不変条件)。GitHub flow は `github_login`、
   * Google flow (issue: MCP OAuth に Google IdP を追加) は `email`。
   */
  github_login?: string;
  email?: string;
  scope: string;
  /** RFC 8707 Resource Indicator (AuthRequestRecord から伝播。詳細は同 doc 参照)。 */
  resource?: string;
  expires_at: number;
}

export async function putAuthRequest(
  env: Env,
  rec: AuthRequestRecord,
): Promise<void> {
  if (!env.MCP_OAUTH_KV) throw new Error("MCP_OAUTH_KV not bound");
  await env.MCP_OAUTH_KV.put(`auth:request:${rec.id}`, JSON.stringify(rec), {
    expirationTtl: AUTH_REQUEST_TTL_SEC,
  });
}

export async function getAuthRequest(
  env: Env,
  id: string,
): Promise<AuthRequestRecord | null> {
  if (!env.MCP_OAUTH_KV) return null;
  const json = await env.MCP_OAUTH_KV.get(`auth:request:${id}`);
  if (!json) return null;
  try {
    return JSON.parse(json) as AuthRequestRecord;
  } catch {
    return null;
  }
}

export async function deleteAuthRequest(env: Env, id: string): Promise<void> {
  if (!env.MCP_OAUTH_KV) return;
  await env.MCP_OAUTH_KV.delete(`auth:request:${id}`);
}

export async function putAuthCode(
  env: Env,
  rec: AuthCodeRecord,
): Promise<void> {
  if (!env.MCP_OAUTH_KV) throw new Error("MCP_OAUTH_KV not bound");
  await env.MCP_OAUTH_KV.put(`auth:code:${rec.code}`, JSON.stringify(rec), {
    expirationTtl: AUTH_CODE_TTL_SEC,
  });
}

/**
 * auth code を取り出して即削除 (single-use)。
 * 不在 / parse 失敗 → null。delete-first パターンで race を最小化。
 */
export async function consumeAuthCode(
  env: Env,
  code: string,
): Promise<AuthCodeRecord | null> {
  if (!env.MCP_OAUTH_KV) return null;
  const json = await env.MCP_OAUTH_KV.get(`auth:code:${code}`);
  if (!json) return null;
  await env.MCP_OAUTH_KV.delete(`auth:code:${code}`);
  try {
    return JSON.parse(json) as AuthCodeRecord;
  } catch {
    return null;
  }
}
