/**
 * MCP OAuth Provider — Dynamic Client Registration (RFC 7591) storage.
 *
 * Phase 5 で `/register` が dynamic に発行する client_id を KV に保存し、
 * `/authorize` / `/mcp/token` で redirect_uri / client_id 一致検証する用途。
 *
 * Public client (no secret) のみサポート。Anthropic Claude.ai は browser-based
 * client なので secret を持てず、PKCE で代替する設計 (RFC 7636 + 7591)。
 *
 * Key 設計:
 *   `dcr:client:{client_id}` → JSON `DcrClientRecord` (TTL 90 days)
 */

import type { Env } from "../index";

/** RFC 7591 §3.2.1 の Client Information Response 相当 (public client サブセット)。 */
export interface DcrClientRecord {
  /** UUID v4 で発行 */
  client_id: string;
  /** client_id_issued_at (RFC 7591 §3.2.1, ms epoch) */
  client_id_issued_at: number;
  /** RFC 7591 §2 — public client は "none" */
  token_endpoint_auth_method: "none";
  /** RFC 7591 §2 — `["code"]` 固定 (Auth Code only) */
  response_types: ["code"];
  /** RFC 7591 §2 — `["authorization_code", "refresh_token"]` 固定 */
  grant_types: ["authorization_code", "refresh_token"];
  /** allowlist ベースで一致検証 (`/authorize` で渡される redirect_uri と完全一致) */
  redirect_uris: string[];
  /** 任意: client が自己申告する name (UI 表示等) */
  client_name?: string;
  /** 任意: 要求 scope 文字列 (space separated) */
  scope?: string;
}

/** `/register` の TTL: 90 日。client が放置されたら自動 expire。 */
export const DCR_CLIENT_TTL_SEC = 60 * 60 * 24 * 90;

export async function putDcrClient(
  env: Env,
  rec: DcrClientRecord,
): Promise<void> {
  if (!env.MCP_OAUTH_KV) throw new Error("MCP_OAUTH_KV not bound");
  await env.MCP_OAUTH_KV.put(
    `dcr:client:${rec.client_id}`,
    JSON.stringify(rec),
    { expirationTtl: DCR_CLIENT_TTL_SEC },
  );
}

export async function getDcrClient(
  env: Env,
  client_id: string,
): Promise<DcrClientRecord | null> {
  if (!env.MCP_OAUTH_KV) return null;
  const json = await env.MCP_OAUTH_KV.get(`dcr:client:${client_id}`);
  if (!json) return null;
  try {
    return JSON.parse(json) as DcrClientRecord;
  } catch {
    return null;
  }
}
