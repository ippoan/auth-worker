/**
 * MCP OAuth Provider — refresh_token issue / consume (KV-backed rotation).
 *
 * RFC 6749 §6 refresh token grant の補助。Phase 3 `/mcp/token` で device_code grant の
 * 成功時 + refresh_token grant の rotation 時に発行 / 消費する。
 *
 * Design:
 *  - Token: 256bit (32B) ランダム hex 文字列。client 側にのみ raw 値を返す
 *  - KV key: `refresh:{sha256(token) hex}` ※ raw token は KV に書かない
 *  - KV value: JSON `{ sub, scope, github_login, expires_at, rotated_from? }`
 *  - TTL: 30 日 (REFRESH_TTL_SEC)
 *  - Rotation: consume は **delete-first** で race window を最小化
 *
 * KV は atomic でないため極稀に同一 refresh の同時 consume が両方成功し得る。
 * Phase 3 では許容 (人手 polling では発火しない)、Phase 5 で必要なら Durable
 * Object 化 (issue #91 Epic コメント参照)。
 */

import type { Env } from "../index";

export const REFRESH_TTL_SEC = 60 * 60 * 24 * 30; // 30 days

export interface RefreshRecord {
  sub: string;
  scope: string;
  github_login: string;
  expires_at: number; // ms epoch
  rotated_from?: string; // 旧 refresh hash (audit / double-spend 検出ログ用)
  /** consume が caller に返す用 (KV value には書かない、in-memory only) */
  hash: string;
}

/**
 * 新 refresh_token を発行して KV に `refresh:{hash}` で保存し、raw token を返す。
 * `rotated_from` を指定すると KV value に audit 用 hash を残す。
 */
export async function issueRefreshToken(
  env: Env,
  args: {
    sub: string;
    scope: string;
    github_login: string;
    rotated_from?: string;
  },
): Promise<string> {
  if (!env.MCP_OAUTH_KV) throw new Error("MCP_OAUTH_KV not bound");
  const raw = randomHex(32); // 256bit
  const hash = await sha256Hex(raw);
  const value: Omit<RefreshRecord, "hash"> = {
    sub: args.sub,
    scope: args.scope,
    github_login: args.github_login,
    expires_at: Date.now() + REFRESH_TTL_SEC * 1000,
    ...(args.rotated_from ? { rotated_from: args.rotated_from } : {}),
  };
  await env.MCP_OAUTH_KV.put(`refresh:${hash}`, JSON.stringify(value), {
    expirationTtl: REFRESH_TTL_SEC,
  });
  return raw;
}

/**
 * refresh_token を hash → KV lookup → delete → record を返す (rotation: 1 回限り使用)。
 * 不在 / expired → null + KV entry は最終的に消える。
 */
export async function consumeRefreshToken(
  env: Env,
  token: string,
): Promise<RefreshRecord | null> {
  if (!env.MCP_OAUTH_KV) throw new Error("MCP_OAUTH_KV not bound");
  const hash = await sha256Hex(token);
  const json = await env.MCP_OAUTH_KV.get(`refresh:${hash}`);
  if (!json) return null;

  // delete first to minimise race window (rotation = 1 回限り使用)
  await env.MCP_OAUTH_KV.delete(`refresh:${hash}`);

  let parsed: Omit<RefreshRecord, "hash">;
  try {
    parsed = JSON.parse(json) as Omit<RefreshRecord, "hash">;
  } catch {
    return null;
  }
  if (parsed.expires_at < Date.now()) return null;
  return { ...parsed, hash };
}

function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}
