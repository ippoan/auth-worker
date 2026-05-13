/**
 * `POST /mcp/introspect`
 *
 * RFC 7662 OAuth 2.0 Token Introspection の拡張版。MCP の confused-deputy 防止仕様
 * (MCP spec 2025-06-18) に従い、Rust binary `github-mcp-server-rs` が MCP JWT を保持
 * したまま GitHub API を直接叩くのを禁ずる代わりに、本 endpoint で JWT を introspect
 * してから別途 `github_token` を取得する設計。
 *
 * 認証: `Authorization: <INTERNAL_SHARED_SECRET>` (生の値、Bearer prefix なし)。
 *   - RFC 6750 とは異なるが issue #96 仕様に準拠。固定共有鍵のため公開 endpoint だが
 *     Rust binary 以外からは呼べない。将来 Service Binding 化 (#91 Epic コメント参照)。
 *
 * Request body: `application/json` `{ "token": "<JWT>" }`
 *
 * Response (RFC 7662 §2.2):
 *   - 有効: 200 `{ active: true, scope, sub, github_login, github_token, exp }`
 *   - 無効 / 期限切れ / KV miss: 200 `{ active: false }` (情報リーク回避)
 *   - 認証失敗: 401 (header 不在 / 値不一致)
 *   - body parse 失敗 / token 欠落: 200 `{ active: false }` (RFC 7662 spec)
 *   - 設定不備 (env 欠落): 503 `{ active: false, error: "server_error" }`
 *
 * Cache-Control: no-store。
 */

import type { Env } from "../index";
import { decryptWithKey } from "../lib/mcp-crypto";
import { verifyMcpJwt } from "../lib/mcp-jwt";

const MCP_AUD = "github-mcp-server-rs";

function jsonNoStore(data: unknown, status = 200): Response {
  const res = new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
  res.headers.set("Cache-Control", "no-store");
  return res;
}

/** 内部認証: `Authorization` header の生の値が `INTERNAL_SHARED_SECRET` と一致するか定数時間比較。 */
function checkInternalAuth(request: Request, expected: string): boolean {
  const auth = request.headers.get("Authorization");
  if (!auth) return false;
  if (auth.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < auth.length; i++) diff |= auth.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

export async function handleMcpIntrospect(
  request: Request,
  env: Env,
): Promise<Response> {
  // ── env guard ────────────────────────────────────────────────────────────
  if (
    !env.MCP_OAUTH_KV ||
    !env.MCP_JWT_SECRET ||
    !env.SSO_ENCRYPTION_KEY ||
    !env.INTERNAL_SHARED_SECRET
  ) {
    return jsonNoStore({ active: false, error: "server_error" }, 503);
  }

  // ── 内部認証 ────────────────────────────────────────────────────────────
  if (!checkInternalAuth(request, env.INTERNAL_SHARED_SECRET)) {
    return jsonNoStore({ error: "unauthorized" }, 401);
  }

  // ── body parse ──────────────────────────────────────────────────────────
  let body: { token?: unknown };
  try {
    body = (await request.json()) as { token?: unknown };
  } catch {
    return jsonNoStore({ active: false });
  }
  const token = typeof body.token === "string" ? body.token : "";
  if (!token) {
    return jsonNoStore({ active: false });
  }

  // ── JWT verify ──────────────────────────────────────────────────────────
  const payload = await verifyMcpJwt(token, env.MCP_JWT_SECRET, MCP_AUD);
  if (!payload) {
    return jsonNoStore({ active: false });
  }

  // ── github_token を KV から復号 ─────────────────────────────────────────
  const encrypted = await env.MCP_OAUTH_KV.get(`github_token:${payload.sub}`);
  if (!encrypted) {
    // sub に対応する github_token が KV から消えている (TTL 切れ等)
    return jsonNoStore({ active: false });
  }
  let github_token: string;
  try {
    github_token = await decryptWithKey(encrypted, env.SSO_ENCRYPTION_KEY);
  } catch {
    // 鍵 mismatch / 改ざん — fail-closed
    return jsonNoStore({ active: false });
  }

  return jsonNoStore({
    active: true,
    scope: payload.scope,
    sub: payload.sub,
    github_login: payload.github_login,
    github_token,
    exp: payload.exp,
  });
}
