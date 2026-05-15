/**
 * `POST /mcp/introspect`
 *
 * RFC 7662 OAuth 2.0 Token Introspection の拡張版。
 *
 * 認証モード (二段。先に成功した方を使う):
 *   1. **Bearer JWT** (推奨, end-user CLI 用)
 *      `Authorization: Bearer <MCP_JWT>` — JWT 自体が認証 + introspect 対象。
 *      OAuth (DCR + PKCE / device flow) で発行された JWT を持っていれば、その
 *      ユーザー本人として自身の github_token を取り出せる。body の `token`
 *      フィールドは無視する (header が source of truth)。
 *      shared secret 配布を不要にするため #(this PR) で追加。
 *
 *   2. **Shared secret** (legacy, 後方互換)
 *      `Authorization: <INTERNAL_SHARED_SECRET>` (生の値、Bearer prefix なし) +
 *      body `{ "token": "<JWT>" }`. 旧 `github-mcp-server-rs` 用。新規利用者は
 *      mode 1 に移行する。将来削除予定 (auth-worker #91 epic)。
 *
 * MCP の confused-deputy 防止 (MCP spec 2025-06-18) の要件は OAuth が満たす:
 *   - JWT の aud / sub / scope で client / user / 権限境界が証明される。
 *   - mode 1 は OAuth で発行された JWT を提示している = ユーザーが当該 client
 *     を authz 済 = raw token を返してよい。
 *
 * Request body: `application/json` `{ "token": "<JWT>" }` (mode 2 のみ必須)
 *
 * Response (RFC 7662 §2.2):
 *   - 有効: 200 `{ active: true, scope, sub, github_login, github_token, exp }`
 *   - 無効 / 期限切れ / KV miss: 200 `{ active: false }` (情報リーク回避)
 *   - 認証失敗: 401 (どちらの mode も成立しない)
 *   - body parse 失敗 / token 欠落 (mode 2 のみ): 200 `{ active: false }` (RFC 7662 spec)
 *   - 設定不備 (env 欠落): 503 `{ active: false, error: "server_error" }`
 *
 * Cache-Control: no-store。
 */

import type { Env } from "../index";
import { decryptWithKey } from "../lib/mcp-crypto";
import { verifyMcpJwt, type McpJwtPayload } from "../lib/mcp-jwt";

const MCP_AUD = "github-mcp-server-rs";

function jsonNoStore(data: unknown, status = 200): Response {
  const res = new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
  res.headers.set("Cache-Control", "no-store");
  return res;
}

/** 定数時間比較。短絡せず全文字を XOR して合算。 */
function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * 認証を解決する。成功時は introspect 対象の JWT payload を返す。
 *
 * - mode 1 (Bearer JWT): header の JWT を verify → payload を返却。
 * - mode 2 (shared secret): header が secret と一致したら body の token を
 *   verify → payload を返却。
 * - どちらも不成立: `null`。
 */
async function resolveAuth(
  request: Request,
  env: Env,
  body: { token?: unknown },
): Promise<McpJwtPayload | null> {
  const authz = request.headers.get("Authorization") ?? "";

  // Mode 1: Bearer JWT (推奨)
  const bearer = /^Bearer\s+(.+)$/i.exec(authz);
  if (bearer && bearer[1]) {
    const payload = await verifyMcpJwt(bearer[1], env.MCP_JWT_SECRET!, MCP_AUD);
    if (payload) return payload;
    // Bearer 形式で来たが verify 失敗 → これは「JWT を提示して認証を試みた」
    // ことが明らかなので mode 2 にフォールバックさせず即失敗扱い (timing
    // attack 経路を増やさない)。
    return null;
  }

  // Mode 2: 生 shared secret (legacy)
  if (authz && env.INTERNAL_SHARED_SECRET
      && constantTimeEquals(authz, env.INTERNAL_SHARED_SECRET)) {
    const token = typeof body.token === "string" ? body.token : "";
    if (!token) return null;
    return await verifyMcpJwt(token, env.MCP_JWT_SECRET!, MCP_AUD);
  }

  return null;
}

export async function handleMcpIntrospect(
  request: Request,
  env: Env,
): Promise<Response> {
  // ── env guard ────────────────────────────────────────────────────────────
  // INTERNAL_SHARED_SECRET は mode 2 でのみ必須。mode 1 (Bearer JWT) しか
  // 使わない deployment では未設定でも 503 にしない方が望ましいが、当面は
  // 既存 deployment との互換を優先して必須のままにする (廃止は ADR-004)。
  if (
    !env.MCP_OAUTH_KV ||
    !env.MCP_JWT_SECRET ||
    !env.SSO_ENCRYPTION_KEY ||
    !env.INTERNAL_SHARED_SECRET
  ) {
    return jsonNoStore({ active: false, error: "server_error" }, 503);
  }

  // ── body parse (mode 2 用、mode 1 でも害なし) ───────────────────────────
  let body: { token?: unknown } = {};
  try {
    body = (await request.json()) as { token?: unknown };
  } catch {
    // body 無し / 不正でも mode 1 なら通る可能性があるので 401 にせず継続。
  }

  // ── 認証解決 (Bearer JWT or legacy shared secret) ────────────────────────
  const payload = await resolveAuth(request, env, body);
  if (!payload) {
    // どちらの mode も成立しない。RFC 7662 は「無効トークン」を 200 active:false
    // で返すが、こちらは「認証されていない caller」なので 401 を返す (mode 2
    // 既存挙動を踏襲)。
    return jsonNoStore({ error: "unauthorized" }, 401);
  }

  // ── github_token を KV から復号 ─────────────────────────────────────────
  const encrypted = await env.MCP_OAUTH_KV.get(`github_token:${payload.sub}`);
  if (!encrypted) {
    return jsonNoStore({ active: false });
  }
  let github_token: string;
  try {
    github_token = await decryptWithKey(encrypted, env.SSO_ENCRYPTION_KEY);
  } catch {
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
