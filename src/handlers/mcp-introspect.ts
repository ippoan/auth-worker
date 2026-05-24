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
 * Request body (mode 2 のみ必須): `application/json` `{ "token": "<JWT>" }`
 *
 * Response (RFC 7662 §2.2):
 *   - 有効: 200 `{ active: true, scope, sub, github_login, github_token, exp }`
 *   - 無効 / 期限切れ / KV miss: 200 `{ active: false }` (情報リーク回避)
 *   - 認証失敗: 401 (どちらの mode も成立しない)
 *   - body parse 失敗 / token 欠落 (mode 2 のみ): 200 `{ active: false }`
 *     (RFC 7662 §2.2 — caller は認証済み、トークン側の問題なので active:false)
 *   - 設定不備 (env 欠落): 503 `{ active: false, error: "server_error" }`
 *
 * Cache-Control: no-store。
 */

import type { Env } from "../index";
import { getLiteralAudAllowlist } from "../lib/mcp-aud";
import { decryptWithKey } from "../lib/mcp-crypto";
import { verifyMcpJwt, type McpJwtPayload } from "../lib/mcp-jwt";
import { mcpRelayOrigin } from "../lib/mcp-origins";

/**
 * binding_jwt の aud claim 受理 predicate を構築する。
 *
 * - legacy literal allowlist (default: `["github-mcp-server-rs", "ref-files-mcp-server-rs"]`、
 *   env `MCP_JWT_AUDIENCE_ALLOWLIST` で上書き) — Rust mcp-relay-rs 由来の
 *   binary が `binding_jwt` の `aud` に焼く literal。`mcp-pair-grant-via-oat` /
 *   `mcp-relay-bridge` と同じ allowlist source を使う (issue #23 — 片方の
 *   handler だけが accept する &quot;片肺&quot; を防ぐ)
 * - `mcp(-staging).ippoan.org` 起点の URL aud (= relay 既存実装)
 * - `MCP_RESOURCE_ORIGINS_ALLOWLIST` env (comma-sep) に並ぶ URL の origin
 *   一致 (= secrets-inventory / secrets-rotate-mcp など追加 RS 用)
 *
 * URL aud は MCP Authorization spec 2025-06-18 が RFC 8707 で要求する
 * `resource` parameter のため、claude.ai connector が任意の RS URL を aud
 * として要求してくる。許容する URL origin を env で明示的に絞り込むことで
 * confused-deputy を防ぐ。
 */
function audPredicate(env: Env): (aud: string) => boolean {
  const relayOrigin = mcpRelayOrigin(env);
  const extra = ((env as Env & { MCP_RESOURCE_ORIGINS_ALLOWLIST?: string })
    .MCP_RESOURCE_ORIGINS_ALLOWLIST ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const allowedOrigins = new Set<string>([relayOrigin, ...extra]);
  const allowedLiterals = new Set<string>(getLiteralAudAllowlist(env));
  return (aud: string) => {
    if (allowedLiterals.has(aud)) return true;
    try {
      return allowedOrigins.has(new URL(aud).origin);
    } catch {
      return false;
    }
  };
}

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
 * Normalise either binding shape into a plain string for comparison.
 *
 * - Worker secret / mock-env test value → already a string, return it.
 * - Secrets Store binding (`SecretsStoreSecret`) → call `.get()` and unwrap.
 * - Missing or unreadable → `null`.
 *
 * Mirrors `ref-files-worker/src/handlers/mcp-introspect.ts`. The dual-mode
 * lets `wrangler secret put` deployments keep working while we cut over
 * both workers to Secrets Store. Once both are on Secrets Store the
 * `string` branch becomes dead code.
 */
async function resolveSecretBinding(binding: unknown): Promise<string | null> {
  if (!binding) return null;
  if (typeof binding === "string") return binding;
  if (typeof binding === "object" && binding !== null
      && typeof (binding as { get?: unknown }).get === "function") {
    try {
      return await (binding as { get: () => Promise<string> }).get();
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Resolve every `INTERNAL_SHARED_SECRET*` binding on the env (legacy
 * `INTERNAL_SHARED_SECRET` + any per-consumer `INTERNAL_SHARED_SECRET_<NAME>`).
 *
 * The naming convention lets new consumers attach their own secret without
 * a code change here — add the binding in `wrangler.toml` and redeploy
 * auth-worker, then the consumer can authenticate `/mcp/introspect` with
 * its own value (issue #189). Mode 2 below tries each candidate in
 * constant-time; a match on ANY accepted secret authorizes the call.
 *
 * Returns `null` only when no candidate is bound — i.e. the env guard
 * should treat this as misconfiguration and return 503.
 */
export async function resolveAllSharedSecrets(env: Env): Promise<string[] | null> {
  const out: string[] = [];
  for (const key of Object.keys(env)) {
    if (!key.startsWith("INTERNAL_SHARED_SECRET")) continue;
    const value = await resolveSecretBinding((env as unknown as Record<string, unknown>)[key]);
    if (value) out.push(value);
  }
  return out.length > 0 ? out : null;
}

/**
 * Resolve `payload.sub` to its KV-encrypted `github_token` and build the
 * RFC 7662 `active:true` response. Common between mode 1 and mode 2.
 */
async function respondWithGithubToken(
  env: Env,
  payload: McpJwtPayload,
): Promise<Response> {
  const encrypted = await env.MCP_OAUTH_KV!.get(`github_token:${payload.sub}`);
  if (!encrypted) {
    return jsonNoStore({ active: false });
  }
  let github_token: string;
  try {
    github_token = await decryptWithKey(encrypted, env.SSO_ENCRYPTION_KEY!);
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

export async function handleMcpIntrospect(
  request: Request,
  env: Env,
): Promise<Response> {
  // ── env guard ────────────────────────────────────────────────────────────
  // INTERNAL_SHARED_SECRET* (legacy + per-consumer) は mode 2 でのみ実質必須。
  // 当面は既存 deployment との互換を優先して両 mode の前提として require する
  // (廃止は ADR-004)。Secrets Store binding は async resolve なのでここで
  // 一度確定させる。`resolveAllSharedSecrets` は `INTERNAL_SHARED_SECRET` で
  // 始まる全 binding を発見して array を返す (issue #189)。1 つも無ければ
  // 503 を出して mode 2 を実質無効化する。
  const sharedSecrets = await resolveAllSharedSecrets(env);
  if (
    !env.MCP_OAUTH_KV ||
    !env.MCP_JWT_SECRET ||
    !env.SSO_ENCRYPTION_KEY ||
    !sharedSecrets
  ) {
    return jsonNoStore({ active: false, error: "server_error" }, 503);
  }

  const authz = request.headers.get("Authorization") ?? "";

  // ── Mode 1: Bearer JWT (推奨) ───────────────────────────────────────────
  const bearer = /^Bearer\s+(.+)$/i.exec(authz);
  if (bearer && bearer[1]) {
    const payload = await verifyMcpJwt(bearer[1], env.MCP_JWT_SECRET, audPredicate(env));
    if (!payload) {
      // Bearer 形式で来たが verify 失敗 → mode 2 フォールバックさせず即 401
      // (timing attack 経路を増やさない、かつ legacy caller は Bearer prefix
      // を付けないので意図せず mode 2 に降りることはない)。
      return jsonNoStore({ error: "unauthorized" }, 401);
    }
    return await respondWithGithubToken(env, payload);
  }

  // ── Mode 2: 生 shared secret (legacy + per-consumer multi-secret #189) ──
  // Each candidate is compared in constant-time. Total wall-clock leaks how
  // many secrets are configured (1-N), but not which one matched. Acceptable
  // for the small N we run with.
  if (!authz || !sharedSecrets.some((s) => constantTimeEquals(authz, s))) {
    return jsonNoStore({ error: "unauthorized" }, 401);
  }

  // 認証通過後の body 不正は RFC 7662 §2.2 に従い active:false (200)。
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

  const payload = await verifyMcpJwt(token, env.MCP_JWT_SECRET, audPredicate(env));
  if (!payload) {
    return jsonNoStore({ active: false });
  }
  return await respondWithGithubToken(env, payload);
}
