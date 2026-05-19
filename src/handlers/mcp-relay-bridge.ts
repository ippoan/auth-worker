/**
 * MCP relay HTTP bridge handler (issue #117 / Phase 6 + ADR-003 user-less variant)。
 *
 * Two callsites in `src/index.ts:dispatchMcpRelay`:
 *
 * - `POST /u/<github_login>/mcp` — back-compat for `github-mcp-server-rs`,
 *   `user` arg is the captured path segment.
 * - `POST /mcp` — ADR-003 user-less endpoint for `.mcp.json` committed to a
 *   consumer repo root. `user` is `null`; DO id is derived from
 *   `verifyMcpJwt(jwt).github_login` so a single static config works for
 *   every collaborator.
 *
 * Phase 6 では DO 側が常に 503 ("no active relay session") or 501
 * ("bridge not implemented") を返す。Phase 7 で実際の frame 変換を実装する
 * (`src/durable_objects/mcp-session-do.ts`)。
 *
 * 認証モデル: binary 側と同じ MCP access JWT を Claude Code Web の MCP 設定に
 * 載せる (`install-mcp.sh` が出力する) ことを前提に、`payload.github_login`
 * と path の `:user` を一致させる (user-less mode は JWT を origin of truth と
 * して照合をスキップする)。
 */

import type { Env } from "../index";
import { verifyMcpJwt } from "../lib/mcp-jwt";
import { mcpRelayOrigin, wwwAuthenticateValue } from "../lib/mcp-origins";

/**
 * 受け入れる JWT の `aud` claim:
 *  - allowlist (default: `["github-mcp-server-rs"]`、env `MCP_JWT_AUDIENCE_ALLOWLIST`
 *    で拡張可) — 各 Rust binary が device flow で得たトークン。Phase 2 multiplex
 *    (ref-files-mcp#4 option C) で複数 binary が共存するため、staging/prod 双方の
 *    env で `["github-mcp-server-rs","ref-files-mcp-server-rs"]` を設定する。
 *  - `mcpRelayOrigin(env)` (例 `https://mcp-staging.ippoan.org`) — Authorization
 *    Code grant + RFC 8707 Resource Indicator で browser MCP client (Anthropic
 *    Claude.ai 等) 向けに発行したトークン。MCP Authorization spec 2025-06-18
 *    が要求する audience binding の対象。
 */
const MCP_AUD_LEGACY_DEFAULT = "github-mcp-server-rs";

/** env の `MCP_JWT_AUDIENCE_ALLOWLIST` を解析。形式: comma-separated string。
 *  未設定 / 空文字列なら `[MCP_AUD_LEGACY_DEFAULT]` を返す (= Phase 1 互換)。 */
function legacyAudienceAllowlist(env: Env): Set<string> {
  const raw =
    (env as unknown as { MCP_JWT_AUDIENCE_ALLOWLIST?: string }).MCP_JWT_AUDIENCE_ALLOWLIST ?? "";
  const parts = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.length === 0) return new Set([MCP_AUD_LEGACY_DEFAULT]);
  return new Set(parts);
}

/**
 * 401 応答用 helper (Phase 4 / issue #126)。
 * MCP Authorization spec 上、auth が必要な MCP server の 401 には
 * `WWW-Authenticate: Bearer realm="...", resource_metadata="..."` header が必須。
 * 欠けると Anthropic Web client は "Couldn't reach the MCP server" で setup 失敗する。
 */
function unauthorizedResponse(env: Env, body: string): Response {
  return new Response(body, {
    status: 401,
    headers: { "WWW-Authenticate": wwwAuthenticateValue(env) },
  });
}

export async function handleMcpRelayBridge(
  request: Request,
  env: Env,
  user: string | null,
): Promise<Response> {
  const gate = await authenticateMcpRelay(request, env, user);
  if (gate.kind === "error") return gate.response;
  const stub = gate.stub;

  // Phase 6: DO に body をそのまま渡すが、Phase 7 で frame 変換実装時に
  // headers / body を再構築する余地を残しておく。
  // `duplex: "half"` は streaming body を渡すとき undici / Workers 双方が要求する。
  const init: RequestInit & { duplex?: "half" } = {
    method: request.method,
    headers: request.headers,
    body: request.body,
    duplex: "half",
  };
  const doReq = new Request("https://do.invalid/__bridge", init);
  return stub.fetch(doReq);
}

/**
 * ADR-004 Phase D: `GET /mcp` (Streamable HTTP transport, MCP spec 2025-06-18)。
 *
 * Claude.ai / Claude Code Web が server-initiated `notifications/message`
 * を受け取るための SSE channel を開く。auth/JWT 検証は POST と同じ。`Mcp-Session-Id`
 * header が無ければ DO 側で採番、ある場合は再利用 (replay の足場、Phase D では
 * 完全 reconnect)。実体は `McpSession` DO の `/__connect_sse` で、push_event /
 * binary back-pipe (`kind:"notif"`) から fan-out される。
 */
export async function handleMcpRelaySse(
  request: Request,
  env: Env,
  user: string | null,
): Promise<Response> {
  const gate = await authenticateMcpRelay(request, env, user);
  if (gate.kind === "error") return gate.response;
  const stub = gate.stub;

  const headers = new Headers();
  const sid = request.headers.get("Mcp-Session-Id");
  if (sid) headers.set("Mcp-Session-Id", sid);
  const doReq = new Request("https://do.invalid/__connect_sse", {
    method: "GET",
    headers,
  });
  return stub.fetch(doReq);
}

/** JWT 検証 + DO stub 解決の共通ロジック (POST `/mcp` と GET `/mcp` で共有)。 */
type Gate =
  | { kind: "ok"; stub: DurableObjectStub; doKey: string }
  | { kind: "error"; response: Response };

async function authenticateMcpRelay(
  request: Request,
  env: Env,
  user: string | null,
): Promise<Gate> {
  if (!env.MCP_JWT_SECRET) {
    return { kind: "error", response: new Response("MCP not configured", { status: 503 }) };
  }
  if (!env.MCP_SESSION_DO) {
    return { kind: "error", response: new Response("MCP relay not configured", { status: 503 }) };
  }
  if (user === "") {
    return { kind: "error", response: new Response("Missing user", { status: 400 }) };
  }

  const authz = request.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(authz);
  if (!m || !m[1]) {
    return { kind: "error", response: unauthorizedResponse(env, "Unauthorized") };
  }
  const relayOrigin = mcpRelayOrigin(env);
  const audAllowlist = legacyAudienceAllowlist(env);
  const payload = await verifyMcpJwt(m[1], env.MCP_JWT_SECRET, (aud) => {
    if (audAllowlist.has(aud)) return true;
    try {
      return new URL(aud).origin === relayOrigin;
    } catch {
      return false;
    }
  });
  if (!payload) {
    return { kind: "error", response: unauthorizedResponse(env, "Invalid token") };
  }
  if (user !== null && payload.github_login !== user) {
    return { kind: "error", response: new Response("User mismatch", { status: 403 }) };
  }

  const doKey = user ?? payload.github_login;
  const id = env.MCP_SESSION_DO.idFromName(doKey);
  const stub = env.MCP_SESSION_DO.get(id);
  return { kind: "ok", stub, doKey };
}
