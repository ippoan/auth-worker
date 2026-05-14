/**
 * MCP relay WebSocket upgrade handler (issue #117 / Phase 6 + ADR-003 user-less variant)。
 *
 * Two callsites in `src/index.ts:dispatchMcpRelay`:
 *
 * - `GET /u/<github_login>/connect` — back-compat for `github-mcp-server-rs`,
 *   `user` arg is the captured path segment.
 * - `GET /connect` — ADR-003 user-less endpoint for a binary that does not
 *   want to pin its github_login in URL config. `user` is `null`; DO id is
 *   derived from `verifyMcpJwt(jwt).github_login`.
 *
 * 認証モデル: binary 側 (`github-mcp-server-rs` / `cc-relay` host broker) が
 * Phase 3 `/mcp/token` で取得した MCP access JWT をそのまま流用する。
 * - aud は `MCP_AUD = "github-mcp-server-rs"` (Phase 3 と同値)。
 * - `payload.github_login !== :user` なら 403 (他人の relay 窓に接続しようと
 *   した、もしくは binary が許可されていない login を主張)。user-less mode
 *   ではこの照合をスキップする (JWT 自体が origin of truth)。
 */

import type { Env } from "../index";
import { verifyMcpJwt } from "../lib/mcp-jwt";
import { wwwAuthenticateValue } from "../lib/mcp-origins";

/** Phase 3 `/mcp/token` で発行される JWT の aud と一致させる (Rust binary 名)。 */
const MCP_AUD = "github-mcp-server-rs";

/**
 * 401 応答用 helper (Phase 4 / issue #126)。
 * `mcp-relay-bridge.ts` と同方針: WS upgrade 401 にも spec 準拠で
 * `WWW-Authenticate.resource_metadata` を載せる (binary 側がこれを見て JWT 取得 flow に進む)。
 */
function unauthorizedResponse(env: Env, body: string): Response {
  return new Response(body, {
    status: 401,
    headers: { "WWW-Authenticate": wwwAuthenticateValue(env) },
  });
}

export async function handleMcpRelayConnect(
  request: Request,
  env: Env,
  user: string | null,
): Promise<Response> {
  if (!env.MCP_JWT_SECRET) {
    return new Response("MCP not configured", { status: 503 });
  }
  if (request.headers.get("Upgrade") !== "websocket") {
    return new Response("Expected websocket", { status: 426 });
  }
  if (!env.MCP_SESSION_DO) {
    return new Response("MCP relay not configured", { status: 503 });
  }
  // user-less route (ADR-003) は `null` を渡す。空文字列は user-scoped route
  // 経由では起き得ない (regex `[^/]+`) が、直接呼出のガードとして残す。
  if (user === "") {
    return new Response("Missing user", { status: 400 });
  }

  const authz = request.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(authz);
  if (!m || !m[1]) {
    return unauthorizedResponse(env, "Unauthorized");
  }
  const payload = await verifyMcpJwt(m[1], env.MCP_JWT_SECRET, MCP_AUD);
  if (!payload) {
    return unauthorizedResponse(env, "Invalid token");
  }
  // user-scoped route だけ照合する (user-less mode = JWT を origin of truth)。
  if (user !== null && payload.github_login !== user) {
    return new Response("User mismatch", { status: 403 });
  }

  // DO への転送。`idFromName(user ?? jwt.github_login)` で github_login ごとに
  // 1 instance が解決される。path は public route と衝突しないように `/__connect` を使う。
  const doKey = user ?? payload.github_login;
  const id = env.MCP_SESSION_DO.idFromName(doKey);
  const stub = env.MCP_SESSION_DO.get(id);
  const doReq = new Request("https://do.invalid/__connect", {
    method: "GET",
    headers: request.headers, // Upgrade / Sec-WebSocket-* を保持
  });
  return stub.fetch(doReq);
}
