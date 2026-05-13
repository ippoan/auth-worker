/**
 * MCP relay WebSocket upgrade handler (issue #117 / Phase 6)。
 *
 * `GET https://mcp.ippoan.org/u/<github_login>/connect` を受けて
 * `Authorization: Bearer <jwt>` を `verifyMcpJwt` で検証し、JWT の
 * `github_login` と path の `:user` が一致したら `McpSession` DO の
 * `/__connect` に転送する。
 *
 * 認証モデル: binary 側 (`github-mcp-server-rs`) が Phase 3 `/mcp/token` で
 * 取得した MCP access JWT をそのまま流用する。
 * - aud は `MCP_AUD = "github-mcp-server-rs"` (Phase 3 と同値)。
 * - `payload.github_login !== :user` なら 403 (他人の relay 窓に
 *   接続しようとした、もしくは binary が許可されていない login を主張)。
 */

import type { Env } from "../index";
import { verifyMcpJwt } from "../lib/mcp-jwt";

/** Phase 3 `/mcp/token` で発行される JWT の aud と一致させる (Rust binary 名)。 */
const MCP_AUD = "github-mcp-server-rs";

export async function handleMcpRelayConnect(
  request: Request,
  env: Env,
  user: string,
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
  if (!user) {
    return new Response("Missing user", { status: 400 });
  }

  const authz = request.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(authz);
  if (!m || !m[1]) {
    return new Response("Unauthorized", { status: 401 });
  }
  const payload = await verifyMcpJwt(m[1], env.MCP_JWT_SECRET, MCP_AUD);
  if (!payload) {
    return new Response("Invalid token", { status: 401 });
  }
  if (payload.github_login !== user) {
    return new Response("User mismatch", { status: 403 });
  }

  // DO への転送。`idFromName(user)` で github_login ごとに 1 instance が解決される。
  // path は public route と衝突しないように `/__connect` を使う。
  const id = env.MCP_SESSION_DO.idFromName(user);
  const stub = env.MCP_SESSION_DO.get(id);
  const doReq = new Request("https://do.invalid/__connect", {
    method: "GET",
    headers: request.headers, // Upgrade / Sec-WebSocket-* を保持
  });
  return stub.fetch(doReq);
}
