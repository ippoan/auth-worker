/**
 * MCP relay HTTP bridge handler (issue #117 / Phase 6)。
 *
 * `POST https://mcp.ippoan.org/u/<github_login>/mcp` を受けて
 * JWT を検証し、`McpSession` DO の `/__bridge` に request を転送する。
 *
 * Phase 6 では DO 側が常に 503 ("no active relay session") or 501
 * ("bridge not implemented") を返す。Phase 7 で実際の frame 変換を実装する。
 *
 * 認証モデル: binary 側と同じ MCP access JWT を Claude Code Web の MCP 設定に
 * 載せる (`install-mcp.sh` が出力する) ことを前提に、`payload.github_login`
 * と path の `:user` を一致させる。
 */

import type { Env } from "../index";
import { verifyMcpJwt } from "../lib/mcp-jwt";
import { wwwAuthenticateValue } from "../lib/mcp-origins";

/** Phase 3 `/mcp/token` で発行される JWT の aud と一致させる (Rust binary 名)。 */
const MCP_AUD = "github-mcp-server-rs";

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
  user: string,
): Promise<Response> {
  if (!env.MCP_JWT_SECRET) {
    return new Response("MCP not configured", { status: 503 });
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
    return unauthorizedResponse(env, "Unauthorized");
  }
  const payload = await verifyMcpJwt(m[1], env.MCP_JWT_SECRET, MCP_AUD);
  if (!payload) {
    return unauthorizedResponse(env, "Invalid token");
  }
  if (payload.github_login !== user) {
    return new Response("User mismatch", { status: 403 });
  }

  const id = env.MCP_SESSION_DO.idFromName(user);
  const stub = env.MCP_SESSION_DO.get(id);
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
