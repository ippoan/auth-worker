/**
 * IssueRoomDO WebSocket upgrade handler — ADR-004 Phase B.
 *
 * `GET /issues/:owner/:repo/:number/connect`
 * (host: `mcp.ippoan.org` / `mcp-staging.ippoan.org`)
 *
 * 1. JWT 検証 (既存 `mcp-jwt.ts` の `verifyMcpJwt` 流用、aud は MCP_AUD)。
 * 2. URL 引数から `owner` / `repo` / `issue_number` を取得。
 * 3. `idFromName(`issue:<owner>/<repo>#<N>`)` で `IssueRoomDO` stub。
 * 4. DO の `/__connect` に Upgrade request を転送、Hibernatable WS が
 *    accept される。
 *
 * 設計判断:
 * - JWT の `github_login` は本 endpoint では **照合しない**。issue は public
 *   情報なので「他人の issue を subscribe」も技術的には可能、認可は GitHub
 *   側の repo 公開設定に委ねる。private repo の event は GitHub が webhook
 *   delivery しないので、結果的に弾かれる。
 * - 但し JWT verify 自体は spam / abuse 防止のため必須 (匿名 subscribe を
 *   許すと DO が枯渇する)。
 */

import type { Env } from "../index";
import { verifyMcpJwt } from "../lib/mcp-jwt";
import { wwwAuthenticateValue } from "../lib/mcp-origins";

/** mcp-relay-connect と同じ aud を使い回す。Phase 3 `/mcp/token` が発行する。 */
const MCP_AUD = "github-mcp-server-rs";

function unauthorizedResponse(env: Env, body: string): Response {
  return new Response(body, {
    status: 401,
    headers: { "WWW-Authenticate": wwwAuthenticateValue(env) },
  });
}

export async function handleIssueRoomConnect(
  request: Request,
  env: Env,
  owner: string,
  repo: string,
  issueNumberStr: string,
): Promise<Response> {
  if (!env.MCP_JWT_SECRET) {
    return new Response("MCP not configured", { status: 503 });
  }
  if (!env.ISSUE_ROOM_DO) {
    return new Response("Issue room not configured", { status: 503 });
  }
  if (request.headers.get("Upgrade") !== "websocket") {
    return new Response("Expected websocket", { status: 426 });
  }
  if (!owner || !repo) {
    return new Response("Missing owner or repo", { status: 400 });
  }

  const issueNumber = Number.parseInt(issueNumberStr, 10);
  if (!Number.isFinite(issueNumber) || issueNumber <= 0) {
    return new Response("Invalid issue number", { status: 400 });
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
  // 上記コメント参照: github_login は照合しない (public issue 前提)。
  // JWT verify までで spam guard としては十分。

  const doKey = `issue:${owner}/${repo}#${issueNumber}`;
  const stub = env.ISSUE_ROOM_DO.get(env.ISSUE_ROOM_DO.idFromName(doKey));
  const doReq = new Request("https://do.invalid/__connect", {
    method: "GET",
    headers: request.headers, // Upgrade / Sec-WebSocket-* を保持
  });
  return stub.fetch(doReq);
}
