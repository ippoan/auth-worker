/**
 * `GET /.well-known/oauth-protected-resource` (issue #126 / Phase 4)
 *
 * RFC 9728 (OAuth 2.0 Protected Resource Metadata) + MCP Authorization spec
 * ([2025-06-18](https://spec.modelcontextprotocol.io/specification/2025-06-18/basic/authorization/))
 * に従い、MCP relay (resource server) の所在と委譲先 AS の URL を JSON で返す。
 *
 * client (Anthropic Claude.ai backend など) は MCP server URL に POST して 401 を
 * 受け、`WWW-Authenticate.resource_metadata` 経由で本 endpoint を踏み、
 * `authorization_servers[0]` から AS metadata (`oauth-authorization-server`) を
 * 発見して Device Flow に入る。
 *
 * 本 endpoint は AS host (`auth(-staging).ippoan.org`) 側に置く (RS host にも
 * 置く設計はありえるが、AS にまとめる方が運用一貫 — issue #126 plan 参照)。
 * resource は MCP relay origin、authorization_servers は AS origin。
 */

import type { Env } from "../index";
import { corsJsonResponse } from "../lib/errors";
import { mcpRelayOrigin } from "../lib/mcp-origins";

export function handleMcpResourceMetadata(_request: Request, env: Env): Response {
  const issuer = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
  const res = corsJsonResponse({
    // resource: MCP relay の base URL (path は user 別の `/u/<login>/mcp` だが、
    // RFC 9728 上 base URL でよい)。client は本 origin に対する resource server
    // metadata と解釈する。
    resource: mcpRelayOrigin(env),
    authorization_servers: [issuer],
    // Bearer token は Authorization header で受ける (binary も Web も同様)。
    bearer_methods_supported: ["header"],
    // AS metadata と同じ scope セットを advertise (一貫性のため)。
    // `mcp.admin` は出さない (internal-only)、`mcp.workflow` / `mcp.project` は
    // public (issue #184)。
    scopes_supported: [
      "mcp.read",
      "mcp.write",
      "mcp.workflow",
      "mcp.project",
      "offline_access",
    ],
    // resource server が要求する文書化方針 (静的なので docs URL は省略)。
  });
  // resource metadata は静的なので edge cache を許可 (AS metadata と同方針)。
  res.headers.set("Cache-Control", "public, max-age=3600");
  return res;
}
