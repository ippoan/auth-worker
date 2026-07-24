/**
 * `GET /.well-known/oauth-protected-resource` (issue #126 / Phase 4)
 * `GET /.well-known/oauth-protected-resource/<slug>` (per-resource variant)
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
 *
 * **Per-resource variant** (Refs ippoan/secrets-inventory#45): MCP relay 以外に
 * 独立した RS (= secrets-inventory worker, `security-inventory.ippoan.org`)
 * を増やしたとき、各 RS が自分用の metadata URL を `WWW-Authenticate` で宣言
 * できるよう、`/<slug>` suffix で resource を切り替える。slug は
 * `MCP_RESOURCE_ORIGINS_ALLOWLIST` env URL の hostname 先頭 label。
 *   - `/.well-known/oauth-protected-resource`                  → mcpRelayOrigin
 *   - `/.well-known/oauth-protected-resource/security-inventory` → security-inventory.ippoan.org
 */

import type { Env } from "../index";
import { corsJsonResponse } from "../lib/errors";
import {
  MCP_GOOGLE_SURFACE_PATH,
  mcpRelayOrigin,
  resourceOriginBySlug,
} from "../lib/mcp-origins";

export function handleMcpResourceMetadata(request: Request, env: Env): Response {
  const issuer = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
  const url = new URL(request.url);
  // issue #438: Google IdP surface の PRM (RFC 9728 path-inserted 形 —
  // resource `<origin>/mcp/google` に対する well-known URL)。authorization_servers
  // に path 付き issuer `<origin>/mcp/google` を返し、client を Google 既定の
  // AS metadata (`/.well-known/oauth-authorization-server/mcp/google`) へ誘導する。
  // slug 方式 (`[A-Za-z0-9-]+` 1 segment、MCP_RESOURCE_ORIGINS_ALLOWLIST 突合) とは
  // 独立した固定 path なので、slug regex より前に明示 match する。
  if (
    new RegExp(
      `^/\\.well-known/oauth-protected-resource${MCP_GOOGLE_SURFACE_PATH}/?$`,
    ).test(url.pathname)
  ) {
    const res = corsJsonResponse({
      resource: `${issuer}${MCP_GOOGLE_SURFACE_PATH}`,
      authorization_servers: [`${issuer}${MCP_GOOGLE_SURFACE_PATH}`],
      bearer_methods_supported: ["header"],
      scopes_supported: [
        "mcp.read",
        "mcp.write",
        "mcp.workflow",
        "mcp.project",
        "offline_access",
      ],
    });
    res.headers.set("Cache-Control", "public, max-age=3600");
    return res;
  }
  // path 末尾 segment が slug。base path (= `/.well-known/oauth-protected-
  // resource` ぴったり) の場合は slug 無し扱い (= mcpRelayOrigin)。
  const m = /^\/\.well-known\/oauth-protected-resource(?:\/([A-Za-z0-9-]+))?\/?$/.exec(
    url.pathname,
  );
  // routing 側で path 一致確認済みなので m が null になることは現実には無いが、
  // defense-in-depth として 404。
  if (!m) {
    return corsJsonResponse({ error: "unknown metadata path" }, 404);
  }
  const slug = m[1] ?? null;

  let resource: string;
  if (slug === null) {
    resource = mcpRelayOrigin(env);
  } else {
    const found = resourceOriginBySlug(env).get(slug);
    if (!found) {
      // 未登録 slug は 404 (= MCP_RESOURCE_ORIGINS_ALLOWLIST に対応 origin 無し)。
      // 攻撃者が任意 slug で metadata を mint させて confused-deputy を引き起こす
      // のを防ぐ。
      return corsJsonResponse({ error: `unknown resource slug: ${slug}` }, 404);
    }
    resource = found;
  }

  const res = corsJsonResponse({
    // resource: 本 metadata document が記述する RS の base URL。
    resource,
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
