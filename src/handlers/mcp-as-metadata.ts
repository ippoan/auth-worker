/**
 * `GET /.well-known/oauth-authorization-server`
 *
 * RFC 8414 (OAuth 2.0 Authorization Server Metadata) に従い、MCP クライアント
 * (Rust binary `github-mcp-server-rs`) が device flow を開始するための
 * endpoint URL とサポート機能を JSON で advertise する。
 *
 * `token_endpoint` / `introspection_endpoint` は Phase 3 / Phase 5 で実装されるが、
 * AS metadata は完成形を返す (URL を先に約束する形)。Phase 1 段階で
 * クライアントが上記 endpoint を叩いても 404 になるが、AS metadata 自体は
 * 安定して publish される。
 *
 * `scopes_supported` は consumer が `/mcp/device_authorization` `/mcp/authorize`
 * の `scope` パラメータに渡せる抽象 MCP scope。実 GitHub OAuth scope への
 * 翻訳は `src/lib/mcp-scope.ts` で行う (issue #130):
 *   - `mcp.read`        → GitHub `read:user`
 *   - `mcp.write`       → GitHub `read:user repo` (Issues r/w + private repo 含む)
 *   - `offline_access`  → 現状 no-op (token endpoint が常に refresh_token を発行)
 */

import type { Env } from "../index";
import { corsJsonResponse } from "../lib/errors";
import { MCP_GOOGLE_SURFACE_PATH } from "../lib/mcp-origins";

/**
 * @param surface "google" の時は Google IdP surface (issue #438) 用 variant を返す:
 *   issuer は `<origin>/mcp/google` (RFC 8414 path-inserted well-known で discovery
 *   される)、authorization_endpoint は resource 未指定でも Google 既定になる
 *   `/mcp/google/authorize`。token / register 等の他 endpoint は既定 surface と共有。
 */
export function handleMcpAsMetadata(
  _request: Request,
  env: Env,
  surface: "default" | "google" = "default",
): Response {
  const origin = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
  const issuer = surface === "google" ? `${origin}${MCP_GOOGLE_SURFACE_PATH}` : origin;
  const res = corsJsonResponse({
    issuer,
    device_authorization_endpoint: `${origin}/mcp/device_authorization`,
    token_endpoint: `${origin}/mcp/token`,
    introspection_endpoint: `${origin}/mcp/introspect`,
    // Phase 5 (issue #128): Browser client (Anthropic Claude.ai 等) 向け
    // Authorization Code grant + Dynamic Client Registration を追加。
    // Google IdP surface では authorize だけ専用 path に差し替える (issue #438)。
    authorization_endpoint:
      surface === "google"
        ? `${origin}${MCP_GOOGLE_SURFACE_PATH}/authorize`
        : `${origin}/mcp/authorize`,
    registration_endpoint: `${origin}/mcp/register`,
    grant_types_supported: [
      "urn:ietf:params:oauth:grant-type:device_code",
      "authorization_code",
      "refresh_token",
    ],
    // public client only (Rust binary は配布、Browser client は secret 隠匿不可)
    token_endpoint_auth_methods_supported: ["none"],
    // Phase 5: code response_type 対応
    response_types_supported: ["code"],
    // `mcp.admin` は意図的に出さない (internal-only、`/mcp/elevate` 経由でだけ
    // 付与される昇格 scope、CLAUDE.md 参照)。`mcp.workflow` / `mcp.project` は
    // public — ci-dashboard 等の consumer が device flow / authcode で要求可能
    // (issue #184)。
    scopes_supported: [
      "mcp.read",
      "mcp.write",
      "mcp.workflow",
      "mcp.project",
      "offline_access",
    ],
    // PKCE: S256 のみ (Phase 5 で実装)
    code_challenge_methods_supported: ["S256"],
    // RFC 8707 Resource Indicators — MCP Authorization spec 2025-06-18 で
    // 必須化された audience binding を本 AS がサポートする旨を advertise。
    // client (Anthropic Claude.ai 等) は本 flag を見て `/authorize` `/mcp/token`
    // に `resource=https://mcp-staging.ippoan.org` を載せる。
    resource_indicators_supported: true,
  });
  // AS metadata は静的なので edge cache を許可 (corsJsonResponse は
  // Cache-Control を付けないので後付け)
  res.headers.set("Cache-Control", "public, max-age=3600");
  return res;
}
