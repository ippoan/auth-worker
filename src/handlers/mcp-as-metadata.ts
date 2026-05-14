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
 */

import type { Env } from "../index";
import { corsJsonResponse } from "../lib/errors";

export function handleMcpAsMetadata(_request: Request, env: Env): Response {
  const issuer = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
  const res = corsJsonResponse({
    issuer,
    device_authorization_endpoint: `${issuer}/mcp/device_authorization`,
    token_endpoint: `${issuer}/mcp/token`,
    introspection_endpoint: `${issuer}/mcp/introspect`,
    // Phase 5 (issue #128): Browser client (Anthropic Claude.ai 等) 向け
    // Authorization Code grant + Dynamic Client Registration を追加
    authorization_endpoint: `${issuer}/mcp/authorize`,
    registration_endpoint: `${issuer}/mcp/register`,
    grant_types_supported: [
      "urn:ietf:params:oauth:grant-type:device_code",
      "authorization_code",
      "refresh_token",
    ],
    // public client only (Rust binary は配布、Browser client は secret 隠匿不可)
    token_endpoint_auth_methods_supported: ["none"],
    // Phase 5: code response_type 対応
    response_types_supported: ["code"],
    scopes_supported: ["mcp.read", "mcp.write", "offline_access"],
    // PKCE: S256 のみ (Phase 5 で実装)
    code_challenge_methods_supported: ["S256"],
  });
  // AS metadata は静的なので edge cache を許可 (corsJsonResponse は
  // Cache-Control を付けないので後付け)
  res.headers.set("Cache-Control", "public, max-age=3600");
  return res;
}
