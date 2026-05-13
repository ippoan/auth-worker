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
    token_endpoint: `${issuer}/mcp/token`,               // Phase 3 で実装
    introspection_endpoint: `${issuer}/mcp/introspect`,  // Phase 5 で実装
    grant_types_supported: [
      "urn:ietf:params:oauth:grant-type:device_code",
      "refresh_token",
    ],
    // RFC 8628 device flow = public client (binary 配布のため secret 隠匿不可)
    token_endpoint_auth_methods_supported: ["none"],
    // device flow は authorization_endpoint を使わない (response_type も不要)
    response_types_supported: [],
    scopes_supported: ["mcp.read", "mcp.write", "offline_access"],
    // Phase 5+ で PKCE 拡張する余地として宣言
    code_challenge_methods_supported: ["S256"],
  });
  // AS metadata は静的なので edge cache を許可 (corsJsonResponse は
  // Cache-Control を付けないので後付け)
  res.headers.set("Cache-Control", "public, max-age=3600");
  return res;
}
