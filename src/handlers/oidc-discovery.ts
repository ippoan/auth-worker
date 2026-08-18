/**
 * `GET /oidc/.well-known/openid-configuration`
 *
 * Cloudflare Access 向け OIDC surface の discovery document。issuer は
 * **`<origin>/oidc`** — 既存の MCP surface (issuer = `<origin>` / `<origin>/mcp/google`)
 * とは別 issuer にすることで、片方の client がもう片方の endpoint に迷い込まない。
 *
 * Access の generic OIDC 設定は Auth / Token / Certs URL を手で入れる形式なので
 * discovery は必須ではないが、issuer を名乗る以上は publish しておく (他の
 * 汎用 OIDC client を後からこの surface に載せるときに効く)。
 *
 * 既存 `/.well-known/oauth-authorization-server` (MCP AS metadata) には触っていない。
 * `mcp.admin` の非公開規約もそちら側の話で、本 surface には MCP scope を出さない。
 */
import type { Env } from "../index";
import { corsJsonResponse } from "../lib/errors";
import { OIDC_SURFACE_PATH, oidcIssuer } from "../lib/oidc-surface";

export function handleOidcDiscovery(_request: Request, env: Env): Response {
  const origin = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
  const base = `${origin}${OIDC_SURFACE_PATH}`;
  const res = corsJsonResponse({
    issuer: oidcIssuer(env),
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    userinfo_endpoint: `${base}/userinfo`,
    jwks_uri: `${base}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    subject_types_supported: ["public"],
    // 非対称署名のみ。HS256 を出さないのは、この surface の検証側 (Access) に
    // 共有秘密を渡す構成を選べないようにするため。
    id_token_signing_alg_values_supported: ["ES256"],
    scopes_supported: ["openid", "email", "profile"],
    // Access は confidential client (client_secret を持つ)。MCP surface の
    // `["none"]` (public client) とはここが決定的に違う。
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
    code_challenge_methods_supported: ["S256"],
    // `tenant_id` / `role` は custom claim。Access のポリシーで組織や権限を
    // 絞れるように id_token / userinfo の両方へ載せる。
    claims_supported: [
      "iss",
      "sub",
      "aud",
      "exp",
      "iat",
      "nonce",
      "email",
      "email_verified",
      "name",
      "tenant_id",
      "role",
      "org_slug",
    ],
  });
  res.headers.set("Cache-Control", "public, max-age=3600");
  return res;
}
