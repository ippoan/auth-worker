/**
 * `GET /oidc/userinfo` (OIDC Core §5.3)
 *
 * `/oidc/token` が返した access_token で identity を引く。Cloudflare Access は
 * id_token だけで完結するので必須ではないが、discovery で `userinfo_endpoint` を
 * 名乗る以上は実装しておく (この surface を Access 以外の汎用 OIDC client にも
 * 使えるようにするのが本来の目的なので、そちらで効く)。
 *
 * access_token は不透明な KV キーで、TTL 5 分。identity は KV に置いた値をそのまま
 * 返すだけで、ここで新しく identity を作ることはしない。
 */
import type { Env } from "../index";
import { corsJsonResponse } from "../lib/errors";
import { getOidcAccessTokenClaims } from "../lib/oidc-authcode";

/**
 * 401 は `WWW-Authenticate: Bearer` を付けて返す (OIDC Core §5.3.3 / RFC 6750 §3)。
 */
function unauthorized(description: string): Response {
  const res = corsJsonResponse(
    { error: "invalid_token", error_description: description },
    401,
  );
  res.headers.set(
    "WWW-Authenticate",
    `Bearer error="invalid_token", error_description="${description}"`,
  );
  return res;
}

export async function handleOidcUserinfo(request: Request, env: Env): Promise<Response> {
  if (!env.MCP_OAUTH_KV) {
    return corsJsonResponse(
      { error: "server_error", error_description: "oidc surface not configured" },
      503,
    );
  }
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) {
    return unauthorized("missing bearer token");
  }
  const claims = await getOidcAccessTokenClaims(env.MCP_OAUTH_KV, auth.slice("Bearer ".length));
  if (!claims) {
    return unauthorized("token is invalid or expired");
  }
  const body: Record<string, unknown> = {
    sub: claims.sub,
    email: claims.email,
    email_verified: true,
  };
  if (claims.name) body.name = claims.name;
  if (claims.tenant_id) body.tenant_id = claims.tenant_id;
  if (claims.role) body.role = claims.role;
  if (claims.org_slug) body.org_slug = claims.org_slug;
  return corsJsonResponse(body);
}
