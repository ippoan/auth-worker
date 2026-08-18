/**
 * `POST /oidc/token`
 *
 * authorization code → `id_token` (+ userinfo 用 access_token) の交換 (RFC 6749 §4.1.3 /
 * OIDC Core §3.1.3)。Cloudflare Access は受け取った `id_token` を JWKS
 * (`/oidc/.well-known/jwks.json`) で検証して identity を確定する。
 *
 * ## 既存 `/mcp/token` と分けてある理由
 *
 * - **client 認証がある**。MCP surface は public client (`auth_methods: ["none"]`) 前提
 *   だが、Access は client_secret を持つ confidential client。
 * - **返すものが違う**。MCP は HS256 の access_token、こちらは ES256 の `id_token`。
 * - `grant_type` も `authorization_code` だけ (refresh_token は出さない — Access は
 *   自分の session cookie で寿命を管理するので、IdP 側に refresh を持たせる必要が無い)。
 *
 * 既存 `/mcp/token` は未変更。
 */
import type { Env } from "../index";
import { corsJsonResponse } from "../lib/errors";
import {
  OIDC_ACCESS_TOKEN_TTL_SEC,
  generateOidcOpaqueToken,
  putOidcAccessToken,
  takeOidcCode,
} from "../lib/oidc-authcode";
import {
  findOidcClient,
  resolveOidcClients,
  verifyClientSecret,
  type OidcClient,
} from "../lib/oidc-clients";
import { verifyPkceS256 } from "../lib/mcp-pkce";
import { resolveOidcSigningKeys, signEs256Jwt } from "../lib/oidc-signing-key";
import { oidcIssuer } from "../lib/oidc-surface";

/** `id_token` の寿命。Access は受領直後に検証するだけなので短くて足りる。 */
const ID_TOKEN_TTL_SEC = 300;

function tokenError(error: string, description: string, status = 400): Response {
  return corsJsonResponse({ error, error_description: description }, status);
}

/**
 * client 認証情報を取り出す。`client_secret_basic` (Authorization ヘッダ) と
 * `client_secret_post` (body) の両方を受ける — Access がどちらを使うかは
 * 設定次第なので、discovery で advertise した 2 方式を両方実装する。
 */
function extractClientCredentials(
  request: Request,
  form: URLSearchParams,
): { clientId: string; clientSecret: string } {
  const auth = request.headers.get("Authorization") || "";
  if (auth.startsWith("Basic ")) {
    try {
      const decoded = atob(auth.slice("Basic ".length));
      const sep = decoded.indexOf(":");
      if (sep !== -1) {
        return {
          // RFC 6749 §2.3.1 は client_id / secret を form-urlencoded せよと定める。
          clientId: decodeURIComponent(decoded.slice(0, sep)),
          clientSecret: decodeURIComponent(decoded.slice(sep + 1)),
        };
      }
    } catch {
      // 壊れた Basic ヘッダは「認証情報なし」として下の body 側にフォールバックさせる。
    }
  }
  return {
    clientId: form.get("client_id") || "",
    clientSecret: form.get("client_secret") || "",
  };
}

export async function handleOidcToken(request: Request, env: Env): Promise<Response> {
  if (!env.MCP_OAUTH_KV) {
    return tokenError("server_error", "oidc surface not configured", 503);
  }
  const clients = await resolveOidcClients(env.ACCESS_OIDC_CLIENTS);
  if (!clients) {
    return tokenError("server_error", "oidc clients not configured", 503);
  }
  const signingKeys = await resolveOidcSigningKeys(env.ACCESS_OIDC_SIGNING_KEY);
  if (!signingKeys) {
    return tokenError("server_error", "signing key not configured", 503);
  }

  let form: URLSearchParams;
  try {
    form = new URLSearchParams(await request.text());
  } catch {
    return tokenError("invalid_request", "malformed request body");
  }

  const { clientId, clientSecret } = extractClientCredentials(request, form);
  const client: OidcClient | null = findOidcClient(clients, clientId);
  // 未登録 client と secret 不一致は **同じ応答** にする (client_id の存在を漏らさない)。
  if (!client || !verifyClientSecret(client, clientSecret)) {
    return tokenError("invalid_client", "client authentication failed", 401);
  }

  if (form.get("grant_type") !== "authorization_code") {
    return tokenError("unsupported_grant_type", "only authorization_code is supported");
  }

  const code = form.get("code") || "";
  // takeOidcCode は読めた時点で必ず消す (single-use)。
  const record = code ? await takeOidcCode(env.MCP_OAUTH_KV, code) : null;
  if (!record) {
    return tokenError("invalid_grant", "code is invalid, expired, or already used");
  }
  // code を発行した client 以外には渡さない (RFC 6749 §4.1.3)。
  if (record.client_id !== client.client_id) {
    return tokenError("invalid_grant", "code was issued to a different client");
  }
  if (record.redirect_uri !== (form.get("redirect_uri") || "")) {
    return tokenError("invalid_grant", "redirect_uri does not match the authorization request");
  }
  if (record.code_challenge) {
    const verifier = form.get("code_verifier") || "";
    if (!(await verifyPkceS256(verifier, record.code_challenge))) {
      return tokenError("invalid_grant", "PKCE verification failed");
    }
  }

  const now = Math.floor(Date.now() / 1000);
  const c = record.claims;
  const payload: Record<string, unknown> = {
    iss: oidcIssuer(env),
    sub: c.sub,
    aud: client.client_id,
    iat: now,
    exp: now + ID_TOKEN_TTL_SEC,
    email: c.email,
    // 自社の login フローを通った identity なので verified 扱いにする
    // (Google / LINE WORKS / e-Gov いずれの経路でも IdP 側で確認済みの address)。
    email_verified: true,
  };
  if (record.nonce) payload.nonce = record.nonce;
  if (c.name) payload.name = c.name;
  if (c.tenant_id) payload.tenant_id = c.tenant_id;
  if (c.role) payload.role = c.role;
  if (c.org_slug) payload.org_slug = c.org_slug;

  // 配列の先頭が現用鍵 (`lib/oidc-signing-key.ts` のローテーション規約)。
  const idToken = await signEs256Jwt(payload, signingKeys[0]!);

  const accessToken = generateOidcOpaqueToken();
  await putOidcAccessToken(env.MCP_OAUTH_KV, accessToken, c);

  console.log(
    JSON.stringify({
      event: "oidc_token_issued",
      client_id: client.client_id,
      tenant_id: c.tenant_id ?? null,
      role: c.role ?? null,
    }),
  );

  return corsJsonResponse({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: OIDC_ACCESS_TOKEN_TTL_SEC,
    id_token: idToken,
    scope: record.scope,
  });
}
