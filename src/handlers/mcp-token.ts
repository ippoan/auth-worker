/**
 * `POST /mcp/token`
 *
 * RFC 8628 §3.4 (device_code grant) + RFC 6749 §6 (refresh_token grant) の polling endpoint。
 *
 *   grant_type=urn:ietf:params:oauth:grant-type:device_code
 *     → device_code lookup → status:
 *         pending    → 400 { error: "authorization_pending" }
 *         denied     → 400 { error: "access_denied" }
 *         approved   → 200 { access_token (JWT), refresh_token, ... }
 *         expired    → 400 { error: "expired_token" }
 *
 *   grant_type=refresh_token
 *     → refresh_token consume (1 回限り使用 = rotation) → 新 JWT + 新 refresh
 *         不在 / expired → 400 { error: "invalid_grant" }
 *
 * access_token TTL: 1 時間。refresh_token TTL: 30 日。
 * `aud` は固定 `"github-mcp-server-rs"` (Rust binary 名)。
 *
 * Phase 5 で `/mcp/introspect` が JWT を verify する設計。
 */

import type { Env } from "../index";
import { corsJsonResponse } from "../lib/errors";
import { consumeAuthCode } from "../lib/mcp-authcode";
import { resolveMcpJwtSecret, signMcpJwt } from "../lib/mcp-jwt";
import { getDeviceCode } from "../lib/mcp-kv";
import { verifyPkceS256 } from "../lib/mcp-pkce";
import {
  consumeRefreshToken,
  issueRefreshToken,
  markRefreshRotated,
} from "../lib/mcp-refresh";

/** access_token (JWT) の有効期間: 1 時間 */
const ACCESS_TOKEN_TTL_SEC = 3600;
/**
 * JWT の `aud` claim 既定値 (legacy: Rust binary `github-mcp-server-rs` 用)。
 *
 * Authorization Code grant で client (Anthropic Claude.ai 等) が RFC 8707
 * `resource` を `/authorize` + `/mcp/token` で送ってきた場合は、その値を
 * aud として焼く (MCP Authorization spec 2025-06-18 で必須化)。送ってこない
 * legacy client (Rust binary device flow) では引き続き本値を使う。
 * `/mcp` 側 (mcp-relay-bridge.ts) は両 aud を許容する。
 */
const MCP_AUD = "github-mcp-server-rs";

/** RFC 6749 §5.2 OAuth error response。description を常に渡す (分岐 1 本)。 */
function oauthError(error: string, description: string, status = 400): Response {
  const res = corsJsonResponse({ error, error_description: description }, status);
  res.headers.set("Cache-Control", "no-store");
  return res;
}

function successResponse(body: {
  access_token: string;
  refresh_token: string;
  scope: string;
}): Response {
  const res = corsJsonResponse({
    access_token: body.access_token,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SEC,
    refresh_token: body.refresh_token,
    scope: body.scope,
  });
  res.headers.set("Cache-Control", "no-store");
  return res;
}

export async function handleMcpToken(
  request: Request,
  env: Env,
): Promise<Response> {
  const jwtSecret = await resolveMcpJwtSecret(env.MCP_JWT_SECRET);
  if (!env.MCP_OAUTH_KV || !jwtSecret) {
    return oauthError("server_error", "MCP OAuth Provider not configured", 503);
  }

  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return oauthError("invalid_request", "expected application/x-www-form-urlencoded body");
  }

  const grant_type = ((form.get("grant_type") as string | null) ?? "").trim();
  if (grant_type === "urn:ietf:params:oauth:grant-type:device_code") {
    return await handleDeviceCodeGrant(form, env, jwtSecret);
  }
  if (grant_type === "authorization_code") {
    return await handleAuthorizationCodeGrant(form, env, jwtSecret);
  }
  if (grant_type === "refresh_token") {
    return await handleRefreshGrant(form, env, jwtSecret);
  }
  return oauthError("unsupported_grant_type", `grant_type "${grant_type}" not supported`);
}

/**
 * Phase 5 (issue #128) — RFC 6749 §4.1.3 + RFC 7636 PKCE.
 * `/authorize` で発行された code を `/mcp/auth_callback` 経由で client が受領、
 * code_verifier 添えて本 endpoint に POST する。
 */
async function handleAuthorizationCodeGrant(
  form: FormData,
  env: Env,
  jwtSecret: string,
): Promise<Response> {
  const code = ((form.get("code") as string | null) ?? "").trim();
  const code_verifier = ((form.get("code_verifier") as string | null) ?? "").trim();
  const redirect_uri = ((form.get("redirect_uri") as string | null) ?? "").trim();
  const client_id = ((form.get("client_id") as string | null) ?? "").trim();
  if (!code || !code_verifier || !redirect_uri || !client_id) {
    return oauthError(
      "invalid_request",
      "code, code_verifier, redirect_uri, client_id are required",
    );
  }

  const rec = await consumeAuthCode(env, code);
  if (!rec) {
    return oauthError("invalid_grant", "auth code is invalid or already used");
  }
  if (rec.expires_at < Date.now()) {
    return oauthError("invalid_grant", "auth code has expired");
  }
  if (rec.client_id !== client_id) {
    return oauthError("invalid_grant", "client_id does not match the issued auth code");
  }
  if (rec.redirect_uri !== redirect_uri) {
    return oauthError("invalid_grant", "redirect_uri does not match the issued auth code");
  }
  const pkceOk = await verifyPkceS256(code_verifier, rec.code_challenge);
  if (!pkceOk) {
    return oauthError("invalid_grant", "PKCE verification failed");
  }

  // RFC 8707 §2.2: token endpoint も `resource` を受け得る。`/authorize` で
  // bind されているなら token request の値と一致を要求 (confused-deputy 防止)。
  // `/authorize` で未指定 (legacy) なら token request 側も無視する。
  const formResource = ((form.get("resource") as string | null) ?? "").trim();
  if (rec.resource !== undefined && formResource && formResource !== rec.resource) {
    return oauthError(
      "invalid_target",
      "resource does not match the one bound at /authorize",
    );
  }
  const aud = rec.resource ?? MCP_AUD;

  const sub = `github:${rec.github_login}`;
  const access_token = await signMcpJwt(
    {
      sub,
      github_login: rec.github_login,
      scope: rec.scope,
      aud,
    },
    jwtSecret,
    ACCESS_TOKEN_TTL_SEC,
  );
  const refresh_token = await issueRefreshToken(env, {
    sub,
    scope: rec.scope,
    github_login: rec.github_login,
    aud,
  });
  return successResponse({ access_token, refresh_token, scope: rec.scope });
}

async function handleDeviceCodeGrant(form: FormData, env: Env, jwtSecret: string): Promise<Response> {
  const device_code = ((form.get("device_code") as string | null) ?? "").trim();
  const client_id = ((form.get("client_id") as string | null) ?? "").trim();
  if (!device_code || !client_id) {
    return oauthError("invalid_request", "device_code and client_id are required");
  }

  const rec = await getDeviceCode(env, device_code);
  if (!rec) {
    return oauthError("expired_token", "device_code not found or expired");
  }
  if (rec.expires_at < Date.now()) {
    return oauthError("expired_token", "device_code has expired");
  }

  if (rec.status === "pending") {
    return oauthError("authorization_pending", "the user has not yet completed authorization");
  }
  if (rec.status === "denied") {
    return oauthError("access_denied", "the user denied the request");
  }
  // status === "approved"
  if (!rec.github_login) {
    // 防御的: callback で必ず github_login を書くはずだが、欠落なら 500
    return oauthError("server_error", "approved record missing github_login", 500);
  }

  const sub = `github:${rec.github_login}`;
  const access_token = await signMcpJwt(
    {
      sub,
      github_login: rec.github_login,
      scope: rec.scope,
      aud: MCP_AUD,
    },
    jwtSecret,
    ACCESS_TOKEN_TTL_SEC,
  );
  const refresh_token = await issueRefreshToken(env, {
    sub,
    scope: rec.scope,
    github_login: rec.github_login,
  });

  // device_code は使い捨て (RFC 8628 §3.5)。user_code は TTL で自然消滅 (race 防止)
  await env.MCP_OAUTH_KV!.delete(`device_code:${device_code}`);

  return successResponse({ access_token, refresh_token, scope: rec.scope });
}

async function handleRefreshGrant(form: FormData, env: Env, jwtSecret: string): Promise<Response> {
  const refresh_token = ((form.get("refresh_token") as string | null) ?? "").trim();
  if (!refresh_token) {
    return oauthError("invalid_request", "refresh_token is required");
  }

  const consumed = await consumeRefreshToken(env, refresh_token);
  if (!consumed) {
    return oauthError("invalid_grant", "refresh_token is invalid, expired, or already used");
  }

  // rotation 直後の旧 token 再使用 (並列 fan-out / 応答消失 retry / KV stale
  // read)。新 pair を再発行すると refresh chain が枝分かれするので、grace record
  // に保存済みの **同一 pair** をそのまま返す (Refs #270)。再使用は監視のため log。
  if (consumed.kind === "grace") {
    console.log(JSON.stringify({ msg: "mcp-refresh-grace-reuse", scope: consumed.grace.scope }));
    return successResponse({
      access_token: consumed.grace.access_token,
      refresh_token: consumed.grace.refresh_token,
      scope: consumed.grace.scope,
    });
  }

  const rec = consumed.record;
  // 初回発行時の aud を継承する。RFC 8707 で resource 指定された Authorization
  // Code grant 発の refresh なら MCP server origin、device flow なら legacy 値。
  // 旧 KV record (本 PR 反映前に発行された refresh) に aud field が無い場合は
  // legacy にフォールバック。
  const aud = rec.aud ?? MCP_AUD;
  const access_token = await signMcpJwt(
    {
      sub: rec.sub,
      github_login: rec.github_login,
      scope: rec.scope,
      aud,
    },
    jwtSecret,
    ACCESS_TOKEN_TTL_SEC,
  );
  const newRefresh = await issueRefreshToken(env, {
    sub: rec.sub,
    scope: rec.scope,
    github_login: rec.github_login,
    aud,
    rotated_from: rec.hash,
  });

  // 旧 hash slot を grace record (60s) に置換。以降 grace 窓内の旧 token 再使用は
  // 上の grace 分岐でこの同一 pair を返す。delete-first を廃したのでここまでの
  // 間 (read→この put) に並走した consume は通常 record を読んで double-rotation
  // し得るが、それは SDK single-flight (PR2) が消す。両者とも有効な新 pair を
  // 得るので invalid_grant の永続死にはならない。
  await markRefreshRotated(env, rec.hash, {
    access_token,
    refresh_token: newRefresh,
    scope: rec.scope,
  });

  return successResponse({
    access_token,
    refresh_token: newRefresh,
    scope: rec.scope,
  });
}
