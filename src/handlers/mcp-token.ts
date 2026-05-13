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
import { signMcpJwt } from "../lib/mcp-jwt";
import { getDeviceCode } from "../lib/mcp-kv";
import {
  consumeRefreshToken,
  issueRefreshToken,
} from "../lib/mcp-refresh";

/** access_token (JWT) の有効期間: 1 時間 */
const ACCESS_TOKEN_TTL_SEC = 3600;
/** JWT の `aud` claim — Rust binary 名 (introspect 側が strict 検証) */
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
  if (!env.MCP_OAUTH_KV || !env.MCP_JWT_SECRET) {
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
    return await handleDeviceCodeGrant(form, env);
  }
  if (grant_type === "refresh_token") {
    return await handleRefreshGrant(form, env);
  }
  return oauthError("unsupported_grant_type", `grant_type "${grant_type}" not supported`);
}

async function handleDeviceCodeGrant(form: FormData, env: Env): Promise<Response> {
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
    env.MCP_JWT_SECRET!,
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

async function handleRefreshGrant(form: FormData, env: Env): Promise<Response> {
  const refresh_token = ((form.get("refresh_token") as string | null) ?? "").trim();
  if (!refresh_token) {
    return oauthError("invalid_request", "refresh_token is required");
  }

  const consumed = await consumeRefreshToken(env, refresh_token);
  if (!consumed) {
    return oauthError("invalid_grant", "refresh_token is invalid, expired, or already used");
  }

  const access_token = await signMcpJwt(
    {
      sub: consumed.sub,
      github_login: consumed.github_login,
      scope: consumed.scope,
      aud: MCP_AUD,
    },
    env.MCP_JWT_SECRET!,
    ACCESS_TOKEN_TTL_SEC,
  );
  const newRefresh = await issueRefreshToken(env, {
    sub: consumed.sub,
    scope: consumed.scope,
    github_login: consumed.github_login,
    rotated_from: consumed.hash,
  });

  return successResponse({
    access_token,
    refresh_token: newRefresh,
    scope: consumed.scope,
  });
}
