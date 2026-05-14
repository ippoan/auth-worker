/**
 * `POST /mcp/device_authorization`
 *
 * RFC 8628 §3.1 Device Authorization Endpoint。
 * Request: `application/x-www-form-urlencoded` with `client_id` (必須) と `scope` (任意)。
 * Response: device_code / user_code / verification_uri / verification_uri_complete /
 *           expires_in / interval。
 *
 * client_id は Phase 1 では validate しない (RFC 8628 準拠)。実際の認可は
 * token endpoint (Phase 3) / introspect (Phase 5) で USER_ALLOWLIST + GitHub OAuth
 * 結果を見て gate する。
 */

import type { Env } from "../index";
import { corsJsonResponse } from "../lib/errors";
import { generateDeviceCode, generateUserCode } from "../lib/mcp-codes";
import { putDeviceCode, DEVICE_CODE_TTL_SEC } from "../lib/mcp-kv";
import { normalizeMcpScope } from "../lib/mcp-scope";

/** RFC 6749 §5.2 OAuth error response。description は spec 上 optional だが、
 *  全 caller で常に渡すため required にして branch を 1 本にする (テスト容易性 + coverage 100%)。 */
function oauthError(error: string, description: string, status = 400): Response {
  return corsJsonResponse({ error, error_description: description }, status);
}

export async function handleMcpDeviceAuthorization(
  request: Request,
  env: Env,
): Promise<Response> {
  if (!env.MCP_OAUTH_KV) {
    return oauthError("server_error", "MCP OAuth Provider not configured", 503);
  }

  // RFC 8628 §3.1: application/x-www-form-urlencoded
  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return oauthError("invalid_request", "expected application/x-www-form-urlencoded body");
  }

  const client_id = ((form.get("client_id") as string | null) ?? "").trim();
  if (!client_id) {
    return oauthError("invalid_request", "client_id is required");
  }
  const scope = normalizeMcpScope(((form.get("scope") as string | null) ?? "").trim());

  const device_code = generateDeviceCode();
  const user_code = generateUserCode();
  const now = Date.now();
  await putDeviceCode(env, {
    device_code,
    user_code,
    client_id,
    scope,
    status: "pending",
    created_at: now,
    expires_at: now + DEVICE_CODE_TTL_SEC * 1000,
  });

  const issuer = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
  const verification_uri = `${issuer}/device`;
  const verification_uri_complete = `${verification_uri}?user_code=${encodeURIComponent(user_code)}`;

  const res = corsJsonResponse({
    device_code,
    user_code,
    verification_uri,
    verification_uri_complete,
    expires_in: DEVICE_CODE_TTL_SEC,
    interval: 5, // RFC 8628 §3.5 default polling interval
  });
  // device_code は機密 — キャッシュ禁止
  res.headers.set("Cache-Control", "no-store");
  return res;
}
