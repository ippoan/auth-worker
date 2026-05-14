/**
 * `POST /register` (mcp-staging.*) / `POST /mcp/register` (auth-staging.*)
 *
 * Phase 5 (issue #128) — RFC 7591 Dynamic Client Registration。Public client 用 subset:
 *
 * Request body (application/json):
 *   {
 *     "redirect_uris": ["https://claude.ai/.../callback", ...],   // required, non-empty
 *     "client_name": "Claude.ai",                                  // optional
 *     "token_endpoint_auth_method": "none",                        // 強制 (public client)
 *     "grant_types": ["authorization_code", "refresh_token"],      // 任意 (固定セット)
 *     "response_types": ["code"],                                  // 任意 (固定)
 *     "scope": "mcp.read mcp.write"                                // 任意
 *   }
 *
 * Response 201 (RFC 7591 §3.2.1):
 *   {
 *     "client_id": "<uuid>",
 *     "client_id_issued_at": <unix-seconds>,
 *     "redirect_uris": [...],                  // 入力をそのまま echo
 *     "token_endpoint_auth_method": "none",
 *     "grant_types": ["authorization_code", "refresh_token"],
 *     "response_types": ["code"]
 *   }
 *
 * Validation (RFC 7591 §3.3):
 *   - body が JSON でない → 400 invalid_client_metadata
 *   - redirect_uris 欠落 / 空配列 / non-string 含む → 400 invalid_redirect_uri
 *   - redirect_uris の各要素が absolute https:// (or http://localhost) → spec
 *     上は緩いが、ここでは https:// only + http://localhost(:port)? を許容
 *
 * KV 保存: `dcr:client:{client_id}` → DcrClientRecord (TTL 90d)
 *
 * 注: Anthropic Claude.ai は `mcp-staging.ippoan.org/register` 直 hit するので
 * `dispatchMcpRelay` 経由で本 handler が呼ばれる。`auth-staging.ippoan.org/mcp/register`
 * 経由でも spec 準拠の場所として呼べる。
 */

import type { Env } from "../index";
import { corsJsonResponse, jsonResponse } from "../lib/errors";
import {
  type DcrClientRecord,
  putDcrClient,
} from "../lib/mcp-dcr";

/** redirect_uri 文法チェック: https:// または http://localhost(:port)? のみ。 */
function isValidRedirectUri(uri: string): boolean {
  try {
    const u = new URL(uri);
    if (u.protocol === "https:") return true;
    if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

function dcrError(error: string, description: string, status = 400): Response {
  // RFC 7591 §3.2.2 error response
  const res = jsonResponse({ error, error_description: description }, status);
  res.headers.set("Cache-Control", "no-store");
  return res;
}

export async function handleMcpRegister(
  request: Request,
  env: Env,
): Promise<Response> {
  if (!env.MCP_OAUTH_KV) {
    return dcrError("server_error", "MCP OAuth Provider not configured", 503);
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return dcrError("invalid_client_metadata", "expected application/json body");
  }
  if (typeof body !== "object" || body === null) {
    return dcrError("invalid_client_metadata", "request body must be a JSON object");
  }
  const m = body as Record<string, unknown>;

  // redirect_uris
  const redirectUrisRaw = m["redirect_uris"];
  if (!Array.isArray(redirectUrisRaw) || redirectUrisRaw.length === 0) {
    return dcrError(
      "invalid_redirect_uri",
      "redirect_uris is required and must be a non-empty array",
    );
  }
  const redirect_uris: string[] = [];
  for (const u of redirectUrisRaw) {
    if (typeof u !== "string" || !isValidRedirectUri(u)) {
      return dcrError(
        "invalid_redirect_uri",
        "redirect_uris must be https:// (or http://localhost) absolute URLs",
      );
    }
    redirect_uris.push(u);
  }

  // 任意 fields は accept するが、固定値を強制 (public client only)
  const client_name =
    typeof m["client_name"] === "string" ? (m["client_name"] as string) : undefined;
  const scope = typeof m["scope"] === "string" ? (m["scope"] as string) : undefined;

  const client_id = crypto.randomUUID();
  const rec: DcrClientRecord = {
    client_id,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    token_endpoint_auth_method: "none",
    response_types: ["code"],
    grant_types: ["authorization_code", "refresh_token"],
    redirect_uris,
    ...(client_name !== undefined ? { client_name } : {}),
    ...(scope !== undefined ? { scope } : {}),
  };
  await putDcrClient(env, rec);

  // RFC 7591 §3.2.1: 201 Created
  const res = corsJsonResponse(rec, 201);
  res.headers.set("Cache-Control", "no-store");
  return res;
}
