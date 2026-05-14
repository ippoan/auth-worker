/**
 * `GET /authorize` (mcp-staging.*) / `GET /mcp/authorize` (auth-staging.*)
 *
 * Phase 5 (issue #128) — RFC 6749 §4.1 Authorization Code grant の開始 endpoint。
 * Browser-based MCP client (Anthropic Claude.ai) が user を redirect で送り込む。
 *
 * Query params (必須):
 *   - response_type=code
 *   - client_id=<uuid>                       (DCR で発行された client_id)
 *   - redirect_uri=<url>                     (DCR で登録された redirect_uris のいずれか)
 *   - state=<opaque>                         (callback redirect でそのまま返す)
 *   - code_challenge=<base64url>             (PKCE)
 *   - code_challenge_method=S256             (S256 のみ許容)
 *   - scope=<space-separated>                (任意)
 *
 * Process:
 *   1. param 検証 + DCR client_id lookup + redirect_uri 一致確認
 *   2. auth request id (UUID) 生成 → KV `auth:request:<id>` に context 保存 (TTL 10m)
 *   3. state HMAC を `{provider:"github_mcp_authcode", auth_request_id}` で生成
 *   4. GitHub OAuth authorize URL に 302 redirect
 *
 * エラー (RFC 6749 §4.1.2.1):
 *   - redirect_uri / client_id 不正 → 400 で client に表示 (redirect しない)
 *   - その他 (response_type / code_challenge_method 等) → redirect_uri に
 *     `?error=...&state=...` で戻す
 *
 * 認証完了 callback は `/mcp/auth_callback` (handlers/mcp-auth-callback.ts)。
 */

import type { Env } from "../index";
import { jsonResponse } from "../lib/errors";
import {
  type AuthRequestRecord,
  AUTH_REQUEST_TTL_SEC,
  putAuthRequest,
} from "../lib/mcp-authcode";
import { getDcrClient } from "../lib/mcp-dcr";
import { generateOAuthState } from "../lib/security";

/** GitHub OAuth scope。`/user` で login を取得するために `read:user` 必須。 */
const GITHUB_OAUTH_SCOPE = "read:user";

/** redirect 先 URL に `error` を query string で乗せる helper (RFC 6749 §4.1.2.1)。 */
function redirectErrorResponse(
  redirectUri: string,
  error: string,
  description: string,
  state: string | null,
): Response {
  const u = new URL(redirectUri);
  u.searchParams.set("error", error);
  u.searchParams.set("error_description", description);
  if (state) u.searchParams.set("state", state);
  return Response.redirect(u.toString(), 302);
}

export async function handleMcpAuthorize(
  request: Request,
  env: Env,
): Promise<Response> {
  // ── env guard ──
  if (
    !env.MCP_OAUTH_KV ||
    !env.GITHUB_MCP_CLIENT_ID ||
    !env.OAUTH_STATE_SECRET ||
    !env.AUTH_WORKER_ORIGIN
  ) {
    return jsonResponse({ error: "server_error", error_description: "MCP OAuth Provider not configured" }, 503);
  }

  const url = new URL(request.url);
  const params = url.searchParams;
  const response_type = params.get("response_type") ?? "";
  const client_id = params.get("client_id") ?? "";
  const redirect_uri = params.get("redirect_uri") ?? "";
  const state = params.get("state") ?? "";
  const code_challenge = params.get("code_challenge") ?? "";
  const code_challenge_method = params.get("code_challenge_method") ?? "";
  const scope = params.get("scope") ?? "";

  // ── client_id / redirect_uri は DCR と照合。失敗時は redirect せず 400 表示
  //    (spec §4.1.2.1: redirect_uri が信用できないので) ──
  if (!client_id) {
    return jsonResponse({ error: "invalid_request", error_description: "client_id is required" }, 400);
  }
  const client = await getDcrClient(env, client_id);
  if (!client) {
    return jsonResponse({ error: "invalid_client", error_description: "client_id not found" }, 400);
  }
  if (!redirect_uri || !client.redirect_uris.includes(redirect_uri)) {
    return jsonResponse({ error: "invalid_request", error_description: "redirect_uri not registered for this client" }, 400);
  }

  // ── ここから後の error は redirect_uri 経由で返す ──
  if (response_type !== "code") {
    return redirectErrorResponse(redirect_uri, "unsupported_response_type", "response_type must be 'code'", state || null);
  }
  if (!code_challenge) {
    return redirectErrorResponse(redirect_uri, "invalid_request", "code_challenge is required (PKCE mandatory)", state || null);
  }
  if (code_challenge_method !== "S256") {
    return redirectErrorResponse(redirect_uri, "invalid_request", "code_challenge_method must be 'S256'", state || null);
  }

  // ── auth request 保存 ──
  const id = crypto.randomUUID();
  const rec: AuthRequestRecord = {
    id,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method: "S256",
    client_state: state,
    scope,
    expires_at: Date.now() + AUTH_REQUEST_TTL_SEC * 1000,
  };
  await putAuthRequest(env, rec);

  // ── GitHub OAuth に飛ばす (state HMAC に auth_request_id 埋め込み) ──
  const issuer = env.AUTH_WORKER_ORIGIN;
  const callbackUri = `${issuer}/mcp/auth_callback`;
  const ghState = await generateOAuthState(callbackUri, env.OAUTH_STATE_SECRET, {
    provider: "github_mcp_authcode",
    auth_request_id: id,
  });
  const ghAuthorize = new URL("https://github.com/login/oauth/authorize");
  ghAuthorize.searchParams.set("client_id", env.GITHUB_MCP_CLIENT_ID);
  ghAuthorize.searchParams.set("redirect_uri", callbackUri);
  ghAuthorize.searchParams.set("scope", GITHUB_OAUTH_SCOPE);
  ghAuthorize.searchParams.set("state", ghState);
  return Response.redirect(ghAuthorize.toString(), 302);
}
