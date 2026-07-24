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
 *   2. IdP を決定 — `resource` origin の `mcpIdpForResourceOrigin` 判定、無ければ
 *      surface 既定 (`opts.idpDefault`、`/mcp/authorize` は github /
 *      `/mcp/google/authorize` は google — issue #438)
 *   3. auth request id (UUID) 生成 → KV `auth:request:<id>` に context 保存 (TTL 10m)
 *   4. state HMAC を `{provider:"github_mcp_authcode"|"google_mcp_authcode", auth_request_id}` で生成
 *   5. GitHub または Google の OAuth authorize URL に 302 redirect
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
import { isAllowedResourceOrigin, mcpIdpForResourceOrigin } from "../lib/mcp-origins";
import { mcpToGithubScope, normalizeMcpScope, parseMcpScope } from "../lib/mcp-scope";
import { resolveSecret } from "../lib/secret";
import { generateOAuthState } from "../lib/security";

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
  opts?: {
    /**
     * resource 未指定時 (および resource origin が MCP_RESOURCE_GOOGLE_ORIGINS に
     * 無い時) に使う既定 IdP。省略時 "github" (既存挙動)。Google IdP surface の
     * `/mcp/google/authorize` (issue #438) は "google" を渡す。
     */
    idpDefault?: "github" | "google";
  },
): Promise<Response> {
  // ── env guard (IdP 非依存分のみ。GitHub/Google の client id は resource から
  //    IdP を決めた後、使う方だけ guard する — 片方しか設定してない環境でも
  //    もう片方の consumer を落とさないため) ──
  if (
    !env.MCP_OAUTH_KV ||
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
  const scope = normalizeMcpScope(params.get("scope") ?? "");

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

  // ── RFC 8707 Resource Indicator (MCP Authorization spec 2025-06-18 で必須化) ──
  // browser MCP client (Anthropic Claude.ai 等) は canonical resource URI を送る。
  // 値の URL.origin が `mcpRelayOrigin(env)` (= mcp(-staging).ippoan.org) または
  // `MCP_RESOURCE_ORIGINS_ALLOWLIST` env に並ぶ追加 RS origin (= secrets-inventory
  // 等の独立 worker) のいずれかと一致することを要求し、不一致は RFC 8707 §2
  // `invalid_target` で redirect エラー返却 (confused-deputy 防止)。
  // path / trailing slash 等は client が指定したまま echo し token aud にする
  // (Anthropic は自分が送った resource と JWT aud の完全一致を client 側で
  // 検証する。例: client が `https://mcp.example/mcp` を送ったら aud も同値)。
  // 未送信 (rust binary / legacy client) は許容し、token 発行時 aud は legacy 値で
  // 焼く (mcp-token.ts 参照)。
  const resourceRaw = params.get("resource");
  let resource: string | undefined;
  if (resourceRaw !== null) {
    let parsedOrigin: string | null = null;
    try {
      parsedOrigin = new URL(resourceRaw).origin;
    } catch {
      parsedOrigin = null;
    }
    if (parsedOrigin === null || !isAllowedResourceOrigin(parsedOrigin, env)) {
      return redirectErrorResponse(
        redirect_uri,
        "invalid_target",
        "resource origin must equal this MCP server's canonical origin",
        state || null,
      );
    }
    resource = resourceRaw;
  }

  // ── IdP を決定 (issue: MCP OAuth に Google IdP を追加 / issue #438)。
  //    優先順: ① resource origin が MCP_RESOURCE_GOOGLE_ORIGINS に列挙されていれば
  //    google (kyuyo-mcp 型 — client 側コードが resource を明示する構成)。
  //    ② それ以外は surface 既定 (`opts.idpDefault`)。既定 surface (`/mcp/authorize`)
  //    は github なので既存 consumer は挙動不変。Google IdP surface
  //    (`/mcp/google/authorize`) は resource 未指定 (claude.ai custom connector が
  //    `resource` を送らない実挙動) でも google に振れる。──
  const issuer = env.AUTH_WORKER_ORIGIN;
  const idp: "github" | "google" =
    opts?.idpDefault === "google" ||
    (resource !== undefined &&
      mcpIdpForResourceOrigin(new URL(resource).origin, env) === "google")
      ? "google"
      : "github";

  if (idp === "google") {
    const googleClientId = await resolveSecret(env.GOOGLE_CLIENT_ID);
    if (!googleClientId) {
      return jsonResponse({ error: "server_error", error_description: "MCP OAuth Provider not configured" }, 503);
    }
    const id = crypto.randomUUID();
    const rec: AuthRequestRecord = {
      id,
      client_id,
      redirect_uri,
      code_challenge,
      code_challenge_method: "S256",
      client_state: state,
      scope,
      ...(resource !== undefined ? { resource } : {}),
      expires_at: Date.now() + AUTH_REQUEST_TTL_SEC * 1000,
    };
    await putAuthRequest(env, rec);

    const callbackUri = `${issuer}/mcp/auth_callback_google`;
    const googleState = await generateOAuthState(callbackUri, env.OAUTH_STATE_SECRET, {
      provider: "google_mcp_authcode",
      auth_request_id: id,
    });
    const googleAuthorize = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    googleAuthorize.searchParams.set("client_id", googleClientId);
    googleAuthorize.searchParams.set("redirect_uri", callbackUri);
    googleAuthorize.searchParams.set("response_type", "code");
    googleAuthorize.searchParams.set("scope", "openid email");
    googleAuthorize.searchParams.set("state", googleState);
    return Response.redirect(googleAuthorize.toString(), 302);
  }

  // ── GitHub OAuth に飛ばす (state HMAC に auth_request_id 埋め込み) ──
  const githubClientId = await resolveSecret(env.GITHUB_MCP_CLIENT_ID);
  if (!githubClientId) {
    return jsonResponse({ error: "server_error", error_description: "MCP OAuth Provider not configured" }, 503);
  }
  const id = crypto.randomUUID();
  const rec: AuthRequestRecord = {
    id,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method: "S256",
    client_state: state,
    scope,
    ...(resource !== undefined ? { resource } : {}),
    expires_at: Date.now() + AUTH_REQUEST_TTL_SEC * 1000,
  };
  await putAuthRequest(env, rec);

  const callbackUri = `${issuer}/mcp/auth_callback`;
  const ghState = await generateOAuthState(callbackUri, env.OAUTH_STATE_SECRET, {
    provider: "github_mcp_authcode",
    auth_request_id: id,
  });
  const ghAuthorize = new URL("https://github.com/login/oauth/authorize");
  ghAuthorize.searchParams.set("client_id", githubClientId);
  ghAuthorize.searchParams.set("redirect_uri", callbackUri);
  ghAuthorize.searchParams.set("scope", mcpToGithubScope(parseMcpScope(scope)));
  ghAuthorize.searchParams.set("state", ghState);
  return Response.redirect(ghAuthorize.toString(), 302);
}
