/**
 * `GET /mcp/auth_callback?code=...&state=...`
 *
 * Phase 5 (issue #128) — Authorization Code 用の GitHub OAuth callback。
 * Device Flow 用の `/mcp/device_callback` と分離 (state の provider で振り分けるより
 * URL 単位で分けたほうが routing がシンプル)。
 *
 * Process:
 *   1. state 検証 + provider="github_mcp_authcode" + auth_request_id 取得
 *   2. KV `auth:request:<id>` lookup → {client_id, redirect_uri, code_challenge, scope, client_state}
 *   3. GitHub `/login/oauth/access_token` で code → github_token 交換
 *   4. GitHub `/user` で login 取得
 *   5. ACL (`GITHUB_MCP_USER_ALLOWLIST`) 検証
 *   6. github_token を AES-256-GCM 暗号化 → KV `github_token:{sub}` に保管 (introspect 用)
 *   7. auth code (UUID) 生成 → KV `auth:code:<code>` 保存 (TTL 5m)
 *   8. auth request 削除
 *   9. client redirect_uri へ 302 (`?code=<auth_code>&state=<client_state>`)
 *
 * エラー時 (token exchange 失敗 / user fetch 失敗 / ACL deny):
 *   client redirect_uri へ `?error=...&state=...` で戻す (RFC 6749 §4.1.2.1)
 */

import type { Env } from "../index";
import {
  type AuthCodeRecord,
  AUTH_CODE_TTL_SEC,
  deleteAuthRequest,
  getAuthRequest,
  putAuthCode,
} from "../lib/mcp-authcode";
import { encryptWithKey } from "../lib/mcp-crypto";
import { jsonResponse } from "../lib/errors";
import { verifyOAuthState } from "../lib/security";

/** github_token は refresh 寿命と同じ TTL で KV に保管 (Phase 3 と同じ key 規約)。 */
const GITHUB_TOKEN_TTL_SEC = 60 * 60 * 24 * 30;

/** ACL parse は fail-closed: JSON 不正 / 非 array / 非 string 混在 → deny all */
function parseAllowlist(raw: string | undefined): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.every((x) => typeof x === "string") ? (parsed as string[]) : [];
  } catch {
    return [];
  }
}

function redirectError(
  redirectUri: string,
  error: string,
  description: string,
  clientState: string,
): Response {
  const u = new URL(redirectUri);
  u.searchParams.set("error", error);
  u.searchParams.set("error_description", description);
  if (clientState) u.searchParams.set("state", clientState);
  return Response.redirect(u.toString(), 302);
}

export async function handleMcpAuthCallback(
  request: Request,
  env: Env,
): Promise<Response> {
  // ── env guard ──
  if (
    !env.MCP_OAUTH_KV ||
    !env.GITHUB_MCP_CLIENT_ID ||
    !env.GITHUB_MCP_CLIENT_SECRET ||
    !env.SSO_ENCRYPTION_KEY ||
    !env.OAUTH_STATE_SECRET ||
    !env.AUTH_WORKER_ORIGIN
  ) {
    return jsonResponse({ error: "server_error", error_description: "MCP OAuth Provider not configured" }, 503);
  }

  const url = new URL(request.url);
  const ghCode = url.searchParams.get("code");
  const stateRaw = url.searchParams.get("state");
  const ghError = url.searchParams.get("error");

  if (!stateRaw) {
    return jsonResponse({ error: "invalid_request", error_description: "state is required" }, 400);
  }

  // ── state 検証 → auth_request_id 取得 ──
  const decoded = await verifyOAuthState(stateRaw, env.OAUTH_STATE_SECRET);
  if (!decoded || decoded.provider !== "github_mcp_authcode" || !decoded.auth_request_id) {
    return jsonResponse({ error: "invalid_request", error_description: "state could not be verified" }, 400);
  }
  const reqRec = await getAuthRequest(env, decoded.auth_request_id);
  if (!reqRec) {
    return jsonResponse({ error: "invalid_request", error_description: "auth request expired or not found" }, 400);
  }

  // ── GitHub 側 user キャンセル ──
  if (ghError) {
    await deleteAuthRequest(env, reqRec.id);
    return redirectError(
      reqRec.redirect_uri,
      "access_denied",
      "GitHub authorization was cancelled or denied",
      reqRec.client_state,
    );
  }
  if (!ghCode) {
    return jsonResponse({ error: "invalid_request", error_description: "code is required" }, 400);
  }

  // ── GitHub token exchange ──
  const issuer = env.AUTH_WORKER_ORIGIN;
  const callbackUri = `${issuer}/mcp/auth_callback`;
  let ghToken: string;
  try {
    const ghResp = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "auth-worker-mcp-oauth",
      },
      body: new URLSearchParams({
        client_id: env.GITHUB_MCP_CLIENT_ID,
        client_secret: env.GITHUB_MCP_CLIENT_SECRET,
        code: ghCode,
        redirect_uri: callbackUri,
      }),
    });
    if (!ghResp.ok) throw new Error(`token exchange status ${ghResp.status}`);
    const ghBody = (await ghResp.json()) as { access_token?: string; error?: string };
    if (!ghBody.access_token) {
      throw new Error(ghBody.error ?? "no access_token in response");
    }
    ghToken = ghBody.access_token;
  } catch {
    await deleteAuthRequest(env, reqRec.id);
    return redirectError(
      reqRec.redirect_uri,
      "server_error",
      "Failed to exchange authorization code with GitHub",
      reqRec.client_state,
    );
  }

  // ── GitHub user fetch ──
  let login: string;
  try {
    const userResp = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${ghToken}`,
        "User-Agent": "auth-worker-mcp-oauth",
        Accept: "application/vnd.github+json",
      },
    });
    if (!userResp.ok) throw new Error(`user status ${userResp.status}`);
    const user = (await userResp.json()) as { login?: string };
    if (!user.login) throw new Error("login missing");
    login = user.login;
  } catch {
    await deleteAuthRequest(env, reqRec.id);
    return redirectError(
      reqRec.redirect_uri,
      "server_error",
      "Failed to fetch GitHub user information",
      reqRec.client_state,
    );
  }

  // ── ACL (fail-closed) ──
  const allowlist = parseAllowlist(env.GITHUB_MCP_USER_ALLOWLIST);
  if (!allowlist.includes(login)) {
    await deleteAuthRequest(env, reqRec.id);
    return redirectError(
      reqRec.redirect_uri,
      "access_denied",
      "Your GitHub account is not authorized to use this MCP server",
      reqRec.client_state,
    );
  }

  // ── success: github_token 暗号化保管 + auth code 発行 ──
  const sub = `github:${login}`;
  const encrypted = await encryptWithKey(ghToken, env.SSO_ENCRYPTION_KEY);
  await env.MCP_OAUTH_KV.put(`github_token:${sub}`, encrypted, {
    expirationTtl: GITHUB_TOKEN_TTL_SEC,
  });

  const code = crypto.randomUUID();
  const codeRec: AuthCodeRecord = {
    code,
    client_id: reqRec.client_id,
    redirect_uri: reqRec.redirect_uri,
    code_challenge: reqRec.code_challenge,
    code_challenge_method: "S256",
    github_login: login,
    scope: reqRec.scope,
    // RFC 8707 Resource Indicator を `/authorize` から token endpoint に伝播。
    // 未指定 (legacy client) は AuthCodeRecord 側も undefined のまま。
    ...(reqRec.resource !== undefined ? { resource: reqRec.resource } : {}),
    expires_at: Date.now() + AUTH_CODE_TTL_SEC * 1000,
  };
  await putAuthCode(env, codeRec);
  await deleteAuthRequest(env, reqRec.id);

  // ── client redirect_uri に code + 元 state を載せて戻す ──
  const dest = new URL(reqRec.redirect_uri);
  dest.searchParams.set("code", code);
  if (reqRec.client_state) dest.searchParams.set("state", reqRec.client_state);
  return Response.redirect(dest.toString(), 302);
}
