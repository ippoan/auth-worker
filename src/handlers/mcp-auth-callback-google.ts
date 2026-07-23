/**
 * `GET /mcp/auth_callback_google?code=...&state=...`
 *
 * MCP OAuth に Google IdP を追加 — Authorization Code 用の Google OAuth callback。
 * `mcp-auth-callback.ts` (GitHub 版) と同じ役割の Google 版。別 URL に分離するのは
 * `mcp-auth-callback.ts` の先例 (device flow 用 `/mcp/device_callback` と分離) と
 * 同じ理由: state の provider で 1 handler 内分岐するより routing を URL 単位で
 * 分けたほうがシンプル。
 *
 * Process:
 *   1. state 検証 + provider="google_mcp_authcode" + auth_request_id 取得
 *   2. KV `auth:request:<id>` lookup → {client_id, redirect_uri, code_challenge, scope, client_state}
 *   3. Google `oauth2.googleapis.com/token` で code → id_token 交換
 *      (`env.GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` — 既存ログイン用と同一クライアントを
 *      流用。MCP 用途も既存ログインも scope は `openid email` のみで機能的に同一なため、
 *      GitHub 側 `GITHUB_MCP_CLIENT_ID` のような専用クライアント分離は不要と判断)
 *   4. id_token の claims を decode (`decodeJwtPayload`、`google-callback.ts` と同じ —
 *      Google token endpoint から TLS 直接受信のため署名検証は省略、email_verified のみ確認)
 *   5. ACL 検証 (fail-closed、KV `google-mcp-user-allowlist` — `lib/config.ts` 参照)
 *   6. auth code (UUID) 生成 → KV `auth:code:<code>` 保存 (TTL 5m)、`email` を積む
 *      (GitHub 版と異なり **github_token 相当の生トークンは保存しない** — Google API を
 *      代理呼び出しする用途が無いため)
 *   7. auth request 削除
 *   8. client redirect_uri へ 302 (`?code=<auth_code>&state=<client_state>`)
 *
 * エラー時 (token exchange 失敗 / id_token 欠落 / email_verified:false / ACL deny):
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
import { getGoogleMcpUserAllowlist } from "../lib/config";
import { jsonResponse } from "../lib/errors";
import { decodeJwtPayload } from "../lib/jwt";
import { resolveSecret } from "../lib/secret";
import { verifyOAuthState } from "../lib/security";

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

export async function handleMcpAuthCallbackGoogle(
  request: Request,
  env: Env,
): Promise<Response> {
  // ── env guard ──
  const googleClientId = await resolveSecret(env.GOOGLE_CLIENT_ID);
  const googleClientSecret = await resolveSecret(env.GOOGLE_CLIENT_SECRET);
  if (
    !env.MCP_OAUTH_KV ||
    !googleClientId ||
    !googleClientSecret ||
    !env.OAUTH_STATE_SECRET ||
    !env.AUTH_WORKER_ORIGIN
  ) {
    return jsonResponse({ error: "server_error", error_description: "MCP OAuth Provider not configured" }, 503);
  }

  const url = new URL(request.url);
  const googleCode = url.searchParams.get("code");
  const stateRaw = url.searchParams.get("state");
  const googleError = url.searchParams.get("error");

  if (!stateRaw) {
    return jsonResponse({ error: "invalid_request", error_description: "state is required" }, 400);
  }

  // ── state 検証 → auth_request_id 取得 ──
  const decoded = await verifyOAuthState(stateRaw, env.OAUTH_STATE_SECRET);
  if (!decoded || decoded.provider !== "google_mcp_authcode" || !decoded.auth_request_id) {
    return jsonResponse({ error: "invalid_request", error_description: "state could not be verified" }, 400);
  }
  const reqRec = await getAuthRequest(env, decoded.auth_request_id);
  if (!reqRec) {
    return jsonResponse({ error: "invalid_request", error_description: "auth request expired or not found" }, 400);
  }

  // ── Google 側 user キャンセル ──
  if (googleError) {
    await deleteAuthRequest(env, reqRec.id);
    return redirectError(
      reqRec.redirect_uri,
      "access_denied",
      "Google authorization was cancelled or denied",
      reqRec.client_state,
    );
  }
  if (!googleCode) {
    return jsonResponse({ error: "invalid_request", error_description: "code is required" }, 400);
  }

  // ── Google token exchange (id_token を要求) ──
  const issuer = env.AUTH_WORKER_ORIGIN;
  const callbackUri = `${issuer}/mcp/auth_callback_google`;
  let idToken: string;
  try {
    const tokenResp = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code: googleCode,
        client_id: googleClientId,
        client_secret: googleClientSecret,
        redirect_uri: callbackUri,
        grant_type: "authorization_code",
      }),
    });
    if (!tokenResp.ok) throw new Error(`token exchange status ${tokenResp.status}`);
    const tokenBody = (await tokenResp.json()) as { id_token?: string; error?: string };
    if (!tokenBody.id_token) {
      throw new Error(tokenBody.error ?? "no id_token in response");
    }
    idToken = tokenBody.id_token;
  } catch {
    await deleteAuthRequest(env, reqRec.id);
    return redirectError(
      reqRec.redirect_uri,
      "server_error",
      "Failed to exchange authorization code with Google",
      reqRec.client_state,
    );
  }

  // ── id_token claims decode ──
  // Google token endpoint から TLS で直接受け取ったものなので署名検証は省略し
  // claims を decode する (google-callback.ts と同じ判断)。email_verified のみ確認。
  const idClaims = decodeJwtPayload(idToken) as {
    email?: string;
    email_verified?: boolean;
  } | null;
  if (!idClaims || !idClaims.email || idClaims.email_verified !== true) {
    await deleteAuthRequest(env, reqRec.id);
    return redirectError(
      reqRec.redirect_uri,
      "server_error",
      "Failed to fetch verified Google account email",
      reqRec.client_state,
    );
  }
  const email = idClaims.email.toLowerCase();

  // ── ACL (fail-closed) ──
  const allowlist = parseAllowlist(await getGoogleMcpUserAllowlist(env));
  if (!allowlist.includes(email)) {
    await deleteAuthRequest(env, reqRec.id);
    return redirectError(
      reqRec.redirect_uri,
      "access_denied",
      "Your Google account is not authorized to use this MCP server",
      reqRec.client_state,
    );
  }

  // ── success: auth code 発行 (github_token 相当の保存は無い) ──
  const code = crypto.randomUUID();
  const codeRec: AuthCodeRecord = {
    code,
    client_id: reqRec.client_id,
    redirect_uri: reqRec.redirect_uri,
    code_challenge: reqRec.code_challenge,
    code_challenge_method: "S256",
    email,
    scope: reqRec.scope,
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
