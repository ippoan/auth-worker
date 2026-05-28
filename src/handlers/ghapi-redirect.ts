/**
 * Google Health API OAuth redirect handler.
 *
 *   `GET /oauth/ghapi/redirect?redirect_uri=<target>`
 *
 * `ippoan/HealthConnectReaderWorker` の Google Health 連携用 OAuth 起点。
 * `redirect_uri` (= hcreader-worker の `/api/ghapi/connected`) を state に
 * 埋めて Google authorize endpoint へ 302。callback (`/oauth/ghapi/callback`)
 * で code → tokens 交換後に hcreader へ refresh_token を内部 POST し、
 * 最後に `redirect_uri` へ戻す。
 *
 * 既存ログイン用 (`/oauth/google/redirect`) と別 OAuth Client を使う:
 *   - Google Cloud で `auth-staging.ippoan.org/oauth/ghapi/callback` を redirect
 *     URI として registered した OAuth Client (`GOOGLE_HEALTH_CLIENT_ID`)
 *   - scope は Google Fit API (Exercise / heart rate / location / body) +
 *     openid email。`GOOGLE_HEALTH_SCOPES` env var で override 可。
 *   - `access_type=offline` + `prompt=consent` で refresh_token を必ず取得。
 *
 * Refs ippoan/HealthConnectReaderWorker#60, #61
 */

import type { Env } from "../index";
import { getAllowedOrigins } from "../lib/config";
import { resolveSecret } from "../lib/secret";
import { isAllowedRedirectUri, generateOAuthState } from "../lib/security";

const DEFAULT_GHAPI_SCOPES = [
  "openid",
  "email",
  "https://www.googleapis.com/auth/fitness.activity.read",
  "https://www.googleapis.com/auth/fitness.heart_rate.read",
  "https://www.googleapis.com/auth/fitness.location.read",
  "https://www.googleapis.com/auth/fitness.body.read",
].join(" ");

export async function handleGhapiRedirect(
  request: Request,
  env: Env,
): Promise<Response> {
  const clientId = await resolveSecret(env.GOOGLE_HEALTH_CLIENT_ID);
  if (!clientId) {
    return new Response("Google Health OAuth not configured", { status: 503 });
  }

  const url = new URL(request.url);
  const redirectUri = url.searchParams.get("redirect_uri");

  if (!redirectUri || !isAllowedRedirectUri(redirectUri, await getAllowedOrigins(env))) {
    return new Response("Invalid or missing redirect_uri", { status: 400 });
  }

  console.log(JSON.stringify({ event: "ghapi_redirect", redirectUri }));

  const state = await generateOAuthState(
    redirectUri,
    env.OAUTH_STATE_SECRET,
    { provider: "ghapi" },
  );

  const scope = env.GOOGLE_HEALTH_SCOPES || DEFAULT_GHAPI_SCOPES;

  const googleAuthUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  googleAuthUrl.searchParams.set("client_id", clientId);
  googleAuthUrl.searchParams.set(
    "redirect_uri",
    `${env.AUTH_WORKER_ORIGIN}/oauth/ghapi/callback`,
  );
  googleAuthUrl.searchParams.set("response_type", "code");
  googleAuthUrl.searchParams.set("scope", scope);
  googleAuthUrl.searchParams.set("state", state);
  googleAuthUrl.searchParams.set("access_type", "offline");
  googleAuthUrl.searchParams.set("prompt", "consent");
  googleAuthUrl.searchParams.set("include_granted_scopes", "true");

  return Response.redirect(googleAuthUrl.toString(), 302);
}
