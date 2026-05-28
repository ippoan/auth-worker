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

// Google Health API v4 (`health.googleapis.com/v4/users/me/dataTypes/...`) 用 scope。
// 旧 Google Fit (`fitness.*`) とは別物。hcreader-worker が叩く 2 dataType が
// それぞれ別 scope を要求する:
//   - exercise (session)   → googlehealth.activity_and_fitness.readonly
//   - heart-rate (sample)  → googlehealth.health_metrics_and_measurements.readonly
// 両方付けないと HR 時系列取得が 403 PERMISSION_DENIED になる。
// scope を変えたら user は disconnect → reconnect で再認証が必要。
// Refs ippoan/HealthConnectReaderWorker#60
const DEFAULT_GHAPI_SCOPES = [
  "openid",
  "email",
  "https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly",
  "https://www.googleapis.com/auth/googlehealth.health_metrics_and_measurements.readonly",
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
