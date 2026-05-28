/**
 * Google Health API OAuth callback handler.
 *
 *   `GET /oauth/ghapi/callback?code=...&state=...`
 *
 * 1. state を verify して `redirect_uri` (= hcreader-worker landing) を復元
 * 2. code → tokens 交換 (`oauth2.googleapis.com/token`)。refresh_token と
 *    id_token を取り出す。id_token.sub を healthUserId として扱う。
 * 3. hcreader-worker `${HCREADER_WORKER_ORIGIN}/api/ghapi/store-tokens` に
 *    `Authorization: Bearer <INTERNAL_SHARED_SECRET>` で
 *    `{ refresh_token, healthUserId }` を POST。
 * 4. ブラウザを `redirect_uri` へ 302。tokens 自体は URL fragment に乗せない
 *    (= LLM context / browser history に漏らさない設計)。
 *
 * Refs ippoan/HealthConnectReaderWorker#60, #61
 */

import type { Env } from "../index";
import { getAllowedOrigins } from "../lib/config";
import { resolveSecret } from "../lib/secret";
import { verifyOAuthState, isAllowedRedirectUri } from "../lib/security";

interface GhapiTokenResponse {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
  error?: string;
  error_description?: string;
}

export async function handleGhapiCallback(
  request: Request,
  env: Env,
): Promise<Response> {
  const clientId = await resolveSecret(env.GOOGLE_HEALTH_CLIENT_ID);
  const clientSecret = await resolveSecret(env.GOOGLE_HEALTH_CLIENT_SECRET);
  const internalSecret = await resolveSecret(env.INTERNAL_SHARED_SECRET);
  if (!clientId || !clientSecret) {
    return new Response("Google Health OAuth not configured", { status: 503 });
  }
  if (!internalSecret) {
    return new Response("INTERNAL_SHARED_SECRET not configured", { status: 503 });
  }
  const hcreaderOrigin = env.HCREADER_WORKER_ORIGIN;
  if (!hcreaderOrigin) {
    return new Response("HCREADER_WORKER_ORIGIN not configured", { status: 503 });
  }

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");
  const errorParam = url.searchParams.get("error");

  console.log(JSON.stringify({ event: "ghapi_callback", hasCode: !!code, error: errorParam }));

  if (errorParam) {
    return new Response(`Google Health OAuth error: ${errorParam}`, { status: 400 });
  }
  if (!code || !stateParam) {
    return new Response("Missing code or state parameter", { status: 400 });
  }

  const stateData = await verifyOAuthState(stateParam, env.OAUTH_STATE_SECRET);
  if (!stateData) {
    return new Response("Invalid state parameter", { status: 400 });
  }

  const redirectUri = stateData.redirect_uri;
  if (!isAllowedRedirectUri(redirectUri, await getAllowedOrigins(env))) {
    return new Response("Invalid redirect_uri in state", { status: 400 });
  }

  const tokenResp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: `${env.AUTH_WORKER_ORIGIN}/oauth/ghapi/callback`,
      grant_type: "authorization_code",
    }),
  });

  if (!tokenResp.ok) {
    const text = await tokenResp.text().catch(() => "");
    console.error(JSON.stringify({ event: "ghapi_token_exchange_failed", status: tokenResp.status, body: text.slice(0, 200) }));
    return new Response(`Google token exchange failed: ${tokenResp.status}`, { status: 502 });
  }

  const tokenData = (await tokenResp.json()) as GhapiTokenResponse;
  if (tokenData.error || !tokenData.refresh_token) {
    console.error(JSON.stringify({
      event: "ghapi_token_missing_refresh",
      error: tokenData.error,
      error_description: tokenData.error_description,
    }));
    return new Response(
      `No refresh_token returned (error=${tokenData.error ?? "unknown"})`,
      { status: 502 },
    );
  }

  const healthUserId = extractSubFromIdToken(tokenData.id_token);
  if (!healthUserId) {
    return new Response("Could not extract user id from id_token", { status: 502 });
  }

  const storeResp = await fetch(`${hcreaderOrigin}/api/ghapi/store-tokens`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${internalSecret}`,
    },
    body: JSON.stringify({
      refresh_token: tokenData.refresh_token,
      healthUserId,
    }),
  });

  if (!storeResp.ok) {
    const text = await storeResp.text().catch(() => "");
    console.error(JSON.stringify({
      event: "ghapi_store_tokens_failed",
      status: storeResp.status,
      body: text.slice(0, 200),
    }));
    return new Response(
      `hcreader store-tokens failed: ${storeResp.status}`,
      { status: 502 },
    );
  }

  console.log(JSON.stringify({ event: "ghapi_callback_success", redirectUri }));
  return Response.redirect(redirectUri, 302);
}

function extractSubFromIdToken(idToken: string | undefined): string | null {
  if (!idToken) return null;
  const parts = idToken.split(".");
  if (parts.length < 2 || !parts[1]) return null;
  try {
    const payloadB64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = payloadB64 + "=".repeat((4 - (payloadB64.length % 4)) % 4);
    const payload = JSON.parse(atob(padded)) as { sub?: string };
    return typeof payload.sub === "string" && payload.sub ? payload.sub : null;
  } catch {
    return null;
  }
}
