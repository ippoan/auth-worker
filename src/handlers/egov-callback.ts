/**
 * e-Gov (Keycloak) OAuth delegation — callback.
 *
 * e-Gov redirects here with ?code=...&state=... after the user authenticates.
 * We verify the state (HMAC), pull code_verifier + original redirect_uri out,
 * exchange the code for tokens at e-Gov's /token endpoint, and forward the
 * tokens to the original client via URL fragment.
 *
 * Fragment format (consumed by the client's /callback page):
 *   #access_token=<at>&refresh_token=<rt>&expires_in=<s>&token_type=Bearer[&id_token=<it>]
 */

import type { Env } from "../index";
import { getAllowedOrigins } from "../lib/config";
import { verifyOAuthState, isAllowedRedirectUri } from "../lib/security";

export async function handleEgovCallback(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");
  const errorParam = url.searchParams.get("error");

  console.log(JSON.stringify({ event: "egov_callback", hasCode: !!code, error: errorParam }));

  if (errorParam) {
    return new Response(`e-Gov OAuth error: ${errorParam}`, { status: 400 });
  }
  if (!code || !stateParam) {
    return new Response("Missing code or state parameter", { status: 400 });
  }

  if (!env.EGOV_CLIENT_ID || !env.EGOV_CLIENT_SECRET || !env.EGOV_AUTH_BASE) {
    return new Response("e-Gov OAuth not configured", { status: 503 });
  }

  const stateData = await verifyOAuthState(stateParam, env.OAUTH_STATE_SECRET);
  if (!stateData) {
    return new Response("Invalid state parameter", { status: 400 });
  }

  const { redirect_uri: redirectUri, code_verifier: codeVerifier } = stateData;
  if (!codeVerifier) {
    return new Response("Missing code_verifier in state", { status: 400 });
  }
  if (!isAllowedRedirectUri(redirectUri, await getAllowedOrigins(env))) {
    return new Response("Invalid redirect_uri in state", { status: 400 });
  }

  const tokenEndpoint = `${env.EGOV_AUTH_BASE}/token`;
  const basicAuth = btoa(`${env.EGOV_CLIENT_ID}:${env.EGOV_CLIENT_SECRET}`);

  const tokenResp = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicAuth}`,
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: `${env.AUTH_WORKER_ORIGIN}/oauth/egov/callback`,
      code_verifier: codeVerifier,
    }),
  });

  if (!tokenResp.ok) {
    const errorText = await tokenResp.text();
    console.error(JSON.stringify({ event: "egov_token_exchange_failed", status: tokenResp.status, error: errorText }));
    return new Response(`e-Gov token exchange failed: ${errorText}`, { status: 502 });
  }

  const tokenData = (await tokenResp.json()) as {
    access_token: string;
    refresh_token?: string;
    expires_in: number;
    token_type?: string;
    id_token?: string;
  };

  const fragment = new URLSearchParams({
    access_token: tokenData.access_token,
    expires_in: String(tokenData.expires_in),
    token_type: tokenData.token_type ?? "Bearer",
  });
  if (tokenData.refresh_token) fragment.set("refresh_token", tokenData.refresh_token);
  if (tokenData.id_token) fragment.set("id_token", tokenData.id_token);

  console.log(JSON.stringify({ event: "egov_login_success", redirectUri }));
  return Response.redirect(`${redirectUri}#${fragment.toString()}`, 302);
}
