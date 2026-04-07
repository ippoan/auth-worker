/**
 * Google OAuth callback handler (REST version)
 * Exchanges authorization code for id_token, then calls rust-alc-api to authenticate
 */

import type { Env } from "../index";
import { verifyOAuthState, isAllowedRedirectUri } from "../lib/security";
import { setAuthCookie } from "../lib/cookies";

export async function handleGoogleCallback(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const origin = url.origin;
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");
  const errorParam = url.searchParams.get("error");

  console.log(JSON.stringify({ event: "google_callback", hasCode: !!code, error: errorParam }));

  // User denied or Google returned error
  if (errorParam) {
    return new Response(`Google OAuth error: ${errorParam}`, { status: 400 });
  }

  if (!code || !stateParam) {
    return new Response("Missing code or state parameter", { status: 400 });
  }

  // Verify HMAC-signed state and extract redirect_uri
  const stateData = await verifyOAuthState(stateParam, env.OAUTH_STATE_SECRET);
  if (!stateData) {
    return new Response("Invalid state parameter", { status: 400 });
  }

  const { redirect_uri: redirectUri, join_org: joinOrg } = stateData;

  // Defense in depth: re-validate redirect_uri
  if (!isAllowedRedirectUri(redirectUri, env.ALLOWED_REDIRECT_ORIGINS)) {
    return new Response("Invalid redirect_uri in state", { status: 400 });
  }

  // Exchange authorization code for tokens
  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${env.AUTH_WORKER_ORIGIN}/oauth/google/callback`,
      grant_type: "authorization_code",
    }),
  });

  if (!tokenResponse.ok) {
    const errorText = await tokenResponse.text();
    console.error("Google token exchange failed:", errorText);
    return redirectToLogin(origin, redirectUri, "Google authentication failed");
  }

  const tokenData = (await tokenResponse.json()) as { id_token?: string };
  if (!tokenData.id_token) {
    return redirectToLogin(origin, redirectUri, "No ID token returned from Google");
  }

  // Call rust-alc-api to authenticate with Google ID token
  const authResp = await fetch(`${env.ALC_API_ORIGIN}/api/auth/google`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id_token: tokenData.id_token }),
  });

  if (!authResp.ok) {
    const errorText = await authResp.text();
    console.log(JSON.stringify({ event: "google_login_failure", error: errorText }));
    return redirectToLogin(origin, redirectUri, errorText);
  }

  const authData = (await authResp.json()) as {
    access_token: string;
    expires_in: number;
    refresh_token?: string;
  };

  const token = authData.access_token;
  const expiresAt = String(Math.floor(Date.now() / 1000) + authData.expires_in);

  // Build JWT fragment
  const fragment = new URLSearchParams({
    token,
    expires_at: expiresAt,
  });

  // Extract org_id from JWT payload
  const payloadB64 = token.split(".")[1];
  if (payloadB64) {
    try {
      const payload = JSON.parse(atob(payloadB64));
      fragment.set("org_id", payload.tenant_id || payload.org || "");
    } catch {
      // ignore decode error
    }
  }

  // Join flow: redirect to /join/:slug/done with JWT fragment
  if (joinOrg) {
    const joinDoneUrl = new URL(`${origin}/join/${joinOrg}/done`);
    console.log(JSON.stringify({ event: "google_login_join", joinOrg }));
    return new Response(null, {
      status: 302,
      headers: {
        Location: `${joinDoneUrl.toString()}#${fragment.toString()}`,
        "Set-Cookie": setAuthCookie(token, new URL(request.url).hostname),
      },
    });
  }

  // Normal flow: redirect back to original redirect_uri
  const finalUrl = new URL(redirectUri);
  if (!finalUrl.searchParams.has("lw_callback")) {
    finalUrl.searchParams.set("lw_callback", "1");
  }

  // JWT は URL fragment (#token=xxx) で渡す。クライアント側で sessionStorage に保存。
  console.log(JSON.stringify({ event: "google_login_success", redirectUri }));
  return new Response(null, {
    status: 302,
    headers: {
      Location: `${finalUrl.toString()}#${fragment.toString()}`,
      "Set-Cookie": setAuthCookie(token, new URL(request.url).hostname),
    },
  });
}

function redirectToLogin(
  origin: string,
  redirectUri: string,
  error: string,
): Response {
  const params = new URLSearchParams({
    redirect_uri: redirectUri,
    error,
  });
  return Response.redirect(`${origin}/login?${params.toString()}`, 302);
}
