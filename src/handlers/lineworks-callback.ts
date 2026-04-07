/**
 * LINE WORKS OAuth callback handler (REST version)
 * Proxies the OAuth callback to rust-alc-api which handles code exchange + JWT issuance
 */

import type { Env } from "../index";
import { verifyOAuthState, isAllowedRedirectUri } from "../lib/security";
import { setAuthCookie } from "../lib/cookies";

export async function handleLineworksCallback(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const origin = url.origin;
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");
  const errorParam = url.searchParams.get("error");

  console.log(JSON.stringify({ event: "lw_callback", hasCode: !!code, error: errorParam }));

  if (errorParam) {
    return new Response(`LINE WORKS OAuth error: ${errorParam}`, { status: 400 });
  }

  if (!code || !stateParam) {
    return new Response("Missing code or state parameter", { status: 400 });
  }

  // Verify HMAC-signed state and extract redirect_uri + provider info
  const stateData = await verifyOAuthState(stateParam, env.OAUTH_STATE_SECRET);
  if (!stateData) {
    return new Response("Invalid state parameter", { status: 400 });
  }

  const { redirect_uri: redirectUri, provider, external_org_id: externalOrgId, join_org: joinOrg } = stateData;

  if (!redirectUri || !isAllowedRedirectUri(redirectUri, env.ALLOWED_REDIRECT_ORIGINS)) {
    return new Response("Invalid redirect_uri in state", { status: 400 });
  }

  if (!provider || !externalOrgId) {
    return new Response("Missing provider info in state", { status: 400 });
  }

  // Proxy to rust-alc-api callback endpoint with the original query parameters
  // rust-alc-api handles code exchange → user upsert → JWT issuance
  const callbackUrl = new URL(`${env.ALC_API_ORIGIN}/api/auth/lineworks/callback`);
  callbackUrl.searchParams.set("code", code);
  callbackUrl.searchParams.set("state", stateParam);

  const resp = await fetch(callbackUrl.toString(), { redirect: "manual" });

  // If rust-alc-api returns a redirect (302), extract the JWT from the Location fragment
  if (resp.status === 302 || resp.status === 307) {
    const location = resp.headers.get("Location");
    if (location) {
      // Extract token from fragment for Set-Cookie
      const headers: HeadersInit = { Location: location };
      const fragIdx = location.indexOf("#");
      if (fragIdx !== -1) {
        const frag = new URLSearchParams(location.slice(fragIdx + 1));
        const token = frag.get("token");
        if (token) headers["Set-Cookie"] = setAuthCookie(token, new URL(request.url).hostname);
      }
      return new Response(null, { status: 302, headers });
    }
  }

  // If rust-alc-api returns JSON (direct response)
  if (resp.ok) {
    const authData = (await resp.json()) as {
      token: string;
      expires_at: string;
    };

    const fragment = new URLSearchParams({
      token: authData.token,
      expires_at: authData.expires_at,
    });

    // Extract org_id from JWT payload
    const payloadB64 = authData.token.split(".")[1];
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
      console.log(JSON.stringify({ event: "lw_login_join", joinOrg, externalOrgId }));
      return new Response(null, {
        status: 302,
        headers: {
          Location: `${joinDoneUrl.toString()}#${fragment.toString()}`,
          "Set-Cookie": setAuthCookie(authData.token, new URL(request.url).hostname),
        },
      });
    }

    // Normal flow
    const finalUrl = new URL(redirectUri);
    if (!finalUrl.searchParams.has("lw_callback")) {
      finalUrl.searchParams.set("lw_callback", "1");
    }

    // JWT は URL fragment (#token=xxx) で渡す。クライアント側で sessionStorage に保存。
    console.log(JSON.stringify({ event: "lw_login_success", externalOrgId, redirectUri }));
    return new Response(null, {
      status: 302,
      headers: {
        Location: `${finalUrl.toString()}#${fragment.toString()}`,
        "Set-Cookie": setAuthCookie(authData.token, new URL(request.url).hostname),
      },
    });
  }

  // Error from backend
  const errorText = await resp.text();
  console.log(JSON.stringify({ event: "lw_login_failure", externalOrgId, error: errorText }));
  return redirectToLogin(origin, redirectUri, errorText);
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
