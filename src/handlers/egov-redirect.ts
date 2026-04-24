/**
 * e-Gov (Keycloak) OAuth delegation — authorization request start.
 *
 * Client frontend (localhost / staging / worktree tunnel) redirects here with
 *   /oauth/egov/redirect?redirect_uri=<target>&idp_hint=<gbiz|...>
 *
 * We generate PKCE, embed code_verifier + idp_hint in an HMAC-signed state, and
 * redirect to e-Gov's Keycloak /auth endpoint with our own /oauth/egov/callback
 * registered as the OAuth redirect_uri.
 */

import { generatePKCE, buildAuthorizationUrl } from "@ippoan/egov-shinsei-sdk/auth";
import type { Env } from "../index";
import { getAllowedOrigins } from "../lib/config";
import { isAllowedRedirectUri, generateOAuthState } from "../lib/security";

export async function handleEgovRedirect(
  request: Request,
  env: Env,
): Promise<Response> {
  if (!env.EGOV_CLIENT_ID || !env.EGOV_AUTH_BASE) {
    return new Response("e-Gov OAuth not configured", { status: 503 });
  }

  const url = new URL(request.url);
  const redirectUri = url.searchParams.get("redirect_uri");
  const idpHint = url.searchParams.get("idp_hint") ?? undefined;

  if (!redirectUri || !isAllowedRedirectUri(redirectUri, await getAllowedOrigins(env))) {
    return new Response("Invalid or missing redirect_uri", { status: 400 });
  }

  console.log(JSON.stringify({ event: "egov_redirect", redirectUri, idpHint }));

  const { codeVerifier, codeChallenge } = await generatePKCE();

  const extra: Record<string, string> = { code_verifier: codeVerifier };
  if (idpHint) extra.idp_hint = idpHint;

  const state = await generateOAuthState(redirectUri, env.OAUTH_STATE_SECRET, extra);

  let authUrl = buildAuthorizationUrl({
    authBase: env.EGOV_AUTH_BASE,
    clientId: env.EGOV_CLIENT_ID,
    redirectUri: `${env.AUTH_WORKER_ORIGIN}/oauth/egov/callback`,
    state,
    codeChallenge,
  });
  if (idpHint) {
    authUrl += (authUrl.includes("?") ? "&" : "?") + "kc_idp_hint=" + encodeURIComponent(idpHint);
  }

  return Response.redirect(authUrl, 302);
}
