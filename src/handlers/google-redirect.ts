import type { Env } from "../index";
import { isAllowedRedirectUri, generateOAuthState } from "../lib/security";

export async function handleGoogleRedirect(
  request: Request,
  env: Env,
): Promise<Response> {
  if (!env.GOOGLE_CLIENT_ID) {
    return new Response("Google OAuth not configured", { status: 503 });
  }

  const url = new URL(request.url);
  const redirectUri = url.searchParams.get("redirect_uri");

  if (!redirectUri || !isAllowedRedirectUri(redirectUri, env.ALLOWED_REDIRECT_ORIGINS)) {
    return new Response("Invalid or missing redirect_uri", { status: 400 });
  }

  const joinOrg = url.searchParams.get("join_org");
  console.log(JSON.stringify({ event: "google_redirect", redirectUri, joinOrg }));

  // Generate HMAC-signed state with embedded redirect_uri (+ optional join_org)
  const extra: Record<string, string> = {};
  if (joinOrg) extra.join_org = joinOrg;
  const state = await generateOAuthState(redirectUri, env.OAUTH_STATE_SECRET, Object.keys(extra).length > 0 ? extra : undefined);

  // Build Google OAuth authorization URL
  const googleAuthUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  googleAuthUrl.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
  googleAuthUrl.searchParams.set(
    "redirect_uri",
    `${env.AUTH_WORKER_ORIGIN}/oauth/google/callback`,
  );
  googleAuthUrl.searchParams.set("response_type", "code");
  googleAuthUrl.searchParams.set("scope", "openid email profile");
  googleAuthUrl.searchParams.set("state", state);
  googleAuthUrl.searchParams.set("access_type", "online");
  googleAuthUrl.searchParams.set("prompt", "select_account");

  return Response.redirect(googleAuthUrl.toString(), 302);
}
