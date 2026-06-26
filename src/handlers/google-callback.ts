/**
 * Google OAuth callback handler (REST version)
 * Exchanges authorization code for id_token, then calls rust-alc-api to authenticate
 */

import type { Env } from "../index";
import { getAllowedOrigins } from "../lib/config";
import { checkOrgAccess, checkAppTenant } from "../lib/acl";
import { resolveSecret } from "../lib/secret";
import { verifyOAuthState, isAllowedRedirectUri } from "../lib/security";
import { setAuthCookie, authCookieReachesHost } from "../lib/cookies";
import { signJwt, decodeJwtPayload } from "../lib/jwt";

export async function handleGoogleCallback(
  request: Request,
  env: Env,
): Promise<Response> {
  const clientId = await resolveSecret(env.GOOGLE_CLIENT_ID);
  const clientSecret = await resolveSecret(env.GOOGLE_CLIENT_SECRET);
  if (!clientId || !clientSecret) {
    return new Response("Google OAuth not configured", { status: 503 });
  }
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
  if (!isAllowedRedirectUri(redirectUri, await getAllowedOrigins(env))) {
    return new Response("Invalid redirect_uri in state", { status: 400 });
  }

  // Exchange authorization code for tokens
  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
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

  const rustToken = authData.access_token;
  const expiresAt = String(Math.floor(Date.now() / 1000) + authData.expires_in);

  // rust-alc-api の access_token は rust の鍵で署名されている。rust は #441 で JWT
  // 検証をやめた dumb backend になったので、/top + introspect が検証する cookie JWT は
  // auth-worker が署名・所有する (Refs rust-alc-api#434)。元 token の claims を取り出し、
  // auth-worker の JWT_SECRET + env=WORKER_ENV (#218 cross-env 保護) で再署名する。
  // これで staging でも prod でも auth-worker 自身の鍵で検証一致する (= rust と
  // auth-worker の鍵不整合による login 無限ループの根治)。再署名できない場合
  // (JWT_SECRET 欠落 / claims 欠落) は rust token のまま fallback (従来動作、非破壊)。
  let tenantId = "";
  let email = "";
  let token = rustToken;
  const claims = decodeJwtPayload(rustToken);
  if (claims) {
    tenantId = (claims.tenant_id as string) || (claims.org as string) || "";
    email = (claims.email as string) || "";
    const jwtSecret = await resolveSecret(env.JWT_SECRET);
    if (jwtSecret && typeof claims.exp === "number") {
      token = await signJwt({ ...claims, env: env.WORKER_ENV }, jwtSecret);
    }
  }

  // Build JWT fragment (再署名後の token を載せる。cookie が届かない host へ fragment 配布)
  const fragment = new URLSearchParams({
    token,
    expires_at: expiresAt,
  });
  if (tenantId) fragment.set("org_id", tenantId);

  // Enforce per-org ACL for the final redirect target.
  const redirectOrigin = new URL(redirectUri).origin;
  if (!(await checkOrgAccess(env, redirectOrigin, tenantId, email))) {
    console.log(JSON.stringify({ event: "google_login_acl_denied", redirectUri, tenantId, email }));
    return new Response("このアプリへのアクセスが許可されていません", { status: 403 });
  }
  // Per-app tenant partitioning (after org ACL).
  if (!checkAppTenant(env, redirectOrigin, tenantId, email)) {
    console.log(JSON.stringify({ event: "google_login_app_tenant_denied", redirectUri, tenantId, email }));
    return new Response("このアカウントはこのアプリにアクセスできません", { status: 403 });
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
  const authHostname = new URL(request.url).hostname;

  // 共有 cookie (logi_auth_token, Domain=.ippoan.org) が redirect 先に届くなら、
  // token を URL fragment に載せず cookie だけで渡す (アドレスバー/履歴に token を出さない)。
  // 届かない host (例: *.workers.dev は public suffix で Domain cookie 不可) は従来どおり
  // fragment で配布する (consumeFragment で受ける)。
  if (authCookieReachesHost(authHostname, finalUrl.hostname)) {
    console.log(JSON.stringify({ event: "google_login_success", redirectUri, delivery: "cookie" }));
    return new Response(null, {
      status: 302,
      headers: {
        Location: finalUrl.toString(),
        "Set-Cookie": setAuthCookie(token, authHostname),
      },
    });
  }

  // Fallback: cookie が届かない host へは fragment で渡す。
  if (!finalUrl.searchParams.has("lw_callback")) {
    finalUrl.searchParams.set("lw_callback", "1");
  }
  console.log(JSON.stringify({ event: "google_login_success", redirectUri, delivery: "fragment" }));
  return new Response(null, {
    status: 302,
    headers: {
      Location: `${finalUrl.toString()}#${fragment.toString()}`,
      "Set-Cookie": setAuthCookie(token, authHostname),
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
