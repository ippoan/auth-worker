/**
 * Google OAuth callback handler (REST version)
 *
 * code 交換 → id_token decode → rust internal 経路で user find-or-create →
 * auth-worker 自身の鍵で JWT 発行 (Refs rust-alc-api#479 — 旧 `/api/auth/google`
 * は撤去済みで、rust は JWT を発行しない dumb backend)。LINE / LINE WORKS の
 * callback と同じ internal パターン。
 */

import type { Env } from "../index";
import { getAllowedOrigins } from "../lib/config";
import { checkOrgAccess, checkAppTenant } from "../lib/acl";
import { resolveSecret } from "../lib/secret";
import { verifyOAuthState, isAllowedRedirectUri } from "../lib/security";
import { setAuthCookie, authCookieReachesHost } from "../lib/cookies";
import { decodeJwtPayload } from "../lib/jwt";
import { upsertGoogleUser, type InternalUserWithSlug } from "../lib/alc-internal";
import { createAccessToken, ACCESS_TOKEN_EXPIRY_SECS } from "../lib/access-token";

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

  // id_token は Google token endpoint から TLS で直接受け取ったものなので署名検証は
  // 省略して claims を decode する。旧 rust `/api/auth/google` の verify() が担っていた
  // email_verified チェックのみ引き継ぐ。
  const idClaims = decodeJwtPayload(tokenData.id_token) as {
    sub?: string;
    email?: string;
    name?: string;
    email_verified?: boolean;
  } | null;
  if (!idClaims?.sub || !idClaims.email) {
    return redirectToLogin(origin, redirectUri, "Invalid ID token");
  }
  if (idClaims.email_verified !== true) {
    return redirectToLogin(origin, redirectUri, "Google アカウントのメールアドレスが未確認です");
  }

  // rust internal 経路で user を find-or-create する。tenant 解決 (招待 →
  // email_domain → STAGING_MODE 自動作成 → 403) は rust 側 upsert-google が担う。
  let user: InternalUserWithSlug | null;
  try {
    user = await upsertGoogleUser(env, {
      google_sub: idClaims.sub,
      email: idClaims.email,
      name: idClaims.name ?? "",
    });
  } catch (e) {
    console.log(JSON.stringify({ event: "google_login_failure", error: String(e) }));
    return redirectToLogin(origin, redirectUri, "ログイン処理に失敗しました");
  }
  if (!user) {
    console.log(JSON.stringify({ event: "google_login_no_tenant", email: idClaims.email }));
    return redirectToLogin(
      origin,
      redirectUri,
      "このメールアドレスはどのテナントにも登録されていません",
    );
  }

  // auth-worker 自身の JWT_SECRET で access JWT を発行 (rust と同形 claims、
  // /top ゲート・introspect と鍵が一致する)。
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) {
    return new Response("JWT secret not configured", { status: 503 });
  }
  const token = await createAccessToken(
    { id: user.id, email: user.email, name: user.name, tenant_id: user.tenant_id, role: user.role },
    jwtSecret,
    user.slug,
  );
  const expiresAt = String(Math.floor(Date.now() / 1000) + ACCESS_TOKEN_EXPIRY_SECS);
  const tenantId = user.tenant_id;
  const email = user.email;

  // Build JWT fragment (cookie が届かない host へ fragment 配布)
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
