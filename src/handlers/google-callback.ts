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
import { resolveSecret } from "../lib/secret";
import { verifyOAuthState, isAllowedRedirectUri } from "../lib/security";
import { decodeJwtPayload } from "../lib/jwt";
import { finishLogin } from "../lib/finish-login";
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

  return finishLogin(request, env, {
    token,
    expiresAt,
    tenantId: user.tenant_id,
    email: user.email,
    redirectUri,
    joinOrg,
    eventPrefix: "google_login",
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
