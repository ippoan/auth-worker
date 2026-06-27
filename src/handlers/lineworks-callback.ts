/**
 * LINE WORKS OAuth callback (rust-alc-api#434 Phase 2)。
 *
 * 旧実装は rust-alc-api `/api/auth/lineworks/callback` への proxy だったが、認証
 * オーケストレーション (code 交換 → profile → user upsert → JWT 発行) を auth-worker に
 * 移管。DB 操作は rust internal endpoint (`/api/internal/auth/*`) 越しに行い、rust は
 * dumb data backend に徹する。token / cookie は auth-worker が発行・set する。
 */
import type { Env } from "../index";
import { getAllowedOrigins } from "../lib/config";
import { checkOrgAccess, checkAppTenant } from "../lib/acl";
import { verifyOAuthState, isAllowedRedirectUri } from "../lib/security";
import { setAuthCookie } from "../lib/cookies";
import { resolveSecret } from "../lib/secret";
import { decryptBotSecret } from "../lib/lineworks-crypto";
import { resolveSsoConfig, upsertLineworksUser, saveRefreshToken } from "../lib/alc-internal";
import { exchangeCode, fetchUserProfile, displayName, emailOrId } from "../lib/lineworks-oauth";
import {
  createAccessToken,
  createRefreshToken,
  refreshTokenExpiresAt,
  ACCESS_TOKEN_EXPIRY_SECS,
} from "../lib/access-token";

export async function handleLineworksCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
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

  const stateData = await verifyOAuthState(stateParam, env.OAUTH_STATE_SECRET);
  if (!stateData) {
    return new Response("Invalid state parameter", { status: 400 });
  }
  const { redirect_uri: redirectUri, external_org_id: externalOrgId } = stateData;

  if (!redirectUri || !isAllowedRedirectUri(redirectUri, await getAllowedOrigins(env))) {
    return new Response("Invalid redirect_uri in state", { status: 400 });
  }
  if (!externalOrgId) {
    return new Response("Missing external_org_id in state", { status: 400 });
  }

  // SSO 設定を internal で解決 (callback では external_org_id をキーに引く)。
  const config = await resolveSsoConfig(env, "lineworks", externalOrgId);
  if (!config) {
    return new Response("SSO config not found", { status: 400 });
  }

  // client_secret を復号 (AES-256-GCM、SSO_ENCRYPTION_KEY、無ければ JWT_SECRET fallback)。
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) {
    return new Response("server_error", { status: 503 });
  }
  const ssoKey = (await resolveSecret(env.SSO_ENCRYPTION_KEY)) || jwtSecret;
  let clientSecret: string;
  try {
    clientSecret = await decryptBotSecret(config.client_secret_encrypted, ssoKey);
  } catch (e: unknown) {
    console.log(JSON.stringify({ event: "lw_secret_decrypt_failed" }));
    return new Response("server_error", { status: 500 });
  }

  // callback URI は redirect 時と同一 (auth-worker 自身)。
  const callbackUri = `${url.origin}/oauth/lineworks/callback`;

  // code → token → profile。
  let profile: Awaited<ReturnType<typeof fetchUserProfile>>;
  try {
    const tokenResp = await exchangeCode(config.client_id, clientSecret, code, callbackUri);
    profile = await fetchUserProfile(tokenResp.access_token);
  } catch (e: unknown) {
    console.log(JSON.stringify({ event: "lw_oauth_upstream_failed" }));
    return new Response("LINE WORKS upstream error", { status: 502 });
  }

  // user upsert + tenant slug (rust internal)。
  const user = await upsertLineworksUser(env, {
    tenant_id: config.tenant_id,
    lineworks_id: profile.userId,
    email: emailOrId(profile),
    name: displayName(profile),
  });

  // per-org ACL (アプリ origin 単位)。
  const redirectOrigin = new URL(redirectUri).origin;
  if (!(await checkOrgAccess(env, redirectOrigin, user.tenant_id, user.email))) {
    console.log(JSON.stringify({ event: "lw_login_acl_denied", redirectUri }));
    return new Response("このアプリへのアクセスが許可されていません", { status: 403 });
  }
  if (!checkAppTenant(env, redirectOrigin, user.tenant_id, user.email)) {
    console.log(JSON.stringify({ event: "lw_login_app_tenant_denied", redirectUri }));
    return new Response("このアカウントはこのアプリにアクセスできません", { status: 403 });
  }

  // access JWT + refresh token を発行し、refresh の hash を rust に保存。
  const token = await createAccessToken(
    { id: user.id, email: user.email, name: user.name, tenant_id: user.tenant_id, role: user.role },
    jwtSecret,
    user.slug,
  );
  const refresh = await createRefreshToken();
  await saveRefreshToken(env, {
    user_id: user.id,
    refresh_hash: refresh.hash,
    expires_at: refreshTokenExpiresAt(),
  });

  // JWT を fragment で渡す + cross-subdomain cookie (rust 旧実装と同じ contract)。
  const fragment = new URLSearchParams({
    token,
    refresh_token: refresh.raw,
    expires_in: String(ACCESS_TOKEN_EXPIRY_SECS),
    lw_callback: "1",
  });
  console.log(JSON.stringify({ event: "lw_login_success", externalOrgId, redirectUri }));
  return new Response(null, {
    status: 302,
    headers: {
      Location: `${redirectUri}#${fragment.toString()}`,
      "Set-Cookie": setAuthCookie(token, url.hostname),
    },
  });
}
