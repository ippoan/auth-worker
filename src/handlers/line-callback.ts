/**
 * LINE Login OAuth callback (rust-alc-api#434 Phase 3)。
 *
 * code 交換 → profile → tenant 解決 → JWT 発行を auth-worker で行う (rust proxy 廃止)。
 * tenant 解決の分岐 (rust `line_callback` と一致):
 *   1. 既存 user (line_user_id 一致) → そのテナントでログイン
 *   2. QR 招待 (state に tenant_id) → recipient 登録 + user 作成 → ログイン
 *   3. recipients 逆引き: 0 件 → エラー / 1 件 → 自動ログイン / 複数 → select-tenant へ
 */
import type { Env } from "../index";
import { getAllowedOrigins } from "../lib/config";
import { verifyOAuthState, isAllowedRedirectUri } from "../lib/security";
import { setAuthCookie } from "../lib/cookies";
import { resolveSecret } from "../lib/secret";
import { exchangeCode, fetchProfile } from "../lib/line-oauth";
import { signSelectToken } from "../lib/line-select-token";
import {
  findUserByLineId,
  upsertLineUser,
  registerLineRecipient,
  recipientsByLineId,
  saveRefreshToken,
  type InternalUserWithSlug,
} from "../lib/alc-internal";
import {
  createAccessToken,
  createRefreshToken,
  refreshTokenExpiresAt,
  ACCESS_TOKEN_EXPIRY_SECS,
} from "../lib/access-token";

/** access JWT + refresh を発行し、cookie + `#token` fragment で redirect する共通処理。 */
async function issueLineJwt(
  env: Env,
  jwtSecret: string,
  user: InternalUserWithSlug,
  redirectUri: string,
  hostname: string,
): Promise<Response> {
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
  const fragment = new URLSearchParams({
    token,
    refresh_token: refresh.raw,
    expires_in: String(ACCESS_TOKEN_EXPIRY_SECS),
    lw_callback: "1",
  });
  return new Response(null, {
    status: 302,
    headers: {
      Location: `${redirectUri}#${fragment.toString()}`,
      "Set-Cookie": setAuthCookie(token, hostname),
    },
  });
}

export async function handleLineCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");
  const errorParam = url.searchParams.get("error");

  if (errorParam) {
    return new Response(`LINE OAuth error: ${errorParam}`, { status: 400 });
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

  const channelId = await resolveSecret(env.LINE_LOGIN_CHANNEL_ID);
  const channelSecret = await resolveSecret(env.LINE_LOGIN_CHANNEL_SECRET);
  if (!channelId || !channelSecret) {
    return new Response("line login not configured", { status: 503 });
  }
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) {
    return new Response("server_error", { status: 503 });
  }

  const callbackUri = `${url.origin}/oauth/line/callback`;
  let lineUserId: string;
  let name: string;
  try {
    const tokenResp = await exchangeCode(channelId, channelSecret, code, callbackUri);
    const profile = await fetchProfile(tokenResp.access_token);
    lineUserId = profile.userId;
    name = profile.displayName;
  } catch {
    console.log(JSON.stringify({ event: "line_oauth_upstream_failed" }));
    return new Response("LINE upstream error", { status: 502 });
  }

  // 1) 既存ユーザー → そのテナントでログイン。
  const existing = await findUserByLineId(env, lineUserId);
  if (existing) {
    return issueLineJwt(env, jwtSecret, existing, redirectUri, url.hostname);
  }

  // 2) QR 招待 (tenant 指定) → recipient 登録 + user 作成。
  if (externalOrgId) {
    await registerLineRecipient(env, {
      tenant_id: externalOrgId,
      name,
      line_user_id: lineUserId,
    }).catch(() => {}); // 既存登録は無視 (rust と同じく best-effort)。
    const user = await upsertLineUser(env, {
      tenant_id: externalOrgId,
      line_user_id: lineUserId,
      name,
    });
    return issueLineJwt(env, jwtSecret, user, redirectUri, url.hostname);
  }

  // 3) recipients 逆引き。
  const tenants = await recipientsByLineId(env, lineUserId);
  const sep = redirectUri.includes("?") ? "&" : "?";
  if (tenants.length === 0) {
    const msg = encodeURIComponent("招待 QR コードからログインしてください");
    return new Response(null, {
      status: 302,
      headers: { Location: `${redirectUri}${sep}error=${msg}` },
    });
  }
  if (tenants.length === 1) {
    const user = await upsertLineUser(env, {
      tenant_id: tenants[0]!.tenant_id,
      line_user_id: lineUserId,
      name,
    });
    return issueLineJwt(env, jwtSecret, user, redirectUri, url.hostname);
  }
  // 複数 → テナント選択画面へ。生 line_user_id を URL に晒さず、署名済み短命
  // select_token に封入して **fragment** で渡す (auth bypass / Referer leak 防止、Refs #434)。
  const selectToken = await signSelectToken(
    { line_user_id: lineUserId, line_name: name },
    env.OAUTH_STATE_SECRET,
  );
  // line_name は表示用 (auth には使わない、select-tenant は token 内の値を使う) なので
  // fragment に同梱して front-end の「<name> さん」表示に供する。line_user_id は token 内のみ。
  const tenantList = JSON.stringify(tenants.map((t) => ({ id: t.tenant_id, name: t.name })));
  const frag = new URLSearchParams({ select_token: selectToken, line_name: name, tenants: tenantList });
  return new Response(null, { status: 302, headers: { Location: `${redirectUri}#${frag.toString()}` } });
}
