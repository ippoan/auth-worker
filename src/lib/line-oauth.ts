/**
 * LINE Login (LINE Messaging API user OAuth) client (rust-alc-api#434 Phase 3)。
 *
 * rust-alc-api `crates/alc-core/src/auth_line.rs` の TypeScript 移植。notify recipient の
 * LINE Login に使う。LINE WORKS とは別チャネル (グローバル LINE Login channel)。
 *
 * - authorize: `https://access.line.me/oauth2/v2.1/authorize` (`scope=profile openid`)
 * - token: `https://api.line.me/oauth2/v2.1/token` (form, `grant_type=authorization_code`)
 * - profile: `https://api.line.me/v2/profile` (Bearer)
 */

const AUTHORIZE_ENDPOINT = "https://access.line.me/oauth2/v2.1/authorize";
const TOKEN_ENDPOINT = "https://api.line.me/oauth2/v2.1/token";
const PROFILE_ENDPOINT = "https://api.line.me/v2/profile";

/** `v2/profile` のレスポンス (rust `LineProfile` 相当)。 */
export interface LineProfile {
  userId: string;
  displayName: string;
  pictureUrl?: string;
}

/** authorize URL を構築する。`redirectUri` / `state` は encode 済みを渡す。 */
export function authorizeUrl(
  channelId: string,
  encodedRedirectUri: string,
  encodedState: string,
): string {
  return (
    `${AUTHORIZE_ENDPOINT}?response_type=code` +
    `&client_id=${channelId}` +
    `&redirect_uri=${encodedRedirectUri}` +
    `&state=${encodedState}` +
    `&scope=profile%20openid`
  );
}

/** authorization code を access token に交換する。 */
export async function exchangeCode(
  channelId: string,
  channelSecret: string,
  code: string,
  redirectUri: string,
): Promise<{ access_token: string }> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: channelId,
    client_secret: channelSecret,
  });
  const res = await fetch(TOKEN_ENDPOINT, { method: "POST", body });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`line token exchange failed: ${res.status} ${text}`);
  }
  return (await res.json()) as { access_token: string };
}

/** access token で LINE profile を取得する。 */
export async function fetchProfile(accessToken: string): Promise<LineProfile> {
  const res = await fetch(PROFILE_ENDPOINT, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`line profile fetch failed: ${res.status} ${text}`);
  }
  return (await res.json()) as LineProfile;
}
