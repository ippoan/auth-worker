/**
 * LINE WORKS OAuth2 client (rust-alc-api#434 Phase 2)。
 *
 * rust-alc-api `crates/alc-core/src/auth_lineworks.rs` の TypeScript 移植。
 * 認証オーケストレーションを auth-worker に移管するため、authorize URL 構築 /
 * code 交換 / user profile 取得を auth-worker 側で行う。endpoint と param は rust と一致:
 *
 * - authorize: `https://auth.worksmobile.com/oauth2/v2.0/authorize` (`response_type=code` /
 *   `scope=user.profile.read`)
 * - token: `https://auth.worksmobile.com/oauth2/v2.0/token` (form, `grant_type=authorization_code`)
 * - userinfo: `https://www.worksapis.com/v1.0/users/me` (Bearer)
 */

const AUTHORIZE_ENDPOINT = "https://auth.worksmobile.com/oauth2/v2.0/authorize";
const TOKEN_ENDPOINT = "https://auth.worksmobile.com/oauth2/v2.0/token";
const USERINFO_ENDPOINT = "https://www.worksapis.com/v1.0/users/me";

/** `users/me` のレスポンス (camelCase、rust `UserProfile` 相当)。 */
export interface LineworksProfile {
  userId: string;
  userName?: { lastName?: string; firstName?: string };
  email?: string;
  domainId?: number;
}

/**
 * authorize URL を構築する。`redirectUri` / `state` は **呼び出し側で encode 済み**を渡す
 * (rust `authorize_url` と同じ前提)。
 */
export function authorizeUrl(
  clientId: string,
  encodedRedirectUri: string,
  encodedState: string,
): string {
  return (
    `${AUTHORIZE_ENDPOINT}?client_id=${clientId}` +
    `&redirect_uri=${encodedRedirectUri}` +
    `&response_type=code` +
    `&scope=user.profile.read` +
    `&state=${encodedState}`
  );
}

/** authorization code を access token に交換する。`redirectUri` は authorize 時と同一。 */
export async function exchangeCode(
  clientId: string,
  clientSecret: string,
  code: string,
  redirectUri: string,
): Promise<{ access_token: string }> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: clientId,
    client_secret: clientSecret,
    code,
    redirect_uri: redirectUri,
  });
  const res = await fetch(TOKEN_ENDPOINT, { method: "POST", body });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`lineworks token exchange failed: ${res.status} ${text}`);
  }
  return (await res.json()) as { access_token: string };
}

/** access token で user profile を取得する。 */
export async function fetchUserProfile(accessToken: string): Promise<LineworksProfile> {
  const res = await fetch(USERINFO_ENDPOINT, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`lineworks profile fetch failed: ${res.status} ${text}`);
  }
  return (await res.json()) as LineworksProfile;
}

/** rust `UserProfile::display_name` と同じ: lastName+firstName、空なら userId。 */
export function displayName(p: LineworksProfile): string {
  const full = `${p.userName?.lastName ?? ""}${p.userName?.firstName ?? ""}`;
  return full.length > 0 ? full : p.userId;
}

/** rust `UserProfile::email_or_id` と同じ: email ?? userId。 */
export function emailOrId(p: LineworksProfile): string {
  return p.email ?? p.userId;
}
