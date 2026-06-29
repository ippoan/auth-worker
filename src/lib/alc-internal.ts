/**
 * rust-alc-api の `/api/internal/auth/*` を叩く internal client (rust-alc-api#434 Phase 2)。
 *
 * 認証 DB 操作 (sso-config 読み / user upsert / refresh-token 保存) は rust が DB owner の
 * まま保持し、auth-worker は `signInternalJWT` (`aud=alc-api-internal`) を付けて internal
 * endpoint 越しに叩く。rust 側は `require_internal_jwt` で検証する。
 *
 * lockdown (`allUsers` 削除) 後は Cloud Run IAM が OIDC を要求するため、`INTERNAL_AUTH_OIDC=1`
 * で `internalAuthToken` が `mintGoogleIdToken(aud=alc-api-internal)` に切替わる (Refs #434)。
 * 移行前 (flag 未設定 or SA key 無し) は従来の HS256 internal-JWT で到達する (非破壊)。
 */
import type { Env } from "../index";
import { signInternalJWT } from "./internal-jwt";
import { resolveSecret } from "./secret";
import { mintGoogleIdToken } from "./oidc";

/** rust の `aud=alc-api-internal` (alc-auth-jwt の INTERNAL_AUD と同値)。 */
const INTERNAL_AUD = "alc-api-internal";

/**
 * internal-auth 呼び出しの Authorization token を返す。
 *
 * - lockdown cutover 後 (`INTERNAL_AUTH_OIDC=1` + `ALC_API_PROXY_SA_KEY` 設定): Google OIDC
 *   (aud=alc-api-internal) を mint。Cloud Run IAM (`--add-custom-audiences=alc-api-internal`) が
 *   検証し、rust 側は dual-accept で aud を確認する。
 * - それ以外 (移行前): 従来の HS256 internal JWT (`signInternalJWT`)。
 */
export async function internalAuthToken(env: Env): Promise<string> {
  if (env.INTERNAL_AUTH_OIDC === "1") {
    const saKey = await resolveSecret(env.ALC_API_PROXY_SA_KEY);
    if (saKey) return mintGoogleIdToken(saKey, INTERNAL_AUD);
  }
  return signInternalJWT(env);
}

/** `/api/internal/auth/sso-config` のレスポンス。 */
export interface SsoConfig {
  tenant_id: string;
  client_id: string;
  client_secret_encrypted: string;
  external_org_id: string;
  woff_id: string | null;
}

/** `/api/internal/auth/users/*` のレスポンス (user + tenant slug、token は含まない)。 */
export interface InternalUserWithSlug {
  id: string;
  tenant_id: string;
  email: string;
  name: string;
  role: string;
  google_sub: string | null;
  lineworks_id: string | null;
  line_user_id: string | null;
  slug: string | null;
}

async function internalFetch(env: Env, path: string, init?: RequestInit): Promise<Response> {
  const token = await internalAuthToken(env);
  const headers = new Headers(init?.headers);
  headers.set("Authorization", `Bearer ${token}`);
  if (init?.body !== undefined) headers.set("Content-Type", "application/json");
  return fetch(`${env.ALC_API_ORIGIN}${path}`, { ...init, headers });
}

/** SSO 設定を解決する。未登録は null。 */
export async function resolveSsoConfig(
  env: Env,
  provider: string,
  domain: string,
): Promise<SsoConfig | null> {
  const qs = `provider=${encodeURIComponent(provider)}&domain=${encodeURIComponent(domain)}`;
  const res = await internalFetch(env, `/api/internal/auth/sso-config?${qs}`);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`internal sso-config failed: ${res.status}`);
  return (await res.json()) as SsoConfig;
}

/** lineworks_id で user を find-or-create する。 */
export async function upsertLineworksUser(
  env: Env,
  body: { tenant_id: string; lineworks_id: string; email: string; name: string },
): Promise<InternalUserWithSlug> {
  const res = await internalFetch(env, `/api/internal/auth/users/upsert-lineworks`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`internal upsert-lineworks failed: ${res.status}`);
  return (await res.json()) as InternalUserWithSlug;
}

/** refresh token の hash を保存する (raw は渡さない)。 */
export async function saveRefreshToken(
  env: Env,
  body: { user_id: string; refresh_hash: string; expires_at: string },
): Promise<void> {
  const res = await internalFetch(env, `/api/internal/auth/refresh-token`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`internal refresh-token failed: ${res.status}`);
}

/** line_user_id で user を逆引きする (未登録は null)。 */
export async function findUserByLineId(
  env: Env,
  lineUserId: string,
): Promise<InternalUserWithSlug | null> {
  const qs = `line_user_id=${encodeURIComponent(lineUserId)}`;
  const res = await internalFetch(env, `/api/internal/auth/users/by-line-id?${qs}`);
  if (!res.ok) throw new Error(`internal by-line-id failed: ${res.status}`);
  return (await res.json()) as InternalUserWithSlug | null;
}

/** line_user_id で user を find-or-create する。 */
export async function upsertLineUser(
  env: Env,
  body: { tenant_id: string; line_user_id: string; name: string },
): Promise<InternalUserWithSlug> {
  const res = await internalFetch(env, `/api/internal/auth/users/upsert-line`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`internal upsert-line failed: ${res.status}`);
  return (await res.json()) as InternalUserWithSlug;
}

/** LINE recipient を自動登録する (QR 招待フロー)。 */
export async function registerLineRecipient(
  env: Env,
  body: { tenant_id: string; name: string; line_user_id: string },
): Promise<void> {
  const res = await internalFetch(env, `/api/internal/auth/recipients/register-line`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`internal register-line failed: ${res.status}`);
}

/** notify_recipients から line_user_id で tenant を逆引きする (複数テナント対応)。 */
export async function recipientsByLineId(
  env: Env,
  lineUserId: string,
): Promise<Array<{ tenant_id: string; name: string }>> {
  const qs = `line_user_id=${encodeURIComponent(lineUserId)}`;
  const res = await internalFetch(env, `/api/internal/auth/recipients/by-line-id?${qs}`);
  if (!res.ok) throw new Error(`internal recipients-by-line-id failed: ${res.status}`);
  return (await res.json()) as Array<{ tenant_id: string; name: string }>;
}
