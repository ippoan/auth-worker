/**
 * rust-alc-api の `/api/internal/auth/*` を叩く internal client (rust-alc-api#434 Phase 2)。
 *
 * 認証 DB 操作 (sso-config 読み / user upsert / refresh-token 保存) は rust が DB owner の
 * まま保持し、auth-worker は `signInternalJWT` (`aud=alc-api-internal`) を付けて internal
 * endpoint 越しに叩く。rust 側は `require_internal_jwt` で検証する。
 *
 * lockdown (`allUsers` 削除) 後は Cloud Run IAM が OIDC を要求するため、ここに
 * `mintGoogleIdToken(aud=alc-api-internal)` を併用する cutover が入る (Refs #434)。
 * 移行中 (Cloud Run が allUsers のまま) は internal-JWT だけで到達する。
 */
import type { Env } from "../index";
import { signInternalJWT } from "./internal-jwt";

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
  const token = await signInternalJWT(env);
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
