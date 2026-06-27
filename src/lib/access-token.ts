/**
 * access JWT + refresh token の発行 (rust-alc-api#434 Phase 2)。
 *
 * 認証オーケストレーションを auth-worker に移管するため、従来 rust-alc-api
 * (`crates/alc-auth-jwt`) が発行していた token を auth-worker 側で発行する。
 * **claim / refresh フォーマットは rust と厳密に一致させる**こと
 * (rust `create_access_token` / `create_refresh_token` / `hash_refresh_token`):
 *
 * - access JWT (`AppClaims`): `{ sub, email, name, tenant_id, role, org_slug?, iat, exp }`、
 *   HS256 / `JWT_SECRET`、`exp = iat + 3600`。`org_slug` は None のとき field 省略。
 * - refresh: raw = `rt_{uuid(no-hyphen)}`、保存する hash = `hex(sha256(raw))`、有効期限 = now + 30日。
 */
import { signJwt } from "./jwt";
import { sha256Hex } from "./device";

export const ACCESS_TOKEN_EXPIRY_SECS = 3600;
export const REFRESH_TOKEN_EXPIRY_DAYS = 30;

/** access JWT の claim に写す user フィールド (rust `AccessTokenInput` 相当)。 */
export interface AccessTokenUser {
  /** user_id → `sub` */
  id: string;
  email: string;
  name: string;
  tenant_id: string;
  role: string;
}

/** rust `create_access_token` (AppClaims) と同形の access JWT を発行する。 */
export async function createAccessToken(
  user: AccessTokenUser,
  secret: string,
  orgSlug: string | null,
  nowSec: number = Math.floor(Date.now() / 1000),
): Promise<string> {
  const payload: Record<string, unknown> = {
    sub: user.id,
    email: user.email,
    name: user.name,
    tenant_id: user.tenant_id,
    role: user.role,
    iat: nowSec,
    exp: nowSec + ACCESS_TOKEN_EXPIRY_SECS,
  };
  // rust 側は org_slug: Option<String> を serde で skip するので None は field ごと省略する。
  if (orgSlug) payload.org_slug = orgSlug;
  return signJwt(payload, secret);
}

/** rust `create_refresh_token` (raw=`rt_{uuid}`, hash=`hex(sha256(raw))`) と同形。 */
export async function createRefreshToken(): Promise<{ raw: string; hash: string }> {
  const raw = `rt_${crypto.randomUUID().replace(/-/g, "")}`;
  const hash = await sha256Hex(raw);
  return { raw, hash };
}

/** now + 30日 を ISO8601 で返す (rust `refresh_token_expires_at`、DateTime<Utc> 互換)。 */
export function refreshTokenExpiresAt(nowMs: number = Date.now()): string {
  return new Date(nowMs + REFRESH_TOKEN_EXPIRY_DAYS * 86400 * 1000).toISOString();
}
