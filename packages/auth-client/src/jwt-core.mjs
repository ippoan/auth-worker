/**
 * JWT デコードユーティリティ実装（framework-agnostic、client / server 両用）
 *
 * `atob` だけだと latin1 として解釈されるため、username 等にマルチバイト文字
 * (日本語の表示名など) が入ると壊れる。base64url を正規化し TextDecoder で
 * UTF-8 として decode する。
 *
 * .mjs + JSDoc なのは **Nitro (rollup) が node_modules の .ts を transpile
 * しない**ため — server route から import される経路 (`./server` subpath) で
 * .ts だと parse error になる (Refs ippoan/auth-worker#257 consumer 移行時に
 * 発覚)。型は jwt-core.d.mts。client からは従来どおり src/jwt.ts (re-export)
 * を経由するので公開 API は不変。
 */

/** base64url 文字列を UTF-8 JSON としてパースする（マルチバイト安全） */
export function decodeJwtPayload(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64)
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0))
  return JSON.parse(new TextDecoder().decode(bytes))
}

/** JWT 全体（header.payload.signature）から payload を取り出す。失敗時は {} */
export function decodeJwtPayloadFromToken(token) {
  try {
    return decodeJwtPayload(token.split('.')[1] ?? '')
  } catch {
    return {}
  }
}

/** JWT payload から username / provider / orgSlug を安全に取り出す */
export function decodeJwtClaims(token) {
  const payload = decodeJwtPayloadFromToken(token)
  return {
    username: payload.username || payload.email || undefined,
    provider: payload.provider || undefined,
    orgSlug: payload.org_slug || undefined,
  }
}

/**
 * `Authorization: Bearer <jwt>` ヘッダーから tenant_id を抽出する server util。
 * Nitro の server route が backend へ X-Tenant-ID を transform する用途
 * (参照: nuxt-pwa-carins / nuxt-ichibanboshi の自前実装を 1 本化)。
 */
export function extractTenantIdFromAuth(authHeader) {
  if (!authHeader) return {}

  const token = authHeader.replace(/^Bearer\s+/i, '')
  const payload = decodeJwtPayloadFromToken(token)
  const tenantId = payload.tenant_id || payload.org || undefined

  return { authorization: authHeader, tenantId }
}
