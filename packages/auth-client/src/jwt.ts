/**
 * JWT デコードユーティリティ（framework-agnostic、client / server 両用）
 *
 * `atob` だけだと latin1 として解釈されるため、username 等にマルチバイト文字
 * (日本語の表示名など) が入ると壊れる。base64url を正規化し TextDecoder で
 * UTF-8 として decode する。
 */

/** base64url 文字列を UTF-8 JSON としてパースする（マルチバイト安全） */
export function decodeJwtPayload(base64url: string): Record<string, unknown> {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64)
  const bytes = Uint8Array.from(binary, (c: string) => c.charCodeAt(0))
  return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>
}

/** JWT 全体（header.payload.signature）から payload を取り出す。失敗時は {} */
export function decodeJwtPayloadFromToken(token: string): Record<string, unknown> {
  try {
    return decodeJwtPayload(token.split('.')[1] ?? '')
  } catch {
    return {}
  }
}

/** JWT payload から username / provider / orgSlug を安全に取り出す */
export function decodeJwtClaims(token: string): {
  username?: string
  provider?: string
  orgSlug?: string
} {
  const payload = decodeJwtPayloadFromToken(token)
  return {
    username: (payload.username as string) || (payload.email as string) || undefined,
    provider: (payload.provider as string) || undefined,
    orgSlug: (payload.org_slug as string) || undefined,
  }
}

/**
 * `Authorization: Bearer <jwt>` ヘッダーから tenant_id を抽出する server util。
 * Nitro の server route が backend へ X-Tenant-ID を transform する用途
 * (参照: nuxt-pwa-carins / nuxt-ichibanboshi の自前実装を 1 本化)。
 *
 * @returns 元の authorization ヘッダーと、JWT から抽出した tenantId
 */
export function extractTenantIdFromAuth(
  authHeader: string | undefined,
): { authorization?: string; tenantId?: string } {
  if (!authHeader) return {}

  const token = authHeader.replace(/^Bearer\s+/i, '')
  const payload = decodeJwtPayloadFromToken(token)
  const tenantId = (payload.tenant_id as string) || (payload.org as string) || undefined

  return { authorization: authHeader, tenantId }
}
