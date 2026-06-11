/**
 * REST API プロキシの pure ロジック（h3 非依存 / テスタブル）
 *
 * nuxt-pwa-carins ↔ nuxt_dtako_logs が `server/api/proxy/[...path].ts` に
 * 相互コピーしていた転送ロジックのうち、ヘッダー構築とレスポンス分類を
 * 切り出したもの (Refs ippoan/auth-worker#257)。h3 handler 側は
 * ./proxy.mjs の `createApiProxyHandler` を参照。型は ./index.d.mts。
 */
import { decodeJwtPayloadFromToken } from '../jwt-core.mjs'

function tenantIdFromToken(token) {
  const payload = decodeJwtPayloadFromToken(token)
  return payload.tenant_id || payload.org || undefined
}

/**
 * backend へ転送するヘッダーを構築する。
 * JWT から tenant_id を抽出し、フォールバック用に `X-Tenant-ID` にも載せる。
 */
export function buildProxyHeaders(input) {
  const headers = {}
  if (input.contentType) headers['Content-Type'] = input.contentType

  if (input.authorization) {
    headers['Authorization'] = input.authorization
    const tenantId = tenantIdFromToken(input.authorization.replace(/^Bearer\s+/i, ''))
    if (tenantId) headers['X-Tenant-ID'] = tenantId
  } else if (input.xAuthToken) {
    // x-auth-token ヘッダー (gRPC 時代の互換)
    headers['Authorization'] = `Bearer ${input.xAuthToken}`
    const tenantId = tenantIdFromToken(input.xAuthToken)
    if (tenantId) headers['X-Tenant-ID'] = tenantId
  }

  // 明示的な X-Tenant-ID ヘッダーがあればそちらを優先
  if (input.xTenantId) headers['X-Tenant-ID'] = input.xTenantId

  return headers
}

/**
 * backend レスポンスの転送方法を分類する。
 * - `/download` を含む path / 非 JSON content-type → binary パススルー
 * - 204 → empty
 * - それ以外 → JSON (parse 失敗時は `{ error: <text> }` に包む)
 */
export function classifyProxyResponse(status, contentType, path) {
  if (path.includes('/download')) return 'binary'
  if (contentType && !contentType.includes('application/json')) return 'binary'
  if (status === 204) return 'empty'
  return 'json'
}

/** JSON レスポンス本文を parse する。空なら null、parse 失敗は `{ error }` に包む。 */
export function parseJsonBody(text) {
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    return { error: text }
  }
}

/** クエリパラメータを転送先 URL に付与する。 */
export function buildTargetUrl(backendUrl, pathPrefix, path, query) {
  const url = new URL(`${backendUrl.replace(/\/$/, '')}${pathPrefix}${path}`)
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null) {
      url.searchParams.set(key, String(value))
    }
  }
  return url.toString()
}
