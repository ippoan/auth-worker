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
 * introspect 検証済み結果から backend へ注入する identity ヘッダーを構築する
 * (Refs ippoan/rust-alc-api#434)。`buildProxyHeaders` (= 署名なし decode で
 * X-Tenant-ID だけ載せる旧経路) と違い、auth-worker `/auth/introspect` で
 * 検証済みの identity を **X-Tenant-ID + X-User-ID/Email/Role** として載せる。
 *
 * rust-alc-api の `require_tenant_header` は X-Tenant-ID で tenant を、
 * X-User-ID/Email/Role が **3 つ揃って初めて** AuthUser を復元する。よって
 * 空フィールドは省略する (= kiosk 等で user 情報が無い時は X-User-* を出さず、
 * tenant scoping だけ通す)。Authorization は **載せない** (rust は JWT を
 * 検証しないため不要、かつ転送面を最小化)。
 */
export function buildIdentityHeaders(result, opts = {}) {
  const headers = {}
  if (opts.contentType) headers['Content-Type'] = opts.contentType
  if (result.tenant_id) headers['X-Tenant-ID'] = result.tenant_id
  if (result.sub) headers['X-User-ID'] = result.sub
  if (result.email) headers['X-User-Email'] = result.email
  if (result.role) headers['X-User-Role'] = result.role
  return headers
}

/**
 * auth-worker `/alc-proxy/*` (rust-alc-api#434 step 3 方式 B) へ thin-forward
 * する時のヘッダーを構築する。consumer worker は SA key / OIDC mint を持たず、
 * **service binding (`AUTH_WORKER`) でこの route に丸投げ**する。auth-worker が
 * introspect (= local JWT 検証) + ACL + OIDC mint + 注入を 1 箇所で行う。
 *
 * consumer が付ける header は 2 つだけ:
 *   - `X-Alc-Proxy-Secret` — consumer worker proof (INTERNAL_SHARED_SECRET、
 *     auth-worker 側が constant-time 検証する。公開 route での直叩き / origin
 *     詐称を弾く関門。空だと auth-worker が 401)
 *   - `X-Alc-Proxy-Origin` — APP_TENANT_ACL 判定用の元アプリ origin
 *     (service binding 越しでは request.url が auth-worker のものになり消えるため)
 * これに browser JWT (`Authorization: Bearer`) と content-type を素通しする。
 */
export function buildAlcProxyHeaders(input) {
  const headers = {
    'X-Alc-Proxy-Secret': input.sharedSecret,
    'X-Alc-Proxy-Origin': input.origin,
  }
  if (input.token) headers['Authorization'] = `Bearer ${input.token}`
  if (input.contentType) headers['Content-Type'] = input.contentType
  // flip 前 preview override (Refs ippoan/ci-dashboard#472)。値の検証は
  // auth-worker `/alc-proxy` 側 (同一 service の tagged revision URL に pin)。
  if (input.previewApiBase) headers['X-Alc-Preview-Api-Base'] = input.previewApiBase
  return headers
}

/**
 * request body を JSON として読み直して再 serialize すべき content-type か判定する
 * (Refs ippoan/rust-alc-api#434)。`undefined` / `application/json` のときだけ JSON
 * 経路。`multipart/form-data` (= ファイルアップロード、boundary 込み) や任意の
 * binary は raw passthrough にしないと壊れる (auth-worker `/alc-proxy` は
 * `request.arrayBuffer()` で raw 転送するため、consumer が raw で渡せば boundary 付き
 * multipart も無傷で届く)。
 */
export function isJsonContentType(contentType) {
  if (!contentType) return true
  return contentType.includes('application/json')
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
