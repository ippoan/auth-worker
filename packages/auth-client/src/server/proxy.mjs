/**
 * REST API プロキシ handler (h3)
 *
 * `/api/proxy/*` → backend (rust-alc-api 等) の `/api/*` へ転送する Nitro
 * server route を生成する。nuxt-pwa-carins ↔ nuxt_dtako_logs のコピーを
 * 1 本化 (Refs ippoan/auth-worker#257)。消費側:
 *
 * ```ts
 * // server/api/proxy/[...path].ts
 * import { createApiProxyHandler } from '@ippoan/auth-client/server'
 * export default createApiProxyHandler({
 *   backendUrl: event =>
 *     (useRuntimeConfig(event).alcApiUrl as string) || 'https://alc-api.ippoan.org',
 * })
 * ```
 *
 * `useRuntimeConfig` は消費側で解決して渡す (本 lib は `#imports` 非依存)。
 * .mjs なのは Nitro (rollup) が node_modules の .ts を transpile しないため。
 */
import {
  defineEventHandler,
  getCookie,
  getHeader,
  getQuery,
  getRequestURL,
  getRouterParam,
  readBody,
  readRawBody,
  setHeader,
  setResponseStatus,
} from 'h3'
import {
  buildAlcProxyHeaders,
  buildIdentityHeaders,
  buildProxyHeaders,
  buildTargetUrl,
  classifyProxyResponse,
  isJsonContentType,
  parseJsonBody,
} from './proxyCore.mjs'
import { introspectToken } from './introspectCore.mjs'
import { mintGoogleIdToken } from './oidc.mjs'

/** logi_auth_token cookie の既定名 (auth.mjs と同じ)。 */
const DEFAULT_COOKIE_NAME = 'logi_auth_token'

function bearerToken(authHeader) {
  if (!authHeader) return undefined
  const m = /^Bearer\s+(.+)$/i.exec(authHeader)
  return m ? m[1] : undefined
}

/** backend レスポンスを event に転送する (両 proxy handler 共通)。 */
async function streamBackendResponse(event, response, path) {
  const responseContentType = response.headers.get('content-type')
  if (responseContentType) setHeader(event, 'content-type', responseContentType)
  const contentDisposition = response.headers.get('content-disposition')
  if (contentDisposition) setHeader(event, 'content-disposition', contentDisposition)
  setResponseStatus(event, response.status)
  switch (classifyProxyResponse(response.status, responseContentType, path)) {
    case 'binary':
      // Workers 互換のため Node Buffer ではなく Uint8Array で返す
      return new Uint8Array(await response.arrayBuffer())
    case 'empty':
      return null
    case 'json':
      return parseJsonBody(await response.text())
  }
}

export function createApiProxyHandler(options) {
  const pathPrefix = options.pathPrefix ?? '/api/'

  return defineEventHandler(async (event) => {
    const path = getRouterParam(event, 'path') || ''
    const backendUrl =
      typeof options.backendUrl === 'function' ? options.backendUrl(event) : options.backendUrl

    const headers = buildProxyHeaders({
      contentType: getHeader(event, 'content-type'),
      authorization: getHeader(event, 'authorization'),
      xAuthToken: getHeader(event, 'x-auth-token'),
      xTenantId: getHeader(event, 'x-tenant-id'),
    })

    const method = event.method
    const url = buildTargetUrl(backendUrl, pathPrefix, path, getQuery(event))

    const fetchOptions = { method, headers }

    // POST/PUT/PATCH の場合は body を転送
    if (['POST', 'PUT', 'PATCH'].includes(method)) {
      try {
        const body = await readBody(event)
        if (body) {
          fetchOptions.body = JSON.stringify(body)
          headers['Content-Type'] = 'application/json'
        }
      } catch {
        // body なし（DELETE 等）
      }
    }

    const response = await fetch(url, fetchOptions)
    return streamBackendResponse(event, response, path)
  })
}

/**
 * auth-worker `/alc-proxy/*` への thin-forward proxy handler
 * (Refs ippoan/rust-alc-api#434 step 3 方式 B)。`createIdentityProxyHandler`
 * (= consumer が自前で introspect + OIDC mint する方式 A) と違い、SA key /
 * OIDC mint / introspect を **すべて auth-worker 側に集約**する。consumer は:
 *
 *   1. browser JWT (cookie / Bearer) と元 origin・consumer proof secret を
 *      `X-Alc-Proxy-Secret` / `X-Alc-Proxy-Origin` に載せ
 *   2. **service binding (`AUTH_WORKER`)** で `/alc-proxy/<api path>` に丸投げ
 *
 * するだけ。方式変更 (OIDC mint の有無等) が auth-worker 1 repo に閉じる。
 *
 * 消費側:
 * ```ts
 * // server/api/proxy/[...path].ts
 * export default createAuthWorkerProxyHandler({
 *   sharedSecret:    e => useRuntimeConfig(e).internalSharedSecret, // INTERNAL_SHARED_SECRET
 *   authWorkerFetch: e => e.context.cloudflare.env.AUTH_WORKER.fetch.bind(
 *     e.context.cloudflare.env.AUTH_WORKER),  // ★ service binding 必須
 * })
 * ```
 */
export function createAuthWorkerProxyHandler(options) {
  const pathPrefix = options.pathPrefix ?? '/api/'
  const proxyPrefix = options.proxyPrefix ?? '/alc-proxy'

  return defineEventHandler(async (event) => {
    const resolve = (v) => (typeof v === 'function' ? v(event) : v)
    const sharedSecret = resolve(options.sharedSecret)
    const proxyFetch = options.authWorkerFetch(event)
    const origin = options.origin ?? getRequestURL(event).origin

    const token =
      getCookie(event, options.cookieName ?? DEFAULT_COOKIE_NAME) ??
      bearerToken(getHeader(event, 'authorization'))

    const path = getRouterParam(event, 'path') || ''
    const headers = buildAlcProxyHeaders({
      sharedSecret,
      origin,
      token,
      contentType: getHeader(event, 'content-type'),
    })

    // service binding fetch には絶対 URL が要る (host は binding が無視するが
    // **path が `/alc-proxy/...` で始まる**必要がある — auth-worker 側が
    // ROUTE_PREFIX を slice して rust-alc-api に転送するため)。
    const base = resolve(options.authWorkerUrl) ?? 'https://alc-proxy.internal'
    const url = buildTargetUrl(`${base.replace(/\/$/, '')}${proxyPrefix}`, pathPrefix, path, getQuery(event))

    const method = event.method
    const fetchOptions = { method, headers }
    if (['POST', 'PUT', 'PATCH'].includes(method)) {
      const contentType = getHeader(event, 'content-type')
      if (isJsonContentType(contentType)) {
        try {
          const body = await readBody(event)
          if (body) {
            fetchOptions.body = JSON.stringify(body)
            headers['Content-Type'] = 'application/json'
          }
        } catch {
          // body なし（DELETE 等）
        }
      } else {
        // multipart / binary は raw passthrough (JSON.stringify すると
        // boundary 付き multipart が壊れる)。Content-Type は buildAlcProxyHeaders が
        // 元の値 (boundary 込み) を載せ済みなので上書きしない。auth-worker
        // `/alc-proxy` 側は body を arrayBuffer で raw 転送するため無傷で届く。
        const raw = await readRawBody(event, false)
        if (raw) fetchOptions.body = raw
      }
    }

    const response = await proxyFetch(url, fetchOptions)
    return streamBackendResponse(event, response, path)
  })
}

/**
 * introspect 検証 → identity 注入 → backend 転送を 1 本化した proxy handler
 * (Refs ippoan/rust-alc-api#434 step 2)。`createApiProxyHandler` (= 署名なし
 * decode で X-Tenant-ID だけ載せる旧版) と違い:
 *
 *   1. cookie / Bearer の browser JWT を auth-worker `/auth/introspect` で **検証**
 *      (`introspectFetch` に CF service binding を渡せば Worker→Worker で in-process)
 *   2. 検証済み identity を **X-Tenant-ID + X-User-ID/Email/Role** として注入
 *      (rust-alc-api の require_tenant_header が AuthUser を復元できる)
 *   3. inactive は 401
 *
 * 消費側:
 * ```ts
 * // server/api/proxy/[...path].ts
 * export default createIdentityProxyHandler({
 *   backendUrl:    e => useRuntimeConfig(e).alcApiUrl,
 *   authWorkerUrl: e => useRuntimeConfig(e).public.authWorkerUrl,
 *   sharedSecret:  e => useRuntimeConfig(e).internalSharedSecret,
 *   introspectFetch: e => e.context.cloudflare.env.AUTH_WORKER.fetch.bind(
 *     e.context.cloudflare.env.AUTH_WORKER),  // ★ service binding (req 増やさない)
 * })
 * ```
 */
export function createIdentityProxyHandler(options) {
  const pathPrefix = options.pathPrefix ?? '/api/'

  return defineEventHandler(async (event) => {
    const resolve = (v) => (typeof v === 'function' ? v(event) : v)
    const backendUrl = resolve(options.backendUrl)
    const authWorkerUrl = resolve(options.authWorkerUrl)
    const sharedSecret = resolve(options.sharedSecret)
    const fetchImpl = options.introspectFetch ? options.introspectFetch(event) : undefined

    const token =
      getCookie(event, options.cookieName ?? DEFAULT_COOKIE_NAME) ??
      bearerToken(getHeader(event, 'authorization'))
    const origin = options.origin ?? getRequestURL(event).origin

    const result = await introspectToken({
      authWorkerUrl,
      sharedSecret,
      token: token ?? '',
      origin,
      fetchImpl,
      ttlMs: options.ttlMs,
    })
    if (!result.active) {
      setResponseStatus(event, 401)
      return { error: 'Unauthorized' }
    }

    const path = getRouterParam(event, 'path') || ''
    const headers = buildIdentityHeaders(result, {
      contentType: getHeader(event, 'content-type'),
    })

    // rust-alc-api#434 step 3: Cloud Run IAM lockdown 用の OIDC mint。
    // `oidcServiceAccountKey` (run.invoker SA key) がある時だけ Google 署名の
    // ID token を mint し Authorization に載せる (= binding 未設定なら非破壊・無効)。
    // aud は明示 `oidcAudience` 優先、無ければ backendUrl の origin
    // (Cloud Run service URL を backendUrl に向けている前提)。
    const saKey = resolve(options.oidcServiceAccountKey)
    if (saKey) {
      const audience = resolve(options.oidcAudience) || new URL(backendUrl).origin
      const idToken = await mintGoogleIdToken(saKey, audience, {
        fetchImpl: options.oidcFetch ? options.oidcFetch(event) : undefined,
      })
      headers['Authorization'] = `Bearer ${idToken}`
    }

    const method = event.method
    const url = buildTargetUrl(backendUrl, pathPrefix, path, getQuery(event))
    const fetchOptions = { method, headers }

    if (['POST', 'PUT', 'PATCH'].includes(method)) {
      try {
        const body = await readBody(event)
        if (body) {
          fetchOptions.body = JSON.stringify(body)
          headers['Content-Type'] = 'application/json'
        }
      } catch {
        // body なし（DELETE 等）
      }
    }

    const response = await fetch(url, fetchOptions)
    return streamBackendResponse(event, response, path)
  })
}
