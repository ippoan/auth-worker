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
  setHeader,
  setResponseStatus,
} from 'h3'
import {
  buildIdentityHeaders,
  buildProxyHeaders,
  buildTargetUrl,
  classifyProxyResponse,
  parseJsonBody,
} from './proxyCore.mjs'
import { introspectToken } from './introspectCore.mjs'

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
