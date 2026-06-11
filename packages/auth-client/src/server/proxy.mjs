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
  getHeader,
  getQuery,
  getRouterParam,
  readBody,
  setHeader,
  setResponseStatus,
} from 'h3'
import {
  buildProxyHeaders,
  buildTargetUrl,
  classifyProxyResponse,
  parseJsonBody,
} from './proxyCore.mjs'

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

    // レスポンスヘッダーを転送
    const responseContentType = response.headers.get('content-type')
    if (responseContentType) {
      setHeader(event, 'content-type', responseContentType)
    }
    const contentDisposition = response.headers.get('content-disposition')
    if (contentDisposition) {
      setHeader(event, 'content-disposition', contentDisposition)
    }

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
  })
}
