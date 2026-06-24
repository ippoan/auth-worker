/**
 * `requireAuth` — introspect ベースの server-side 認証ガード (h3)
 * (ippoan/auth-worker#290 Phase 2)。
 *
 * 各 consumer の Nitro server route から呼び、cookie / Bearer の browser JWT を
 * auth-worker `POST /auth/introspect` で検証する。consumer 側は **`JWT_SECRET`
 * (署名鍵) も `APP_TENANT_ACL` も持たず**、署名検証と tenant/aud 判定を
 * auth-worker に委譲する。これにより:
 *
 *   - 共有 HS256 鍵を各 consumer から撤去できる (鍵漏洩面の縮小)
 *   - cross-app cookie 流用 (#290 穴 #3) を auth-worker 側の APP_TENANT_ACL で
 *     塞げる (origin を送るため)
 *
 * 既存の `checkTenantId` (署名なし decode の page gate) を置き換える新版だが、
 * 既存 export は据え置き (additive)。
 *
 * 消費側:
 * ```ts
 * // server/middleware/auth.ts など
 * import { requireAuth } from '@ippoan/auth-client/server'
 * export default defineEventHandler(async (event) => {
 *   if (!event.path.startsWith('/api/')) return
 *   const cfg = useRuntimeConfig(event)
 *   await requireAuth(event, {
 *     authWorkerUrl: cfg.public.authWorkerUrl,
 *     sharedSecret: cfg.internalSharedSecret, // CF Secrets Store / env
 *   })
 * })
 * ```
 *
 * .mjs なのは Nitro (rollup) が node_modules の .ts を transpile しないため。
 */
import { createError, getCookie, getHeader, getRequestURL } from 'h3'
import { introspectToken } from './introspectCore.mjs'

/** logi_auth_token cookie の既定名。`.ippoan.org` 共有 cookie。 */
const DEFAULT_COOKIE_NAME = 'logi_auth_token'

function bearerToken(authHeader) {
  if (!authHeader) return undefined
  const m = /^Bearer\s+(.+)$/i.exec(authHeader)
  return m ? m[1] : undefined
}

/**
 * event から browser JWT を取り出して introspect する。
 *
 * - token は cookie (`logi_auth_token`) を優先、無ければ `Authorization: Bearer`。
 * - origin は `options.origin` を優先、無ければ request URL の origin。
 *   APP_TENANT_ACL 分割に必須なので auth-worker 側で origin 欠落は active:false。
 *
 * @param {import('h3').H3Event} event
 * @param {object} options
 * @param {string} options.authWorkerUrl
 * @param {string} options.sharedSecret
 * @param {string} [options.origin]       明示 origin (proxy 環境で getRequestURL が内部 origin になる時)
 * @param {string} [options.cookieName]   default 'logi_auth_token'
 * @param {number} [options.ttlMs]        introspect cache TTL cap
 * @returns {Promise<{active:true, tenant_id?:string, role?:string, email?:string, exp?:number}>}
 * @throws 401 (createError) when the token is missing / invalid / disallowed
 */
export async function requireAuth(event, options) {
  const token =
    getCookie(event, options.cookieName ?? DEFAULT_COOKIE_NAME) ??
    bearerToken(getHeader(event, 'authorization'))
  const origin = options.origin ?? getRequestURL(event).origin

  const result = await introspectToken({
    authWorkerUrl: options.authWorkerUrl,
    sharedSecret: options.sharedSecret,
    token: token ?? '',
    origin,
    ttlMs: options.ttlMs,
  })

  if (!result.active) {
    throw createError({ statusCode: 401, statusMessage: 'Unauthorized' })
  }

  // downstream handler から参照できるよう context に載せる。
  event.context.auth = result
  return result
}
