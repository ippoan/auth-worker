/**
 * dev-login `__dev/callback` h3 handler (issue #423/#425)。
 *
 * `issue_dev_login_url` MCP tool が返す
 * `http://localhost:<port>/__dev/callback?code=...` を人間が開いたときに
 * 叩かれる。code を auth-worker `POST /dev-login/token` に server-to-server
 * で交換し、`token_kind=dev` を確認できたら `logi_auth_token_dev` を
 * host-only cookie として立てて `/` へ 302 する。
 *
 * **DEV_LOGIN ガードは呼び出し側の責務**: このパッケージは Hono ではなく
 * h3/Nitro 前提のため、consumer は `[env.dev.vars] DEV_LOGIN="true"` の
 * ときだけこの handler をルートに登録する (例:
 * `server/routes/__dev/callback.get.ts`)。本番 vars に定義しなければ
 * ルート自体が存在せず 404 になる。詳細は README。
 *
 * .mjs なのは Nitro (rollup) が node_modules の .ts を transpile しないため
 * (他ファイルと同じ理由、型は ./index.d.mts)。
 */
import { createError, defineEventHandler, getQuery, sendRedirect, setCookie } from 'h3'
import {
  DEV_COOKIE_NAME,
  buildDevTokenExchangeRequest,
  devCookieOptions,
  normalizeDevTokenExchangeResult,
} from './devLoginCore.mjs'

/**
 * @param {object} options
 * @param {string | ((event: import('h3').H3Event) => string)} options.authWorkerUrl
 * @param {string} [options.redirectTo] 成功時のリダイレクト先 (default '/')
 * @param {typeof fetch} [options.fetchImpl] code 交換用 fetch (test 注入 / CF service binding 用)
 * @param {string} [options.cookieName] dev cookie 名 (default 'logi_auth_token_dev')
 */
export function createDevLoginCallbackHandler(options) {
  const redirectTo = options.redirectTo ?? '/'
  const fetchImpl = options.fetchImpl ?? fetch
  const cookieName = options.cookieName ?? DEV_COOKIE_NAME

  return defineEventHandler(async (event) => {
    const authWorkerUrl =
      typeof options.authWorkerUrl === 'function' ? options.authWorkerUrl(event) : options.authWorkerUrl

    const code = getQuery(event).code
    if (typeof code !== 'string' || !code) {
      throw createError({ statusCode: 400, statusMessage: 'missing code' })
    }

    const { url, init } = buildDevTokenExchangeRequest({ authWorkerUrl, code })

    let status
    let data
    try {
      const res = await fetchImpl(url, init)
      status = res.status
      data = await res.json().catch(() => undefined)
    } catch {
      throw createError({ statusCode: 502, statusMessage: 'dev-login code exchange failed' })
    }

    const result = normalizeDevTokenExchangeResult(status, data)
    if (!result.ok) {
      throw createError({ statusCode: 403, statusMessage: 'invalid or unexpected dev-login token' })
    }

    setCookie(event, cookieName, result.token, devCookieOptions(result.expiresIn))
    return sendRedirect(event, redirectTo)
  })
}
