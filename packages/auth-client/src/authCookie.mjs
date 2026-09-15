/**
 * 共有 auth cookie (`logi_auth_token`) の client/server 共用読み出し (pure、DOM 非依存)。
 *
 * ブラウザは host-only cookie と `Domain=.ippoan.org` 付き cookie を別物として
 * **両方** `document.cookie` に載せる。古い方が先頭に来ると、先頭一致 1 件だけを
 * 見る実装は期限切れの token を拾って「未ログイン」と誤判定し、ログイン直後なのに
 * もう一度 Google へ飛ばす (auth-worker 側で #387 / #531 として直したのと同じ穴)。
 *
 * 同名 cookie の候補を全部走査し、payload が decode できて `exp` が未来の
 * **最初の候補**を返す。`exp` の無い token は採用しない (server の verifyJwt と
 * 同じく期限が判定できないものは信用しない)。
 *
 * .mjs + JSDoc なのは **Nitro (rollup) が node_modules の .ts を transpile
 * しない**ため — server 経路 (`runtime/authState.server.ts` 等) から import
 * される (#560)。型は `authCookie.d.mts`。client からの利用も引き続き可能
 * (`useAuth.ts` がこのモジュールを直接 import する)。
 */
import { decodeJwtPayloadFromToken } from './jwt-core.mjs'

/** `document.cookie` 形式の文字列から `name` の値を全て返す (出現順)。
 * @param {string} cookieString
 * @param {string} name
 * @returns {string[]}
 */
export function readCookieValues(cookieString, name) {
  const prefix = name + '='
  /** @type {string[]} */
  const out = []
  for (const part of cookieString.split('; ')) {
    if (part.startsWith(prefix)) out.push(part.slice(prefix.length))
  }
  return out
}

/**
 * `name` の同名 cookie 候補のうち、`exp > nowSec` を満たす最初の JWT を返す。
 * 該当が無ければ null。
 * @param {string} cookieString
 * @param {string} name
 * @param {number} nowSec
 * @returns {string | null}
 */
export function findValidAuthCookieToken(cookieString, name, nowSec) {
  for (const token of readCookieValues(cookieString, name)) {
    if (!token) continue
    /** @type {Record<string, unknown>} */
    const payload = decodeJwtPayloadFromToken(token)
    const exp = payload.exp
    if (typeof exp === 'number' && exp > nowSec) return token
  }
  return null
}

/**
 * JWT payload から認証 state を組み立てる (`useAuth.ts` の `recoverFromCookie` /
 * SSR (`runtime/authState.server.ts`) が共用する)。
 *
 * `exp` の未来判定はここではしない — 呼び出し側が `findValidAuthCookieToken` で
 * 済ませている前提 (token を直接 decode しただけの壊れた payload では null)。
 * token 自体は state に含めて返す (payload に生 JWT を載せたくない呼び出し側
 * ─ SSR plugin ─ が `token: ''` で落とす)。
 * @param {string} token
 * @returns {{ token: string, orgId: string, expiresAt: number, username?: string, provider?: string, orgSlug?: string } | null}
 */
export function authStateFromToken(token) {
  /** @type {Record<string, unknown>} */
  const payload = decodeJwtPayloadFromToken(token)
  const exp = payload.exp
  if (typeof exp !== 'number') return null

  const orgId = String(payload.tenant_id || payload.org || '')
  const username =
    (payload.username || payload.email || payload.name || undefined)
  const provider = payload.provider || undefined
  const orgSlug = payload.org_slug || undefined

  return {
    token,
    orgId,
    expiresAt: exp,
    username: username ? String(username) : undefined,
    provider: provider ? String(provider) : undefined,
    orgSlug: orgSlug ? String(orgSlug) : undefined,
  }
}
