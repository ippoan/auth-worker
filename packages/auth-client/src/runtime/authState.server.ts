/**
 * SSR で `logi_auth_token` cookie から認証状態を決めて `useState('auth')` に
 * 載せる server 専用 Nuxt plugin (issue #560、opt-in — module の `authState`
 * option、既定 off)。
 *
 * client 側の `loadFromStorage` が hydrate 済み state を localStorage の古い
 * コピーで上書きしないようにするのが目的 (#559 の穴の恒久対策)。
 *
 * ★ payload に生 JWT を載せない: SSR の HTML (`window.__NUXT__`) に JWT を埋める
 * と、後続の HttpOnly 化 (#416) を無効化する (cookie を JS から隠しても payload
 * から読める) うえ、中間キャッシュに載れば別ユーザーへ渡る。認証の**判定**
 * (expiresAt / orgId / username 等) だけを server で決めて渡し、Bearer 送信用の
 * token 本体は client 側で `loadFromStorage` が cookie から補う
 * (HttpOnly 化後は補えなくなるが、その時点では API 呼び出しを同一 origin の
 * proxy に寄せる #418/#419 が前提)。
 *
 * ★ token が無いときに何もしない: fragment 配送 (`#token=`、*.pages.dev 等) と
 * `?lw_callback=1` は server から見えない。ここで auth_loading=false にすると
 * `authMiddleware` が SSR 中に `/login` へ redirect してしまい、client が
 * fragment を消費する前に弾かれる。未認証の判断は従来どおり client に残す。
 */
import { defineNuxtPlugin, useRequestEvent, useRequestHeaders, useRuntimeConfig, useState } from '#imports'
import { setResponseHeader } from 'h3'
import { authStateFromToken, findValidAuthCookieToken } from '../authCookie.mjs'
import { AUTH_COOKIE_NAME, AUTH_LOADING_KEY, AUTH_STATE_KEY } from '../useAuth'

export default defineNuxtPlugin({
  name: 'ippoan-auth-state',
  enforce: 'pre',
  setup() {
    const config = useRuntimeConfig()
    // staging bypass は client の loadFromStorage が担う責務 (JWT 不要の疑似認証)。
    if ((config.public.stagingTenantId as string | undefined) || '') return

    const cookie = useRequestHeaders(['cookie']).cookie ?? ''
    const now = Math.floor(Date.now() / 1000)
    const token = findValidAuthCookieToken(cookie, AUTH_COOKIE_NAME, now)
    if (!token) return // 無ければ何もしない (上の doc comment 参照)

    const state = authStateFromToken(token)
    if (!state) return

    // ★ payload に生 JWT を載せない: token は空にして派生 state だけを渡す。
    useState(AUTH_STATE_KEY, () => null).value = { ...state, token: '' }
    useState(AUTH_LOADING_KEY, () => true).value = false

    const event = useRequestEvent()
    if (event) setResponseHeader(event, 'Cache-Control', 'private, no-store')
  },
})
