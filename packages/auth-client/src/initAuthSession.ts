/**
 * Auth プラグイン共通フロー (ブラウザ専用)
 *
 * アプリ起動時に JWT を復元/検証し、未認証ならログイン画面へリダイレクトする。
 * nuxt-items / nuxt_dtako_logs / nuxt-pwa-carins / nuxt-ichibanboshi が
 * `plugins/auth.client.ts` に相互コピーしていた 40-50 行を 1 本化したもの
 * (Refs ippoan/auth-worker#257)。
 *
 * 消費側は数行の plugin から呼ぶ:
 *
 * ```ts
 * // plugins/auth.client.ts
 * import { initAuthSession } from '@ippoan/auth-client'
 * export default defineNuxtPlugin({
 *   name: 'auth',
 *   enforce: 'pre',
 *   setup() {
 *     initAuthSession()
 *   },
 * })
 * ```
 *
 * アプリ固有の前処理 (WOFF 認証 / backend 種別ガード等) は消費側 plugin で
 * initAuthSession() の前に行い、自前で認証を確立した場合は呼ばない。
 */
import { useAuth } from './useAuth'

export interface InitAuthSessionOptions {
  /** `?lw=<domain>` パラメータの保存 + URL クリーンアップを行う (default: true) */
  lineWorksParam?: boolean
  /** 認証成功後に組織一覧を取得する (複数組織対応アプリ向け、default: true) */
  fetchOrganizations?: boolean
  /** token 期限切れタイミングで再ログインへ飛ばすタイマーを張る (default: true) */
  expiryTimer?: boolean
}

export function initAuthSession(options: InitAuthSessionOptions = {}): void {
  const {
    lineWorksParam = true,
    fetchOrganizations: shouldFetchOrganizations = true,
    expiryTimer = true,
  } = options

  if (typeof window === 'undefined') return

  // auth-worker から戻ってきた直後か (cookie handoff / fragment のどちらでも付く)。
  // この後の復元が全部失敗して未認証のまま redirectToLogin に落ちる = 「ログイン
  // したのにセッションを確立できない」= cookie が毒 (dangling tenant 等)。素の
  // /login へ戻すと同じ cookie でまた戻ってきて無限ループになるため、その時だけ
  // reauth (=/logout で cookie 破棄してから /login) にしてループを断つ。
  const cameFromAuthWorker = new URLSearchParams(window.location.search).has('lw_callback')

  const {
    consumeFragment,
    loadFromStorage,
    recoverFromCookie,
    isAuthenticated,
    redirectToLogin,
    authState,
    saveLwDomain,
    fetchOrganizations,
  } = useAuth()

  // 0. ?lw=<domain> パラメータ → LINE WORKS ドメイン保存 + URL から除去
  if (lineWorksParam) {
    const urlParams = new URLSearchParams(window.location.search)
    const lwParam = urlParams.get('lw')
    if (lwParam) {
      saveLwDomain(lwParam)
      urlParams.delete('lw')
      const newSearch = urlParams.toString()
      const cleanUrl =
        window.location.pathname + (newSearch ? `?${newSearch}` : '') + window.location.hash
      history.replaceState(null, '', cleanUrl)
    }
  }

  // 1. URL fragment からトークン取得を試行（auth-worker リダイレクト後）
  const foundInFragment = consumeFragment()

  if (foundInFragment) {
    // lw_domain cookie → localStorage 同期（サーバーミドルウェアが設定した cookie を永続化）
    const lwCookie = document.cookie.split('; ').find(c => c.startsWith('lw_domain='))
    if (lwCookie) {
      const domain = decodeURIComponent(lwCookie.split('=')[1] || '')
      if (domain) saveLwDomain(domain)
    }
    // token を消費したら URL を必ずクリーンアップする（ログイン情報をアドレスバー/履歴に残さない）。
    // auth-worker は `#token=...&expires_at=...&org_id=...`（+ 場合により `?lw_callback=1`）で
    // 返すため、fragment と lw_callback を除去する。cleanPath に hash を含めない＝ fragment 除去。
    // `?lw_callback` の有無に関わらず常に実行する（lw_callback を付けないアプリでも token を消す）。
    const currentUrl = new URL(window.location.href)
    currentUrl.searchParams.delete('lw_callback')
    const cleanPath = currentUrl.pathname + (currentUrl.search || '')
    history.replaceState(null, '', cleanPath)
  } else {
    // 2. localStorage から復元
    loadFromStorage()
  }

  // 2.5. Cookie からの復旧（トップページや他アプリで認証済みの場合）
  if (!isAuthenticated.value) {
    recoverFromCookie()
  }

  // 3. 未認証 → ログイン画面へ（redirectToLogin 内で lw_domain をチェック）。
  //    auth-worker から戻った直後なのに未認証なら、毒 cookie を破棄してから
  //    再認証する (reauth) — 素の /login はループになるため (上のコメント参照)。
  if (!isAuthenticated.value) {
    redirectToLogin(cameFromAuthWorker ? { reauth: true } : undefined)
    return
  }

  // 4. 認証済み → 組織一覧を取得（複数組織対応）
  if (shouldFetchOrganizations) {
    void fetchOrganizations()
  }

  // 5. 期限切れタイマーを設定
  if (expiryTimer) {
    const state = authState.value
    if (state) {
      const now = Math.floor(Date.now() / 1000)
      const msUntilExpiry = (state.expiresAt - now) * 1000
      if (msUntilExpiry > 0) {
        setTimeout(() => {
          if (!isAuthenticated.value) {
            redirectToLogin()
          }
        }, msUntilExpiry)
      }
    }
  }
}
