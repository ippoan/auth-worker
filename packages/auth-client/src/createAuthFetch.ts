/**
 * 認証付き fetch ラッパーファクトリ
 * Authorization ヘッダー + X-Tenant-ID 自動付与、401 時の refresh→retry / コールバック対応
 */

export interface AuthFetchOptions {
  baseUrl: string
  tokenGetter: () => string | null
  tenantIdGetter?: () => string | null
  /**
   * 401 を受けたときに access token を refresh する関数。
   * 設定すると 401→refresh→retry(1回) が有効になる。
   * 同時に複数リクエストが 401 を受けても refresh は single-flight で 1 回だけ走る。
   * refresh 後 `tokenGetter()` が新しい token を返す前提。
   */
  tokenRefresher?: () => Promise<void>
  /**
   * refresh が無い / refresh しても 401 が解消しなかった場合に呼ばれる。
   * (ログアウト誘導など)
   */
  onUnauthorized?: () => void
  /**
   * エラーメッセージの先頭ラベル (default: 'API error')。
   * 日本語 UI でそのまま err.message を表示する app は 'API エラー' 等を渡す
   * (alc-app / nuxt-dtako-admin の既存文言互換、Refs #257)。
   */
  errorLabel?: string
}

export function createAuthFetch(options: AuthFetchOptions) {
  const { baseUrl, tokenGetter, tenantIdGetter, tokenRefresher, onUnauthorized, errorLabel = 'API error' } = options
  const base = baseUrl.replace(/\/$/, '')

  // 同時 refresh 抑止（single-flight）。この factory インスタンスにスコープする。
  let refreshPromise: Promise<void> | null = null

  function buildHeaders(init: RequestInit): Record<string, string> {
    const isFormData = init.body instanceof FormData
    const headers: Record<string, string> = {
      ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
      ...((init.headers as Record<string, string>) || {}),
    }

    const token = tokenGetter()
    if (token) headers['Authorization'] = `Bearer ${token}`

    const tid = tenantIdGetter?.()
    if (tid) headers['X-Tenant-ID'] = tid

    return headers
  }

  async function toResult<T>(res: Response): Promise<T> {
    if (!res.ok) {
      const body = await res.text().catch(() => '')
      throw new Error(`${errorLabel} (${res.status}): ${body || res.statusText}`)
    }
    if (res.status === 204) return undefined as T
    return res.json() as Promise<T>
  }

  return async function authFetch<T>(
    path: string,
    init: RequestInit = {},
  ): Promise<T> {
    const url = `${base}${path}`
    const res = await fetch(url, { ...init, headers: buildHeaders(init) })

    if (res.status === 401) {
      // refresh 可能なら 1 回だけ refresh → retry を試みる
      if (tokenRefresher && tokenGetter()) {
        let refreshed = false
        try {
          if (!refreshPromise) {
            refreshPromise = tokenRefresher().finally(() => {
              refreshPromise = null
            })
          }
          await refreshPromise
          refreshed = true
        } catch {
          // refresh 失敗 → 下の onUnauthorized へ落とす
        }

        if (refreshed) {
          const retryRes = await fetch(url, { ...init, headers: buildHeaders(init) })
          if (retryRes.status === 401) {
            onUnauthorized?.()
          }
          // retry も 401 なら toResult が `${errorLabel} (401): ...` を throw する
          // (= 自前実装時代の「元の 401 エラーにフォールスルー」と同形式)
          return toResult<T>(retryRes)
        }
      }

      onUnauthorized?.()
      return toResult<T>(res)
    }

    return toResult<T>(res)
  }
}
