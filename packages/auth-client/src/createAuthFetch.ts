/**
 * 認証付き fetch ラッパーファクトリ
 * Authorization ヘッダー + X-Tenant-ID 自動付与、401 時のコールバック対応
 */

export interface AuthFetchOptions {
  baseUrl: string
  tokenGetter: () => string | null
  tenantIdGetter?: () => string | null
  onUnauthorized?: () => void
}

export function createAuthFetch(options: AuthFetchOptions) {
  const { baseUrl, tokenGetter, tenantIdGetter, onUnauthorized } = options
  const base = baseUrl.replace(/\/$/, '')

  return async function authFetch<T>(
    path: string,
    init: RequestInit = {},
  ): Promise<T> {
    const isFormData = init.body instanceof FormData
    const headers: Record<string, string> = {
      ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
      ...(init.headers as Record<string, string> || {}),
    }

    const token = tokenGetter()
    if (token) headers['Authorization'] = `Bearer ${token}`

    const tid = tenantIdGetter?.()
    if (tid) headers['X-Tenant-ID'] = tid

    const res = await fetch(`${base}${path}`, { ...init, headers })

    if (res.status === 401) {
      onUnauthorized?.()
      throw new Error('Unauthorized')
    }

    if (!res.ok) {
      const body = await res.text().catch(() => '')
      throw new Error(`API error (${res.status}): ${body || res.statusText}`)
    }

    if (res.status === 204) return undefined as T
    return res.json()
  }
}
