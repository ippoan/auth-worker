/**
 * Auth状態管理 composable
 *
 * JWT の保存・復元・URL fragment 解析・ログインリダイレクトを担当
 * localStorage + cookie の二重保存（cookie は server-side handler 用）
 *
 * LINE WORKS 自動ログイン:
 * ?lw=<domain> パラメータでドメインを保存し、次回以降はログインページをスキップして
 * LINE WORKS OAuth を直接開始する
 */
import { computed } from 'vue'
import { useRuntimeConfig, useState } from '#imports'

const AUTH_STORAGE_KEY = 'logi_auth'
const AUTH_COOKIE_NAME = 'logi_auth_token'
const LW_DOMAIN_KEY = 'logi_lw_domain'
const LW_DOMAIN_COOKIE = 'lw_domain'

/** ホスト名から親ドメインを取得（cross-subdomain cookie 用） */
function getParentDomain(): string {
  if (typeof window === 'undefined') return ''
  const parts = window.location.hostname.split('.')
  return parts.length > 2 ? '.' + parts.slice(-2).join('.') : window.location.hostname
}

export interface AuthState {
  token: string
  orgId: string
  expiresAt: number // unix timestamp (seconds)
  username?: string   // JWT username claim (email or display name)
  provider?: string   // 'google' | 'lineworks' | 'password'
  orgSlug?: string    // organization slug from JWT org_slug claim
}

export interface OrgInfo {
  id: string
  name: string
  slug: string
  role: string
}

/** JWT payload から username と provider を安全に取り出す */
function decodeJwtClaims(token: string): { username?: string; provider?: string; orgSlug?: string } {
  try {
    const payload = JSON.parse(atob(token.split('.')[1] ?? ''))
    return {
      username: payload.username || payload.email || undefined,
      provider: payload.provider || undefined,
      orgSlug: payload.org_slug || undefined,
    }
  } catch {
    return {}
  }
}

function readStorage(): AuthState | null {
  if (typeof window === 'undefined') return null
  try {
    const raw = localStorage.getItem(AUTH_STORAGE_KEY)
    if (!raw) return null
    return JSON.parse(raw) as AuthState
  } catch {
    return null
  }
}

function writeStorage(state: AuthState): void {
  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(state))

  // cookie にもトークンを保存（server-side handler + cross-subdomain 共有用）
  const now = Math.floor(Date.now() / 1000)
  const maxAge = Math.max(state.expiresAt - now, 0)
  const domain = getParentDomain()
  document.cookie = `${AUTH_COOKIE_NAME}=${state.token}; Domain=${domain}; path=/; max-age=${maxAge}; secure; samesite=lax`
}

function clearStorage(): void {
  localStorage.removeItem(AUTH_STORAGE_KEY)
  const domain = getParentDomain()
  document.cookie = `${AUTH_COOKIE_NAME}=; Domain=${domain}; path=/; max-age=0; secure; samesite=lax`
  // host-only cookie も削除
  document.cookie = `${AUTH_COOKIE_NAME}=; path=/; max-age=0; secure; samesite=lax`
  // 異なるドメインの cookie も削除（auth 統合移行期の互換性）
  for (const d of ['.ippoan.org', '.mtamaramu.com']) {
    if (d !== domain) {
      document.cookie = `${AUTH_COOKIE_NAME}=; Domain=${d}; path=/; max-age=0; secure; samesite=lax`
    }
  }
}

/** LINE WORKS ドメインを保存（localStorage + cookie 二重保存、cross-subdomain 共有） */
function saveLwDomain(domain: string): void {
  localStorage.setItem(LW_DOMAIN_KEY, domain)
  const maxAge = 30 * 24 * 60 * 60 // 30日
  const parentDomain = getParentDomain()
  document.cookie = `${LW_DOMAIN_COOKIE}=${encodeURIComponent(domain)}; Domain=${parentDomain}; path=/; max-age=${maxAge}; secure; samesite=lax`
}

/** LINE WORKS ドメインを取得 */
function getLwDomain(): string | null {
  if (typeof window === 'undefined') return null
  return localStorage.getItem(LW_DOMAIN_KEY)
}

/** LINE WORKS ドメインをクリア（明示的ログアウト時） */
function clearLwDomain(): void {
  localStorage.removeItem(LW_DOMAIN_KEY)
  const parentDomain = getParentDomain()
  document.cookie = `${LW_DOMAIN_COOKIE}=; Domain=${parentDomain}; path=/; max-age=0; secure; samesite=lax`
  // host-only cookie も削除（サーバーミドルウェアが Domain なしで設定した stale cookie 対策）
  document.cookie = `${LW_DOMAIN_COOKIE}=; path=/; max-age=0; secure; samesite=lax`
}

export const useAuth = () => {
  const config = useRuntimeConfig()
  const authWorkerUrl = config.public.authWorkerUrl as string

  // Global reactive state (shared across all composable calls via key 'auth')
  const authState = useState<AuthState | null>('auth', () => null)

  /** localStorage からトークンを復元。期限切れなら破棄。 */
  function loadFromStorage(): void {
    const stored = readStorage()
    if (stored) {
      const now = Math.floor(Date.now() / 1000)
      if (stored.expiresAt > now) {
        // 既存の localStorage に username/provider がない場合、JWT からバックフィル
        if (!stored.username || !stored.provider || !stored.orgSlug) {
          const { username, provider, orgSlug } = decodeJwtClaims(stored.token)
          stored.username = username
          stored.provider = provider
          stored.orgSlug = orgSlug
          writeStorage(stored)
        }
        authState.value = stored
      } else {
        clearStorage()
        authState.value = null
      }
    }
  }

  /**
   * auth-worker リダイレクト後の URL fragment を解析・保存。
   * Fragment: #token=<jwt>&org_id=<uuid>&expires_at=<RFC3339>
   * @returns true if token was found and stored
   */
  function consumeFragment(): boolean {
    if (typeof window === 'undefined') return false
    const hash = window.location.hash
    if (!hash || !hash.includes('token=')) return false

    const params = new URLSearchParams(hash.slice(1))
    const token = params.get('token')

    if (!token) return false

    // JWT から claims を取得
    let payload: Record<string, unknown> = {}
    try { payload = JSON.parse(atob(token.split('.')[1] ?? '')) } catch { /* ignore */ }

    // org_id: fragment パラメータ or JWT の tenant_id/org
    const orgId = params.get('org_id') || (payload.tenant_id as string) || (payload.org as string) || ''
    if (!orgId) return false

    // expires: expires_in (秒数) or expires_at (timestamp/RFC3339) or JWT exp
    const expiresInStr = params.get('expires_in')
    const expiresAtStr = params.get('expires_at')
    let expiresAt: number
    if (expiresInStr) {
      expiresAt = Math.floor(Date.now() / 1000) + Number(expiresInStr)
    } else if (expiresAtStr) {
      const asNum = Number(expiresAtStr)
      if (!isNaN(asNum) && expiresAtStr.length >= 10) {
        expiresAt = asNum
      } else {
        const parsed = new Date(expiresAtStr).getTime()
        expiresAt = isNaN(parsed) ? Math.floor(Date.now() / 1000) + 86400 : Math.floor(parsed / 1000)
      }
    } else if (payload.exp) {
      expiresAt = payload.exp as number
    } else {
      expiresAt = Math.floor(Date.now() / 1000) + 86400
    }

    const { username, provider, orgSlug } = decodeJwtClaims(token)
    const state: AuthState = { token, orgId, expiresAt, username, provider, orgSlug }
    writeStorage(state)
    authState.value = state

    // Clean fragment from URL without reload
    history.replaceState(null, '', window.location.pathname + window.location.search)
    return true
  }

  /**
   * Cookie から認証状態を復旧（cross-subdomain 共有用）
   * トップページや他アプリで認証済みの場合、.mtamaramu.com cookie から JWT を復元
   * @returns true if token was recovered from cookie
   */
  function recoverFromCookie(): boolean {
    if (typeof window === 'undefined') return false
    const tokenCookie = document.cookie.split('; ').find(c => c.startsWith(AUTH_COOKIE_NAME + '='))
    if (!tokenCookie) return false
    const token = tokenCookie.split('=').slice(1).join('=')
    try {
      const payload = JSON.parse(atob(token.split('.')[1] ?? ''))
      const now = Math.floor(Date.now() / 1000)
      if (payload.exp <= now) return false
      const state: AuthState = {
        token,
        orgId: payload.tenant_id || payload.org,
        expiresAt: payload.exp,
        username: payload.username || payload.email || payload.name || undefined,
        provider: payload.provider || undefined,
        orgSlug: payload.org_slug || undefined,
      }
      authState.value = state
      localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(state))
      // lw_domain cookie → localStorage 同期
      const lwCookie = document.cookie.split('; ').find(c => c.startsWith(LW_DOMAIN_COOKIE + '='))
      if (lwCookie) {
        const domain = decodeURIComponent(lwCookie.split('=')[1] || '')
        if (domain) saveLwDomain(domain)
      }
      return true
    } catch {
      return false
    }
  }

  /**
   * auth-worker ログイン画面へリダイレクト
   * LINE WORKS ドメインが保存済みなら OAuth を直接開始（ログインページスキップ）
   */
  function redirectToLogin(): void {
    if (!authWorkerUrl) {
      console.error('[Auth] authWorkerUrl is not configured')
      return
    }
    const redirectUri = window.location.origin + '/?lw_callback=1'

    // URL パラメータによる自動ログイン（QRコード等の明示的指定を優先）
    const urlParams = new URLSearchParams(window.location.search)
    if (urlParams.get('provider') === 'google') {
      window.location.href = `${authWorkerUrl}/api/auth/google/redirect?redirect_uri=${encodeURIComponent(redirectUri)}`
      return
    }
    const lwParam = urlParams.get('lw')
    if (lwParam) {
      const params = new URLSearchParams({ domain: lwParam, redirect_uri: redirectUri })
      window.location.href = `${authWorkerUrl}/api/auth/lineworks/redirect?${params.toString()}`
      return
    }

    // localStorage 保存済みドメインによる LINE WORKS 自動ログイン
    const lwDomain = getLwDomain()
    if (lwDomain) {
      const params = new URLSearchParams({ domain: lwDomain, redirect_uri: redirectUri })
      window.location.href = `${authWorkerUrl}/api/auth/lineworks/redirect?${params.toString()}`
      return
    }

    // デフォルト: auth-worker ログインページ
    window.location.href = `https://auth.mtamaramu.com/login?redirect_uri=${encodeURIComponent(redirectUri)}`
  }

  /** ログアウト: ストレージ/cookie クリア → トップページに遷移 */
  function logout(): void {
    clearStorage()
    clearLwDomain()
    authState.value = null
    // auth-worker のログインページにリダイレクト
    if (authWorkerUrl) {
      const redirectUri = window.location.origin + '/?lw_callback=1'
      window.location.href = `https://auth.mtamaramu.com/login?redirect_uri=${encodeURIComponent(redirectUri)}`
    } else {
      window.location.href = window.location.origin + '/?logout=1'
    }
  }

  /** LINE WORKS 自動ログイン URL を生成 */
  function getLwLoginUrl(): string | null {
    if (typeof window === 'undefined') return null
    const lwDomain = getLwDomain()
    if (!lwDomain) return null
    return `${window.location.origin}/?lw=${encodeURIComponent(lwDomain)}`
  }

  /** QRコード用: auth-worker OAuth エンドポイントへの直接URL */
  function getAutoLoginUrl(): string {
    const redirectUri = `${window.location.origin}/?lw_callback=1`
    const lwDomain = getLwDomain()
    if (lwDomain) {
      return `${authWorkerUrl}/api/auth/lineworks/redirect?domain=${encodeURIComponent(lwDomain)}&redirect_uri=${encodeURIComponent(redirectUri)}`
    }
    if (authState.value?.provider === 'google') {
      return `${authWorkerUrl}/api/auth/google/redirect?redirect_uri=${encodeURIComponent(redirectUri)}`
    }
    return `https://auth.mtamaramu.com/login?redirect_uri=${encodeURIComponent(redirectUri)}`
  }

  /** LINE WORKS 自動ログイン URL をクリップボードにコピー */
  async function copyLwLoginUrl(): Promise<boolean> {
    const url = getLwLoginUrl()
    if (!url) return false
    try {
      await navigator.clipboard.writeText(url)
      return true
    } catch {
      return false
    }
  }

  /** auth-worker の設定ページ URL を取得 */
  function getSettingsUrl(): string {
    return `https://auth.ippoan.org/admin/sso`
  }

  // 組織一覧 + 切り替え
  const organizations = useState<OrgInfo[]>('auth_organizations', () => [])
  const isMultiOrg = computed(() => organizations.value.length > 1)

  /** ユーザーが所属する組織一覧を取得 */
  async function fetchOrganizations(): Promise<OrgInfo[]> {
    if (!authState.value?.token) return []
    try {
      const res = await fetch(`${authWorkerUrl}/api/my-orgs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authState.value.token}`,
        },
      })
      if (!res.ok) return []
      const data = await res.json() as { organizations: OrgInfo[] }
      organizations.value = data.organizations
      return data.organizations
    } catch {
      return []
    }
  }

  /** 別の組織に切り替え（新しい JWT を発行） */
  async function switchOrganization(orgId: string): Promise<boolean> {
    if (!authState.value?.token) return false
    try {
      const res = await fetch(`${authWorkerUrl}/api/switch-org`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authState.value.token}`,
        },
        body: JSON.stringify({ organizationId: orgId }),
      })
      if (!res.ok) return false
      const data = await res.json() as {
        token: string
        expiresAt: string
        orgId: string
        orgSlug: string
      }

      const expiresAt = Math.floor(new Date(data.expiresAt).getTime() / 1000)
      const { username, provider } = decodeJwtClaims(data.token)

      const newState: AuthState = {
        token: data.token,
        orgId: data.orgId,
        expiresAt,
        username,
        provider,
        orgSlug: data.orgSlug,
      }
      writeStorage(newState)
      authState.value = newState
      return true
    } catch {
      return false
    }
  }

  // ownerType: 'org' | 'personal' — AuthToolbar が org slug 表示を自動制御するために使用
  const ownerType = useState<string>('auth_owner_type', () => 'org')

  function setOwnerType(type: string): void {
    ownerType.value = type
  }

  const isAuthenticated = computed(() => {
    if (!authState.value) return false
    const now = Math.floor(Date.now() / 1000)
    return authState.value.expiresAt > now
  })

  const token = computed(() => authState.value?.token ?? null)
  const orgId = computed(() => authState.value?.orgId ?? null)
  const username = computed(() => authState.value?.username ?? null)
  const provider = computed(() => authState.value?.provider ?? null)
  const orgSlug = computed(() => authState.value?.orgSlug ?? null)

  /** プロバイダの表示名 */
  const providerLabel = computed(() => {
    switch (authState.value?.provider) {
      case 'google': return 'Google'
      case 'lineworks': return 'LINE WORKS'
      case 'password': return 'パスワード'
      default: return null
    }
  })

  return {
    authState,
    isAuthenticated,
    token,
    orgId,
    orgSlug,
    username,
    provider,
    providerLabel,
    loadFromStorage,
    recoverFromCookie,
    consumeFragment,
    redirectToLogin,
    logout,
    saveLwDomain,
    getLwDomain,
    clearLwDomain,
    getLwLoginUrl,
    getAutoLoginUrl,
    copyLwLoginUrl,
    getSettingsUrl,
    ownerType,
    setOwnerType,
    organizations,
    isMultiOrg,
    fetchOrganizations,
    switchOrganization,
  }
}
