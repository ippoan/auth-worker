/**
 * 認証 server middleware のコアロジック（pure / テスタブル、h3 非依存）
 *
 * nuxt-ichibanboshi ↔ nuxt-pwa-carins が `server/utils/auth-logic.ts` に
 * 相互コピーしていたものを 1 本化 (Refs ippoan/auth-worker#257)。
 * 両 repo の差分は union で吸収:
 * - WOFF SDK 分岐 (`?woff`) — nuxt-pwa-carins 由来。`?woff` を送らない
 *   アプリでは到達しないため無条件に含める
 * - `checkTenantId` — nuxt-ichibanboshi 由来のテナント制限チェック
 *
 * .mjs + JSDoc なのは Nitro (rollup) が node_modules の .ts を transpile
 * しないため。型は ./index.d.mts。
 */
import { decodeJwtPayloadFromToken } from '../jwt-core.mjs'

/** ホスト名から親ドメインを取得（cross-subdomain cookie 用） */
export function getParentDomainFromHost(hostname) {
  const parts = hostname.split('.')
  return parts.length > 2 ? '.' + parts.slice(-2).join('.') : undefined
}

export function resolveAuthAction(config, req) {
  if (config.apiBackend !== 'rust-logi' && config.apiBackend !== 'rust-alc-api') {
    return { type: 'pass' }
  }

  if (req.pathname.startsWith('/api/')) return { type: 'pass' }
  if (req.cookie) return { type: 'pass' }
  if (!config.authWorkerUrl) return { type: 'pass' }
  if (req.searchParams.has('lw_callback')) return { type: 'pass' }
  if (req.searchParams.has('logout')) return { type: 'pass' }

  const domain = getParentDomainFromHost(req.hostname)
  const redirectUri = `${req.origin}/?lw_callback=1`

  // ?woff — WOFF SDK (クライアント側で WOFF 認証するため redirect しない)
  if (req.searchParams.has('woff')) {
    const lwParam = req.searchParams.get('lw')
    if (lwParam) {
      return { type: 'set-cookie-and-pass', name: 'lw_domain', value: lwParam, domain }
    }
    return { type: 'pass' }
  }

  // ?lw=<domain> — LINE WORKS 自動ログイン
  const lwParam = req.searchParams.get('lw')
  if (lwParam) {
    const params = new URLSearchParams({ domain: lwParam, redirect_uri: redirectUri })
    return {
      type: 'set-cookie-and-redirect',
      name: 'lw_domain',
      value: lwParam,
      domain,
      redirectUrl: `${config.authWorkerUrl}/api/auth/lineworks/redirect?${params.toString()}`,
    }
  }

  // lw_domain cookie — 自動ログイン
  if (req.lwDomainCookie) {
    const params = new URLSearchParams({ domain: req.lwDomainCookie, redirect_uri: redirectUri })
    return {
      type: 'redirect',
      redirectUrl: `${config.authWorkerUrl}/api/auth/lineworks/redirect?${params.toString()}`,
    }
  }

  // デフォルト
  return {
    type: 'redirect',
    redirectUrl: `${config.authWorkerUrl}/login?redirect_uri=${encodeURIComponent(redirectUri)}`,
  }
}

/**
 * JWT cookie の tenant_id チェック。
 *
 * - `allowedTenantId` が空: チェック無効 (pass)
 *   → staging では tenant 制限 secret を未設定にして auth-worker
 *     (APP_TENANT_ACL + bypass_emails) に gate を集約する想定
 * - cookie 無し: 認証 middleware の前段なので pass
 * - JWT.tenant_id が `allowedTenantId` と一致: pass
 * - それ以外: forbidden
 */
export function checkTenantId(cookie, allowedTenantId) {
  if (!allowedTenantId) return { type: 'pass' }
  if (!cookie) return { type: 'pass' }
  const payload = decodeJwtPayloadFromToken(cookie)
  if (Object.keys(payload).length === 0) {
    return { type: 'forbidden', reason: 'invalid token' }
  }
  if (payload.tenant_id !== allowedTenantId) {
    return { type: 'forbidden', reason: 'tenant_id mismatch' }
  }
  return { type: 'pass' }
}
