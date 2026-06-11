import { describe, it, expect } from 'vitest'
import {
  getParentDomainFromHost,
  resolveAuthAction,
  checkTenantId,
  type AuthConfig,
  type AuthRequest,
} from '../src/server/authLogic'

/** base64url エンコード（UTF-8 safe）でテスト用 JWT payload を作る */
function b64url(obj: Record<string, unknown>): string {
  const json = JSON.stringify(obj)
  const bytes = new TextEncoder().encode(json)
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function makeToken(payload: Record<string, unknown>): string {
  return `header.${b64url(payload)}.sig`
}

const config: AuthConfig = {
  apiBackend: 'rust-alc-api',
  authWorkerUrl: 'https://auth.example.com',
}

function makeReq(overrides: Partial<AuthRequest> = {}): AuthRequest {
  return {
    pathname: '/',
    origin: 'https://app.ippoan.org',
    hostname: 'app.ippoan.org',
    searchParams: new URLSearchParams(),
    cookie: undefined,
    lwDomainCookie: undefined,
    ...overrides,
  }
}

describe('getParentDomainFromHost', () => {
  it('サブドメインありなら親ドメインを返す', () => {
    expect(getParentDomainFromHost('app.ippoan.org')).toBe('.ippoan.org')
  })

  it('2 ラベル以下なら undefined (host-only cookie)', () => {
    expect(getParentDomainFromHost('localhost')).toBeUndefined()
    expect(getParentDomainFromHost('example.com')).toBeUndefined()
  })
})

describe('resolveAuthAction', () => {
  it('対象外 backend は pass', () => {
    const action = resolveAuthAction({ ...config, apiBackend: 'mock' }, makeReq())
    expect(action).toEqual({ type: 'pass' })
  })

  it('/api/ パスは pass', () => {
    expect(resolveAuthAction(config, makeReq({ pathname: '/api/items' }))).toEqual({
      type: 'pass',
    })
  })

  it('認証 cookie ありは pass', () => {
    expect(resolveAuthAction(config, makeReq({ cookie: 'jwt' }))).toEqual({ type: 'pass' })
  })

  it('authWorkerUrl 未設定は pass', () => {
    expect(resolveAuthAction({ ...config, authWorkerUrl: '' }, makeReq())).toEqual({
      type: 'pass',
    })
  })

  it('?lw_callback / ?logout は pass (リダイレクトループ防止)', () => {
    expect(
      resolveAuthAction(config, makeReq({ searchParams: new URLSearchParams('lw_callback=1') })),
    ).toEqual({ type: 'pass' })
    expect(
      resolveAuthAction(config, makeReq({ searchParams: new URLSearchParams('logout=1') })),
    ).toEqual({ type: 'pass' })
  })

  it('?woff + ?lw は lw_domain cookie を保存して pass (WOFF SDK)', () => {
    const action = resolveAuthAction(
      config,
      makeReq({ searchParams: new URLSearchParams('woff=1&lw=ohishi') }),
    )
    expect(action).toEqual({
      type: 'set-cookie-and-pass',
      name: 'lw_domain',
      value: 'ohishi',
      domain: '.ippoan.org',
    })
  })

  it('?woff のみは pass', () => {
    expect(
      resolveAuthAction(config, makeReq({ searchParams: new URLSearchParams('woff=1') })),
    ).toEqual({ type: 'pass' })
  })

  it('?lw=<domain> は cookie 保存 + LINE WORKS redirect', () => {
    const action = resolveAuthAction(
      config,
      makeReq({ searchParams: new URLSearchParams('lw=ohishi') }),
    )
    expect(action.type).toBe('set-cookie-and-redirect')
    if (action.type === 'set-cookie-and-redirect') {
      expect(action.value).toBe('ohishi')
      expect(action.redirectUrl).toContain('/api/auth/lineworks/redirect?')
      expect(action.redirectUrl).toContain('domain=ohishi')
      expect(action.redirectUrl).toContain(
        encodeURIComponent('https://app.ippoan.org/?lw_callback=1'),
      )
    }
  })

  it('lw_domain cookie ありは LINE WORKS redirect', () => {
    const action = resolveAuthAction(config, makeReq({ lwDomainCookie: 'ohishi' }))
    expect(action.type).toBe('redirect')
    if (action.type === 'redirect') {
      expect(action.redirectUrl).toContain('/api/auth/lineworks/redirect?')
      expect(action.redirectUrl).toContain('domain=ohishi')
    }
  })

  it('デフォルトはログインページへ redirect', () => {
    const action = resolveAuthAction(config, makeReq())
    expect(action).toEqual({
      type: 'redirect',
      redirectUrl: `https://auth.example.com/login?redirect_uri=${encodeURIComponent(
        'https://app.ippoan.org/?lw_callback=1',
      )}`,
    })
  })
})

describe('checkTenantId', () => {
  const tenantId = '11111111-2222-3333-4444-555555555555'

  it('allowedTenantId 未設定はチェック無効 (pass)', () => {
    expect(checkTenantId(makeToken({ tenant_id: 'other' }), '')).toEqual({ type: 'pass' })
  })

  it('cookie 無しは pass (認証 middleware の前段)', () => {
    expect(checkTenantId(undefined, tenantId)).toEqual({ type: 'pass' })
  })

  it('tenant_id 一致は pass', () => {
    expect(checkTenantId(makeToken({ tenant_id: tenantId }), tenantId)).toEqual({
      type: 'pass',
    })
  })

  it('tenant_id 不一致は forbidden', () => {
    expect(checkTenantId(makeToken({ tenant_id: 'other' }), tenantId)).toEqual({
      type: 'forbidden',
      reason: 'tenant_id mismatch',
    })
  })

  it('壊れた token は forbidden', () => {
    expect(checkTenantId('not-a-jwt', tenantId)).toEqual({
      type: 'forbidden',
      reason: 'invalid token',
    })
  })
})
