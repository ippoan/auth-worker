import { describe, it, expect } from 'vitest'
import {
  decodeJwtPayload,
  decodeJwtPayloadFromToken,
  decodeJwtClaims,
  extractTenantIdFromAuth,
} from '../src/jwt'

/** base64url エンコード（UTF-8 safe）でテスト用 JWT payload を作る */
function b64url(obj: Record<string, unknown>): string {
  const json = JSON.stringify(obj)
  const bytes = new TextEncoder().encode(json)
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** header.payload.signature 形式のダミー JWT */
function makeToken(payload: Record<string, unknown>): string {
  return `header.${b64url(payload)}.sig`
}

describe('decodeJwtPayload', () => {
  it('マルチバイト (日本語) の username を壊さずデコードする', () => {
    const payload = { username: '大石 太郎', tenant_id: 't-1' }
    const decoded = decodeJwtPayload(b64url(payload))
    expect(decoded.username).toBe('大石 太郎')
    expect(decoded.tenant_id).toBe('t-1')
  })

  it('絵文字・非 latin1 文字も正しく復元する', () => {
    const payload = { name: 'café ☕ 名前' }
    const decoded = decodeJwtPayload(b64url(payload))
    expect(decoded.name).toBe('café ☕ 名前')
  })
})

describe('decodeJwtPayloadFromToken', () => {
  it('正常な JWT から payload を取り出す', () => {
    const token = makeToken({ provider: 'google', email: 'a@example.com' })
    expect(decodeJwtPayloadFromToken(token)).toMatchObject({
      provider: 'google',
      email: 'a@example.com',
    })
  })

  it('壊れた token では {} を返す（throw しない）', () => {
    expect(decodeJwtPayloadFromToken('not-a-jwt')).toEqual({})
    expect(decodeJwtPayloadFromToken('')).toEqual({})
    expect(decodeJwtPayloadFromToken('a.!!!.c')).toEqual({})
  })
})

describe('decodeJwtClaims', () => {
  it('username / provider / orgSlug を抽出する', () => {
    const token = makeToken({
      username: 'たろう',
      provider: 'lineworks',
      org_slug: 'ohishi',
    })
    expect(decodeJwtClaims(token)).toEqual({
      username: 'たろう',
      provider: 'lineworks',
      orgSlug: 'ohishi',
    })
  })

  it('username 不在時は email に fallback する', () => {
    const token = makeToken({ email: 'b@example.com' })
    expect(decodeJwtClaims(token)).toEqual({
      username: 'b@example.com',
      provider: undefined,
      orgSlug: undefined,
    })
  })

  it('壊れた token では空オブジェクト相当を返す', () => {
    expect(decodeJwtClaims('garbage')).toEqual({
      username: undefined,
      provider: undefined,
      orgSlug: undefined,
    })
  })
})

describe('extractTenantIdFromAuth', () => {
  it('Bearer JWT から tenant_id を抽出する', () => {
    const token = makeToken({ tenant_id: 'tenant-abc' })
    expect(extractTenantIdFromAuth(`Bearer ${token}`)).toEqual({
      authorization: `Bearer ${token}`,
      tenantId: 'tenant-abc',
    })
  })

  it('tenant_id 不在時は org claim に fallback する', () => {
    const token = makeToken({ org: 'org-xyz' })
    expect(extractTenantIdFromAuth(`Bearer ${token}`).tenantId).toBe('org-xyz')
  })

  it('Bearer prefix が無い生 token も受ける', () => {
    const token = makeToken({ tenant_id: 'raw-tid' })
    expect(extractTenantIdFromAuth(token).tenantId).toBe('raw-tid')
  })

  it('header 未指定なら空オブジェクト', () => {
    expect(extractTenantIdFromAuth(undefined)).toEqual({})
  })

  it('壊れた JWT では authorization は保持し tenantId は undefined', () => {
    const r = extractTenantIdFromAuth('Bearer broken.token')
    expect(r.authorization).toBe('Bearer broken.token')
    expect(r.tenantId).toBeUndefined()
  })
})
