import { describe, it, expect } from 'vitest'
import {
  buildIdentityHeaders,
  buildProxyHeaders,
  buildTargetUrl,
  classifyProxyResponse,
  parseJsonBody,
} from '../src/server/proxyCore.mjs'

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

describe('buildIdentityHeaders', () => {
  it('injects X-Tenant-ID + X-User-* + Content-Type from a verified result', () => {
    expect(
      buildIdentityHeaders(
        { active: true, tenant_id: 't1', role: 'admin', email: 'a@b.com', sub: 'u1' },
        { contentType: 'application/json' },
      ),
    ).toEqual({
      'Content-Type': 'application/json',
      'X-Tenant-ID': 't1',
      'X-User-ID': 'u1',
      'X-User-Email': 'a@b.com',
      'X-User-Role': 'admin',
    })
  })

  it('omits empty fields (kiosk: tenant only, no AuthUser) and Content-Type when absent', () => {
    expect(
      buildIdentityHeaders({ active: true, tenant_id: 't1', role: '', email: '', sub: '' }),
    ).toEqual({ 'X-Tenant-ID': 't1' })
  })

  it('omits everything when all fields empty', () => {
    expect(
      buildIdentityHeaders({ active: true, tenant_id: '', role: '', email: '', sub: '' }),
    ).toEqual({})
  })
})

describe('buildProxyHeaders', () => {
  it('Authorization から tenant_id を抽出して X-Tenant-ID に載せる', () => {
    const token = makeToken({ tenant_id: 't-1' })
    const headers = buildProxyHeaders({ authorization: `Bearer ${token}` })
    expect(headers['Authorization']).toBe(`Bearer ${token}`)
    expect(headers['X-Tenant-ID']).toBe('t-1')
  })

  it('tenant_id が無ければ org claim にフォールバック', () => {
    const token = makeToken({ org: 'org-1' })
    const headers = buildProxyHeaders({ authorization: `Bearer ${token}` })
    expect(headers['X-Tenant-ID']).toBe('org-1')
  })

  it('壊れた JWT でも Authorization は転送する (X-Tenant-ID は無し)', () => {
    const headers = buildProxyHeaders({ authorization: 'Bearer broken' })
    expect(headers['Authorization']).toBe('Bearer broken')
    expect(headers['X-Tenant-ID']).toBeUndefined()
  })

  it('x-auth-token 互換: Authorization 不在時のみ Bearer 化する', () => {
    const token = makeToken({ tenant_id: 't-2' })
    const headers = buildProxyHeaders({ xAuthToken: token })
    expect(headers['Authorization']).toBe(`Bearer ${token}`)
    expect(headers['X-Tenant-ID']).toBe('t-2')

    const both = buildProxyHeaders({
      authorization: `Bearer ${makeToken({ tenant_id: 't-1' })}`,
      xAuthToken: token,
    })
    expect(both['X-Tenant-ID']).toBe('t-1')
  })

  it('明示的な X-Tenant-ID ヘッダーが JWT 抽出より優先される', () => {
    const headers = buildProxyHeaders({
      authorization: `Bearer ${makeToken({ tenant_id: 'from-jwt' })}`,
      xTenantId: 'explicit',
    })
    expect(headers['X-Tenant-ID']).toBe('explicit')
  })

  it('Content-Type を転送する', () => {
    expect(buildProxyHeaders({ contentType: 'application/json' })['Content-Type']).toBe(
      'application/json',
    )
    expect(buildProxyHeaders({})).toEqual({})
  })
})

describe('buildTargetUrl', () => {
  it('backend + prefix + path + query を組み立てる', () => {
    const url = buildTargetUrl('https://api.example.com', '/api/', 'items/1', {
      page: 2,
      q: 'あ',
    })
    const parsed = new URL(url)
    expect(parsed.origin + parsed.pathname).toBe('https://api.example.com/api/items/1')
    expect(parsed.searchParams.get('page')).toBe('2')
    expect(parsed.searchParams.get('q')).toBe('あ')
  })

  it('undefined / null のクエリ値は落とす + 末尾スラッシュを正規化', () => {
    const url = buildTargetUrl('https://api.example.com/', '/api/', 'items', {
      a: undefined,
      b: null,
      c: 0,
    })
    const parsed = new URL(url)
    expect(parsed.pathname).toBe('/api/items')
    expect(parsed.searchParams.has('a')).toBe(false)
    expect(parsed.searchParams.has('b')).toBe(false)
    expect(parsed.searchParams.get('c')).toBe('0')
  })
})

describe('classifyProxyResponse', () => {
  it('/download を含む path は常に binary', () => {
    expect(classifyProxyResponse(200, 'application/json', 'files/1/download')).toBe('binary')
  })

  it('非 JSON content-type は binary', () => {
    expect(classifyProxyResponse(200, 'application/pdf', 'files/1')).toBe('binary')
  })

  it('204 は empty', () => {
    expect(classifyProxyResponse(204, null, 'items/1')).toBe('empty')
  })

  it('JSON は json (content-type 不明も json 扱い)', () => {
    expect(classifyProxyResponse(200, 'application/json; charset=utf-8', 'items')).toBe('json')
    expect(classifyProxyResponse(500, null, 'items')).toBe('json')
  })
})

describe('parseJsonBody', () => {
  it('空文字は null', () => {
    expect(parseJsonBody('')).toBeNull()
  })

  it('JSON は parse して返す', () => {
    expect(parseJsonBody('{"ok":true}')).toEqual({ ok: true })
  })

  it('非 JSON は { error } に包む (黙って握り潰さない)', () => {
    expect(parseJsonBody('upstream exploded')).toEqual({ error: 'upstream exploded' })
  })
})
