import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  buildIntrospectRequest,
  normalizeIntrospectResult,
  cacheKey,
  computeCacheExpiryMs,
  introspectToken,
  DEFAULT_TTL_MS,
  _clearIntrospectCache,
} from '../src/server/introspectCore.mjs'

const AUTH = 'https://auth.test.example'
const SECRET = 'internal-shared-secret'
const ORIGIN = 'https://app.ippoan.org'

function okResponse(data: unknown): Response {
  return { ok: true, status: 200, json: async () => data } as unknown as Response
}
function errResponse(status: number): Response {
  return { ok: false, status, json: async () => ({}) } as unknown as Response
}

describe('buildIntrospectRequest', () => {
  it('POST /auth/introspect with raw shared secret + token/origin body', () => {
    const { url, init } = buildIntrospectRequest({
      authWorkerUrl: AUTH,
      sharedSecret: SECRET,
      token: 'jwt-x',
      origin: ORIGIN,
    })
    expect(url).toBe(`${AUTH}/auth/introspect`)
    expect(init.method).toBe('POST')
    expect((init.headers as Record<string, string>).Authorization).toBe(SECRET)
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json')
    expect(JSON.parse(init.body as string)).toEqual({ token: 'jwt-x', origin: ORIGIN })
  })
})

describe('normalizeIntrospectResult', () => {
  it('active:true with all claims', () => {
    expect(
      normalizeIntrospectResult({
        active: true,
        tenant_id: 't',
        role: 'admin',
        email: 'a@b',
        sub: 'u1',
        exp: 10,
      }),
    ).toEqual({ active: true, tenant_id: 't', role: 'admin', email: 'a@b', sub: 'u1', exp: 10 })
  })
  it('coerces missing/wrong-typed claims to empty/undefined', () => {
    expect(normalizeIntrospectResult({ active: true })).toEqual({
      active: true,
      tenant_id: '',
      role: '',
      email: '',
      sub: '',
      exp: undefined,
    })
    expect(normalizeIntrospectResult({ active: true, tenant_id: 1, sub: 2, exp: 'x' })).toEqual({
      active: true,
      tenant_id: '',
      role: '',
      email: '',
      sub: '',
      exp: undefined,
    })
  })
  it('active:false for active!==true / null / non-object', () => {
    expect(normalizeIntrospectResult({ active: false })).toEqual({ active: false })
    expect(normalizeIntrospectResult(null)).toEqual({ active: false })
    expect(normalizeIntrospectResult('nope')).toEqual({ active: false })
    expect(normalizeIntrospectResult({})).toEqual({ active: false })
  })
})

describe('cacheKey', () => {
  it('combines origin and token, distinct per pair', () => {
    expect(cacheKey('t1', ORIGIN)).not.toBe(cacheKey('t2', ORIGIN))
    expect(cacheKey('t1', ORIGIN)).not.toBe(cacheKey('t1', 'https://other'))
  })
})

describe('computeCacheExpiryMs', () => {
  it('caps at now+ttl when no exp', () => {
    expect(computeCacheExpiryMs({ active: true, tenant_id: '', role: '', email: '' }, 1000, 5000)).toBe(6000)
  })
  it('bounds by JWT exp when exp*1000 is sooner than the ttl cap', () => {
    expect(
      computeCacheExpiryMs({ active: true, tenant_id: '', role: '', email: '', exp: 2 }, 1000, 5000),
    ).toBe(2000)
  })
  it('uses the ttl cap when exp is further out', () => {
    expect(
      computeCacheExpiryMs({ active: true, tenant_id: '', role: '', email: '', exp: 100 }, 1000, 5000),
    ).toBe(6000)
  })
  it('caps at now+ttl for inactive results', () => {
    expect(computeCacheExpiryMs({ active: false }, 1000, 5000)).toBe(6000)
  })
})

describe('introspectToken', () => {
  it('returns inactive without a fetch for an empty token', async () => {
    const fetchImpl = vi.fn()
    const cache = new Map()
    const res = await introspectToken({ authWorkerUrl: AUTH, sharedSecret: SECRET, token: '', origin: ORIGIN, fetchImpl, cache })
    expect(res).toEqual({ active: false })
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('fetches, normalizes and caches an active result', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(okResponse({ active: true, tenant_id: 't', role: 'viewer', email: 'a@b', sub: 'u1', exp: 9999999999 }))
    const cache = new Map()
    const res = await introspectToken({ authWorkerUrl: AUTH, sharedSecret: SECRET, token: 'jwt', origin: ORIGIN, fetchImpl, cache, nowMs: 0 })
    expect(res).toEqual({ active: true, tenant_id: 't', role: 'viewer', email: 'a@b', sub: 'u1', exp: 9999999999 })
    expect(fetchImpl).toHaveBeenCalledTimes(1)
    expect(cache.has(cacheKey('jwt', ORIGIN))).toBe(true)
  })

  it('serves a cached active result without re-fetching', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(okResponse({ active: true, tenant_id: 't', role: '', email: '', exp: 9999999999 }))
    const cache = new Map()
    const opts = { authWorkerUrl: AUTH, sharedSecret: SECRET, token: 'jwt', origin: ORIGIN, fetchImpl, cache, nowMs: 0 }
    await introspectToken(opts)
    const res = await introspectToken({ ...opts, nowMs: 1000 })
    expect(res.active).toBe(true)
    expect(fetchImpl).toHaveBeenCalledTimes(1) // 2nd call served from cache
  })

  it('re-fetches after the cache entry expires', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(okResponse({ active: true, tenant_id: 't', role: '', email: '', exp: 2 }))
    const cache = new Map()
    const base = { authWorkerUrl: AUTH, sharedSecret: SECRET, token: 'jwt', origin: ORIGIN, fetchImpl, cache, ttlMs: 1000 }
    await introspectToken({ ...base, nowMs: 0 }) // expiresAt = min(1000, 2000) = 1000
    await introspectToken({ ...base, nowMs: 5000 }) // expired → re-fetch
    expect(fetchImpl).toHaveBeenCalledTimes(2)
  })

  it('does not cache inactive results (fail-open recovery)', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(okResponse({ active: false }))
    const cache = new Map()
    const res = await introspectToken({ authWorkerUrl: AUTH, sharedSecret: SECRET, token: 'jwt', origin: ORIGIN, fetchImpl, cache, nowMs: 0 })
    expect(res).toEqual({ active: false })
    expect(cache.size).toBe(0)
  })

  it('fail-closed on non-2xx (401 shared-secret / 503 misconfig)', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(errResponse(401))
    const res = await introspectToken({ authWorkerUrl: AUTH, sharedSecret: SECRET, token: 'jwt', origin: ORIGIN, fetchImpl, cache: new Map() })
    expect(res).toEqual({ active: false })
  })

  it('fail-closed on a network/JSON error', async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error('boom'))
    const res = await introspectToken({ authWorkerUrl: AUTH, sharedSecret: SECRET, token: 'jwt', origin: ORIGIN, fetchImpl, cache: new Map() })
    expect(res).toEqual({ active: false })
  })

  describe('default fetch / cache / now (no injection)', () => {
    beforeEach(() => {
      _clearIntrospectCache()
    })
    afterEach(() => {
      vi.unstubAllGlobals()
      _clearIntrospectCache()
    })

    it('uses global fetch, module cache and Date.now defaults', async () => {
      const globalFetch = vi.fn().mockResolvedValue(okResponse({ active: true, tenant_id: 't', role: '', email: '', exp: 9999999999 }))
      vi.stubGlobal('fetch', globalFetch)
      // only required args → exercises fetchImpl=fetch, cache=defaultCache, ttlMs/nowMs defaults
      const res1 = await introspectToken({ authWorkerUrl: AUTH, sharedSecret: SECRET, token: 'jwt-default', origin: ORIGIN })
      expect(res1.active).toBe(true)
      // 2nd call hits the module-scope default cache (no 2nd fetch)
      const res2 = await introspectToken({ authWorkerUrl: AUTH, sharedSecret: SECRET, token: 'jwt-default', origin: ORIGIN })
      expect(res2.active).toBe(true)
      expect(globalFetch).toHaveBeenCalledTimes(1)
      expect(DEFAULT_TTL_MS).toBeGreaterThan(0)
    })
  })
})
