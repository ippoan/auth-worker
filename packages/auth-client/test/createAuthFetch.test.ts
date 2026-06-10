import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { createAuthFetch } from '../src/createAuthFetch'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('createAuthFetch', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('Bearer + X-Tenant-ID を付与して JSON を返す', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ ok: true }))
    const af = createAuthFetch({
      baseUrl: 'https://api.example.com/',
      tokenGetter: () => 'tok-1',
      tenantIdGetter: () => 'tenant-1',
    })

    const data = await af<{ ok: boolean }>('/things')
    expect(data).toEqual({ ok: true })

    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('https://api.example.com/things') // 末尾スラッシュ除去
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer tok-1')
    expect((init.headers as Record<string, string>)['X-Tenant-ID']).toBe('tenant-1')
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json')
  })

  it('FormData body では Content-Type を付けない', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}))
    const af = createAuthFetch({
      baseUrl: 'https://api.example.com',
      tokenGetter: () => 'tok',
    })
    const fd = new FormData()
    fd.append('a', 'b')
    await af('/upload', { method: 'POST', body: fd })
    const init = fetchMock.mock.calls[0][1]
    expect((init.headers as Record<string, string>)['Content-Type']).toBeUndefined()
  })

  it('204 は undefined を返す', async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }))
    const af = createAuthFetch({ baseUrl: 'https://x', tokenGetter: () => null })
    expect(await af('/no-content')).toBeUndefined()
  })

  it('non-ok (500) は本文付きで throw する', async () => {
    fetchMock.mockResolvedValueOnce(new Response('boom', { status: 500 }))
    const af = createAuthFetch({ baseUrl: 'https://x', tokenGetter: () => null })
    await expect(af('/err')).rejects.toThrow('API error (500): boom')
  })

  describe('401 の挙動', () => {
    it('refresher 無し: onUnauthorized を呼び Unauthorized を throw', async () => {
      fetchMock.mockResolvedValueOnce(new Response(null, { status: 401 }))
      const onUnauthorized = vi.fn()
      const af = createAuthFetch({
        baseUrl: 'https://x',
        tokenGetter: () => 'tok',
        onUnauthorized,
      })
      await expect(af('/p')).rejects.toThrow('Unauthorized')
      expect(onUnauthorized).toHaveBeenCalledTimes(1)
      expect(fetchMock).toHaveBeenCalledTimes(1) // retry なし
    })

    it('refresher あり: 401 → refresh → retry 成功', async () => {
      fetchMock
        .mockResolvedValueOnce(new Response(null, { status: 401 }))
        .mockResolvedValueOnce(jsonResponse({ value: 42 }))
      let token = 'old'
      const tokenRefresher = vi.fn(async () => {
        token = 'new'
      })
      const onUnauthorized = vi.fn()
      const af = createAuthFetch({
        baseUrl: 'https://x',
        tokenGetter: () => token,
        tokenRefresher,
        onUnauthorized,
      })

      const data = await af<{ value: number }>('/p')
      expect(data).toEqual({ value: 42 })
      expect(tokenRefresher).toHaveBeenCalledTimes(1)
      expect(onUnauthorized).not.toHaveBeenCalled()
      // retry は新 token で叩かれる
      const retryInit = fetchMock.mock.calls[1][1]
      expect((retryInit.headers as Record<string, string>)['Authorization']).toBe('Bearer new')
    })

    it('refresher あり: token が無ければ refresh せず即 Unauthorized', async () => {
      fetchMock.mockResolvedValueOnce(new Response(null, { status: 401 }))
      const tokenRefresher = vi.fn()
      const onUnauthorized = vi.fn()
      const af = createAuthFetch({
        baseUrl: 'https://x',
        tokenGetter: () => null,
        tokenRefresher,
        onUnauthorized,
      })
      await expect(af('/p')).rejects.toThrow('Unauthorized')
      expect(tokenRefresher).not.toHaveBeenCalled()
      expect(onUnauthorized).toHaveBeenCalledTimes(1)
    })

    it('refresh 後も 401: onUnauthorized 1回 + Unauthorized throw', async () => {
      fetchMock
        .mockResolvedValueOnce(new Response(null, { status: 401 }))
        .mockResolvedValueOnce(new Response(null, { status: 401 }))
      const tokenRefresher = vi.fn(async () => {})
      const onUnauthorized = vi.fn()
      const af = createAuthFetch({
        baseUrl: 'https://x',
        tokenGetter: () => 'tok',
        tokenRefresher,
        onUnauthorized,
      })
      await expect(af('/p')).rejects.toThrow('Unauthorized')
      expect(onUnauthorized).toHaveBeenCalledTimes(1)
      expect(fetchMock).toHaveBeenCalledTimes(2)
    })

    it('refresh が reject: onUnauthorized 1回 + retry しない', async () => {
      fetchMock.mockResolvedValueOnce(new Response(null, { status: 401 }))
      const tokenRefresher = vi.fn(async () => {
        throw new Error('refresh failed')
      })
      const onUnauthorized = vi.fn()
      const af = createAuthFetch({
        baseUrl: 'https://x',
        tokenGetter: () => 'tok',
        tokenRefresher,
        onUnauthorized,
      })
      await expect(af('/p')).rejects.toThrow('Unauthorized')
      expect(onUnauthorized).toHaveBeenCalledTimes(1)
      expect(fetchMock).toHaveBeenCalledTimes(1) // retry なし
    })

    it('retry が 500: API error を伝播する (Unauthorized ではない)', async () => {
      fetchMock
        .mockResolvedValueOnce(new Response(null, { status: 401 }))
        .mockResolvedValueOnce(new Response('nope', { status: 500 }))
      const af = createAuthFetch({
        baseUrl: 'https://x',
        tokenGetter: () => 'tok',
        tokenRefresher: vi.fn(async () => {}),
      })
      await expect(af('/p')).rejects.toThrow('API error (500): nope')
    })

    it('single-flight: 同時 401 でも refresh は 1 回だけ', async () => {
      // 2 本の並行リクエスト両方が最初 401、refresh 後の retry で成功
      let resolveRefresh: () => void = () => {}
      const refreshGate = new Promise<void>((r) => {
        resolveRefresh = r
      })
      const tokenRefresher = vi.fn(async () => {
        await refreshGate
      })

      // call 順: req1=401, req2=401, retry1=200, retry2=200
      // (Response body は 1 回しか読めないので retry は都度 fresh に生成)
      fetchMock
        .mockResolvedValueOnce(new Response(null, { status: 401 }))
        .mockResolvedValueOnce(new Response(null, { status: 401 }))
        .mockImplementation(async () => jsonResponse({ ok: true }))

      const af = createAuthFetch({
        baseUrl: 'https://x',
        tokenGetter: () => 'tok',
        tokenRefresher,
      })

      const p1 = af('/a')
      const p2 = af('/b')
      // 両方が 401 を受け refresh に入るのを待ってから gate を開く
      await Promise.resolve()
      resolveRefresh()

      await expect(p1).resolves.toEqual({ ok: true })
      await expect(p2).resolves.toEqual({ ok: true })
      expect(tokenRefresher).toHaveBeenCalledTimes(1) // single-flight
    })
  })
})
