import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mintGoogleIdToken, _clearIdTokenCache } from '../src/server/oidc.mjs'

// ---------------------------------------------------------------------------
// テスト用 SA key (実 RSA 鍵を WebCrypto で生成して PKCS#8 PEM 化)
// ---------------------------------------------------------------------------
function pkcs8ToPem(der: ArrayBuffer): string {
  const bytes = new Uint8Array(der)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  const b64 = btoa(bin)
  const lines = b64.match(/.{1,64}/g) ?? []
  return `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----\n`
}

async function makeSaKey() {
  const kp = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )
  const der = await crypto.subtle.exportKey('pkcs8', kp.privateKey)
  return {
    type: 'service_account',
    client_email: 'alc-api-proxy-invoker@cloudsql-sv.iam.gserviceaccount.com',
    private_key_id: 'test-key-id',
    private_key: pkcs8ToPem(der),
    token_uri: 'https://oauth2.googleapis.com/token',
  }
}

function b64url(obj: Record<string, unknown>): string {
  const json = JSON.stringify(obj)
  const bytes = new TextEncoder().encode(json)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** id_token 風 JWT (payload に exp だけ持たせる) */
function fakeIdToken(exp: number): string {
  return `${b64url({ alg: 'RS256' })}.${b64url({ exp })}.sig`
}

function okTokenResponse(idToken: string): Response {
  return { ok: true, status: 200, json: async () => ({ id_token: idToken }) } as unknown as Response
}

const AUD = 'https://rust-alc-api-staging-747065218280.asia-northeast1.run.app'

describe('mintGoogleIdToken (rust-alc-api#434 step 3)', () => {
  beforeEach(() => _clearIdTokenCache())

  it('SA key で jwt-bearer assertion を組んで id_token を返す', async () => {
    const sa = await makeSaKey()
    const now = 1_700_000_000
    const fetchImpl = vi.fn(async () => okTokenResponse(fakeIdToken(now + 3600)))

    const token = await mintGoogleIdToken(JSON.stringify(sa), AUD, { fetchImpl, now, nowMs: now * 1000 })
    expect(token).toBe(fakeIdToken(now + 3600))
    expect(fetchImpl).toHaveBeenCalledTimes(1)

    const [url, init] = fetchImpl.mock.calls[0]!
    expect(url).toBe(sa.token_uri)
    const body = new URLSearchParams((init as RequestInit).body as string)
    expect(body.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:jwt-bearer')

    // assertion の header / claims を検証
    const assertion = body.get('assertion')!
    const [h, p] = assertion.split('.')
    const header = JSON.parse(atob(h!.replace(/-/g, '+').replace(/_/g, '/')))
    const claims = JSON.parse(atob(p!.replace(/-/g, '+').replace(/_/g, '/')))
    expect(header.alg).toBe('RS256')
    expect(header.kid).toBe('test-key-id')
    expect(claims.iss).toBe(sa.client_email)
    expect(claims.sub).toBe(sa.client_email)
    expect(claims.aud).toBe(sa.token_uri)
    expect(claims.target_audience).toBe(AUD)
    expect(claims.exp - claims.iat).toBe(3600)
  })

  it('object でも文字列でも受ける + audience 単位で cache (2 回目は fetch しない)', async () => {
    const sa = await makeSaKey()
    const now = 1_700_000_000
    const fetchImpl = vi.fn(async () => okTokenResponse(fakeIdToken(now + 3600)))

    const t1 = await mintGoogleIdToken(sa, AUD, { fetchImpl, now, nowMs: now * 1000 })
    const t2 = await mintGoogleIdToken(sa, AUD, { fetchImpl, now, nowMs: now * 1000 })
    expect(t1).toBe(t2)
    expect(fetchImpl).toHaveBeenCalledTimes(1) // cache hit
  })

  it('exp 手前 (60s 以内) は cache 失効して再 mint する', async () => {
    const sa = await makeSaKey()
    const now = 1_700_000_000
    const fetchImpl = vi.fn(async () => okTokenResponse(fakeIdToken(now + 100)))

    await mintGoogleIdToken(sa, AUD, { fetchImpl, now, nowMs: now * 1000 })
    // 50s 後 = exp(100s 先) の 60s 手前 → 再 mint
    await mintGoogleIdToken(sa, AUD, { fetchImpl, now: now + 50, nowMs: (now + 50) * 1000 })
    expect(fetchImpl).toHaveBeenCalledTimes(2)
  })

  it('audience 未指定は throw', async () => {
    const sa = await makeSaKey()
    await expect(mintGoogleIdToken(JSON.stringify(sa), '', { fetchImpl: vi.fn() })).rejects.toThrow(
      /audience/,
    )
  })

  it('SA key 不正 (private_key 欠落) は throw', async () => {
    await expect(
      mintGoogleIdToken(JSON.stringify({ client_email: 'x@y' }), AUD, { fetchImpl: vi.fn() }),
    ).rejects.toThrow(/invalid service account key/)
  })

  it('token endpoint が non-ok なら throw', async () => {
    const sa = await makeSaKey()
    const fetchImpl = vi.fn(async () => ({ ok: false, status: 403, json: async () => ({}) }) as unknown as Response)
    await expect(mintGoogleIdToken(sa, AUD, { fetchImpl, noCache: true })).rejects.toThrow(/403/)
  })

  it('id_token が response に無ければ throw', async () => {
    const sa = await makeSaKey()
    const fetchImpl = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({}) }) as unknown as Response)
    await expect(mintGoogleIdToken(sa, AUD, { fetchImpl, noCache: true })).rejects.toThrow(/no id_token/)
  })
})
