import { describe, it, expect } from 'vitest'
import {
  DEV_COOKIE_NAME,
  buildDevTokenExchangeRequest,
  devCookieOptions,
  normalizeDevTokenExchangeResult,
} from '../src/server/devLoginCore.mjs'

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

describe('buildDevTokenExchangeRequest', () => {
  it('POST {authWorkerUrl}/dev-login/token with JSON {code} body', () => {
    const { url, init } = buildDevTokenExchangeRequest({
      authWorkerUrl: 'https://auth.ippoan.org',
      code: 'abc123',
    })
    expect(url).toBe('https://auth.ippoan.org/dev-login/token')
    expect(init.method).toBe('POST')
    expect(init.headers).toEqual({ 'Content-Type': 'application/json' })
    expect(JSON.parse(init.body as string)).toEqual({ code: 'abc123' })
  })

  it('authWorkerUrl の末尾スラッシュを正規化する', () => {
    const { url } = buildDevTokenExchangeRequest({
      authWorkerUrl: 'https://auth.ippoan.org/',
      code: 'abc123',
    })
    expect(url).toBe('https://auth.ippoan.org/dev-login/token')
  })
})

describe('normalizeDevTokenExchangeResult', () => {
  it('token_kind=dev の access_token を ok:true で返す', () => {
    const token = makeToken({ sub: 'u1', token_kind: 'dev', exp: 123 })
    expect(normalizeDevTokenExchangeResult(200, { access_token: token, expires_in: 1800 })).toEqual({
      ok: true,
      token,
      expiresIn: 1800,
    })
  })

  it('expires_in が数値でなければ expiresIn は undefined', () => {
    const token = makeToken({ token_kind: 'dev' })
    expect(normalizeDevTokenExchangeResult(200, { access_token: token })).toEqual({
      ok: true,
      token,
      expiresIn: undefined,
    })
  })

  it('status が 200 以外は ok:false (fail-closed)', () => {
    const token = makeToken({ token_kind: 'dev' })
    expect(normalizeDevTokenExchangeResult(400, { access_token: token })).toEqual({ ok: false })
  })

  it('access_token が無い/不正型は ok:false', () => {
    expect(normalizeDevTokenExchangeResult(200, {})).toEqual({ ok: false })
    expect(normalizeDevTokenExchangeResult(200, { access_token: 123 })).toEqual({ ok: false })
    expect(normalizeDevTokenExchangeResult(200, undefined)).toEqual({ ok: false })
  })

  it('token_kind が dev でなければ ok:false (誤って通常 JWT を混入させない)', () => {
    const token = makeToken({ sub: 'u1' }) // token_kind 無し
    expect(normalizeDevTokenExchangeResult(200, { access_token: token })).toEqual({ ok: false })

    const other = makeToken({ token_kind: 'mcp' })
    expect(normalizeDevTokenExchangeResult(200, { access_token: other })).toEqual({ ok: false })
  })

  it('壊れた JWT は decode 失敗 → token_kind 不在扱いで ok:false', () => {
    expect(normalizeDevTokenExchangeResult(200, { access_token: 'not-a-jwt' })).toEqual({ ok: false })
  })
})

describe('devCookieOptions', () => {
  it('httpOnly / sameSite=lax / path=/ を常に含み、expiresIn を maxAge に載せる', () => {
    expect(devCookieOptions(1800)).toEqual({
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 1800,
    })
  })

  it('expiresIn が無ければ maxAge を省略する (session cookie)', () => {
    expect(devCookieOptions(undefined)).toEqual({
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
    })
  })
})

describe('DEV_COOKIE_NAME', () => {
  it('logi_auth_token_dev (本番 logi_auth_token との衝突回避、issue #423)', () => {
    expect(DEV_COOKIE_NAME).toBe('logi_auth_token_dev')
  })
})
