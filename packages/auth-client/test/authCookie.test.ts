import { describe, it, expect } from 'vitest'
import { findValidAuthCookieToken, readCookieValues } from '../src/authCookie'

/** base64url (UTF-8 safe、`-` / `_` を含みうる実運用と同型) で JWT を組む */
function b64url(obj: Record<string, unknown>): string {
  const bytes = new TextEncoder().encode(JSON.stringify(obj))
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function makeToken(payload: Record<string, unknown>): string {
  return `eyJhbGciOiJIUzI1NiJ9.${b64url(payload)}.sig`
}

const NOW = 1_700_000_000
const NAME = 'logi_auth_token'

describe('readCookieValues', () => {
  it('同名 cookie を出現順に全部返す', () => {
    const c = `${NAME}=a; other=x; ${NAME}=b`
    expect(readCookieValues(c, NAME)).toEqual(['a', 'b'])
  })

  it('前方一致の別名 (logi_auth_token_dev) は拾わない', () => {
    expect(readCookieValues(`${NAME}_dev=z; ${NAME}=a`, NAME)).toEqual(['a'])
  })

  it('無ければ空配列', () => {
    expect(readCookieValues('', NAME)).toEqual([])
    expect(readCookieValues('other=x', NAME)).toEqual([])
  })
})

describe('findValidAuthCookieToken', () => {
  const expired = makeToken({ sub: 'u1', exp: NOW - 10 })
  const valid = makeToken({ sub: 'u1', exp: NOW + 3600 })

  it('有効な cookie 1 件をそのまま返す', () => {
    expect(findValidAuthCookieToken(`${NAME}=${valid}`, NAME, NOW)).toBe(valid)
  })

  it('期限切れが先頭・有効が後続 (shadowing) でも有効な方を選ぶ', () => {
    const c = `${NAME}=${expired}; ${NAME}=${valid}`
    expect(findValidAuthCookieToken(c, NAME, NOW)).toBe(valid)
  })

  it('壊れた候補 (JWT でない) が先頭でも後続の有効な cookie を選ぶ', () => {
    const c = `${NAME}=garbage; ${NAME}=${valid}`
    expect(findValidAuthCookieToken(c, NAME, NOW)).toBe(valid)
  })

  it('全候補が期限切れなら null', () => {
    const c = `${NAME}=${expired}; ${NAME}=${makeToken({ exp: NOW })}`
    expect(findValidAuthCookieToken(c, NAME, NOW)).toBeNull()
  })

  it('exp の無い token は採用しない', () => {
    expect(findValidAuthCookieToken(`${NAME}=${makeToken({ sub: 'u1' })}`, NAME, NOW)).toBeNull()
  })

  it('cookie が無い / 空値なら null', () => {
    expect(findValidAuthCookieToken('', NAME, NOW)).toBeNull()
    expect(findValidAuthCookieToken(`${NAME}=`, NAME, NOW)).toBeNull()
  })

  it('多バイト claim (日本語の name) を含む base64url payload でも decode できる', () => {
    const t = makeToken({ sub: 'u1', name: '大石 太郎', exp: NOW + 60 })
    expect(findValidAuthCookieToken(`${NAME}=${t}`, NAME, NOW)).toBe(t)
  })
})
