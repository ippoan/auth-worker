/**
 * テスト用 HS256 JWT 生成
 */
import { createHmac } from 'node:crypto'

export interface JwtPayload {
  sub: string
  email?: string
  name?: string
  tenant_id?: string
  role?: string
  [key: string]: unknown
}

/** HS256 JWT を生成する */
export function makeJwt(secret: string, payload: JwtPayload): string {
  const header = { alg: 'HS256', typ: 'JWT' }
  const now = Math.floor(Date.now() / 1000)
  const fullPayload = {
    iat: now,
    exp: now + 3600,
    ...payload,
  }
  const b64 = (obj: unknown) =>
    Buffer.from(JSON.stringify(obj)).toString('base64url')
  const unsigned = `${b64(header)}.${b64(fullPayload)}`
  const sig = createHmac('sha256', secret).update(unsigned).digest('base64url')
  return `${unsigned}.${sig}`
}
