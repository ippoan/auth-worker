/**
 * dev-login (issue #423/#425) の pure ロジック（h3 非依存 / テスタブル）。
 * h3 handler 側は ./devLogin.mjs の `createDevLoginCallbackHandler` を参照。
 *
 * 署名の再検証はしない: `/dev-login/token` への code 交換は edge 上の
 * server-to-server 呼び出し (TLS) で、auth-worker 自身が署名した token しか
 * 返らない。ローカル JWKS 検証は攻撃面を減らさないため、`token_kind` の
 * decode チェックのみ行う (auth-worker 側 `dev-login-token.ts` の mint 時と
 * 同じ「検証なし decode」の非対称性は無い設計)。
 */
import { decodeJwtPayloadFromToken } from '../jwt-core.mjs'

/** dev-login 用 cookie 名。本番 `logi_auth_token` との混同防止のため分離 (issue #423)。 */
export const DEV_COOKIE_NAME = 'logi_auth_token_dev'

/** `POST {authWorkerUrl}/dev-login/token` 用の fetch params を組み立てる (純粋関数)。 */
export function buildDevTokenExchangeRequest({ authWorkerUrl, code }) {
  return {
    url: `${authWorkerUrl.replace(/\/$/, '')}/dev-login/token`,
    init: {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    },
  }
}

/**
 * 交換レスポンスを正規化する。`token_kind !== "dev"` を含め、あらゆる
 * 異常系は `{ ok: false }` (fail-closed) に畳む。
 */
export function normalizeDevTokenExchangeResult(status, data) {
  if (status !== 200 || !data || typeof data.access_token !== 'string') {
    return { ok: false }
  }
  const claims = decodeJwtPayloadFromToken(data.access_token)
  if (claims.token_kind !== 'dev') return { ok: false }
  return {
    ok: true,
    token: data.access_token,
    expiresIn: typeof data.expires_in === 'number' ? data.expires_in : undefined,
  }
}

/** dev cookie の属性。host-only (Domain 省略) / HttpOnly / SameSite=Lax、maxAge は token の exp 連動。 */
export function devCookieOptions(expiresIn) {
  return {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    ...(typeof expiresIn === 'number' ? { maxAge: expiresIn } : {}),
  }
}
