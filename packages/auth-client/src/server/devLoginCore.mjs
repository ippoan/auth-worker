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

/**
 * 成功時リダイレクト先の Location を組み立てる (純粋関数)。
 *
 * httpOnly cookie だけでは SPA consumer が dev セッションを確立できない —
 * `initAuthSession` (client 側) は fragment / localStorage / 非 httpOnly cookie
 * しか読めず、未認証と判定して通常ログイン (`redirectToLogin`) へ飛ばして
 * しまう (localhost は prod auth-worker の redirect_uri 許可外なので
 * "Invalid or missing redirect_uri" で死ぬ)。そこで通常ログインの
 * auth-worker handoff と同じ `#token=...` fragment で token を手渡す。
 * fragment はサーバーに送信されず、`consumeFragment` が localStorage 保存後に
 * `history.replaceState` で即座に除去する。org_id / expires は dev token の
 * claims (`tenant_id` / `exp`) へのフォールバックで解決されるため、fragment
 * には token のみ載せる。
 */
export function buildDevRedirectLocation(redirectTo, token) {
  return `${redirectTo}#token=${encodeURIComponent(token)}`
}

/**
 * dev-login write allowlist (2026-07-24、consumer が prod backend に向けた
 * `AUTH_WORKER` service binding を使う時の安全弁)。
 *
 * dev token は `logi_auth_token` と同じ `JWT_SECRET` で署名されているため、
 * consumer が dev-login 用の `AUTH_WORKER` service binding を prod
 * auth-worker に向けると、dev token はそのまま prod の `/alc-proxy` を通る
 * (issue #423 が「残存リスク(受容)」と明記した「dev tokenの本番持ち込み」)。
 * ここで守っているのは権限昇格ではなく、**検証中の未検証ローカルコードが
 * 事故で prod に書き込む**リスク — read/write とも consumer の通常ロール権限
 * の範囲内。よって write を一律禁止せず、consumer が起動時に明示登録した
 * path prefix だけを一時的に通す allowlist 方式にした。
 */

/** GET/HEAD/OPTIONS はデータを変更しないため allowlist の対象外 (常に許可)。 */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

export function isSafeMethod(method) {
  return SAFE_METHODS.has(method)
}

/** カンマ区切りの path prefix 文字列を配列にパースする (空/undefined は空配列)。 */
export function parseDevLoginWriteAllowlist(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return []
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

/**
 * method/path が allowlist で許可されているか判定する。
 * safe method (GET/HEAD/OPTIONS) は allowlist に関係なく常に許可。
 * それ以外は `allowlist` のいずれかの prefix と完全一致 or `${prefix}/` で
 * 始まる時のみ許可 (境界を跨いだ誤許可を防ぐ、例: "api/foo" は
 * "api/foo-bar" を許可しない)。
 */
export function isDevLoginWriteAllowed(method, path, allowlist) {
  if (isSafeMethod(method)) return true
  return allowlist.some((prefix) => path === prefix || path.startsWith(`${prefix}/`))
}
