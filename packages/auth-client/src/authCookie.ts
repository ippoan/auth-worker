/**
 * 共有 auth cookie (`logi_auth_token`) の client 側読み出し (pure、DOM 非依存)。
 *
 * ブラウザは host-only cookie と `Domain=.ippoan.org` 付き cookie を別物として
 * **両方** `document.cookie` に載せる。古い方が先頭に来ると、先頭一致 1 件だけを
 * 見る実装は期限切れの token を拾って「未ログイン」と誤判定し、ログイン直後なのに
 * もう一度 Google へ飛ばす (auth-worker 側で #387 / #531 として直したのと同じ穴)。
 *
 * 同名 cookie の候補を全部走査し、payload が decode できて `exp` が未来の
 * **最初の候補**を返す。`exp` の無い token は採用しない (server の verifyJwt と
 * 同じく期限が判定できないものは信用しない)。
 */
import { decodeJwtPayloadFromToken } from './jwt'

/** `document.cookie` 形式の文字列から `name` の値を全て返す (出現順)。 */
export function readCookieValues(cookieString: string, name: string): string[] {
  const prefix = name + '='
  const out: string[] = []
  for (const part of cookieString.split('; ')) {
    if (part.startsWith(prefix)) out.push(part.slice(prefix.length))
  }
  return out
}

/**
 * `name` の同名 cookie 候補のうち、`exp > nowSec` を満たす最初の JWT を返す。
 * 該当が無ければ null。
 */
export function findValidAuthCookieToken(
  cookieString: string,
  name: string,
  nowSec: number,
): string | null {
  for (const token of readCookieValues(cookieString, name)) {
    if (!token) continue
    const payload: Record<string, unknown> = decodeJwtPayloadFromToken(token)
    const exp = payload.exp
    if (typeof exp === 'number' && exp > nowSec) return token
  }
  return null
}
