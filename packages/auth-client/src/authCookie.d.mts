/** 型定義 — 実装は authCookie.mjs (理由はそちらの doc comment 参照) */

/** `document.cookie` 形式の文字列から `name` の値を全て返す (出現順)。 */
export declare function readCookieValues(cookieString: string, name: string): string[]

/**
 * `name` の同名 cookie 候補のうち、`exp > nowSec` を満たす最初の JWT を返す。
 * 該当が無ければ null。
 */
export declare function findValidAuthCookieToken(
  cookieString: string,
  name: string,
  nowSec: number,
): string | null

/**
 * `authStateFromToken` が返す認証 state。`useAuth.ts` の `AuthState` と同形
 * (型の循環 import を避けるためここで独立宣言し、`useAuth.ts` 側で代入する)。
 */
export interface AuthCookieState {
  token: string
  orgId: string
  expiresAt: number
  username?: string
  provider?: string
  orgSlug?: string
}

/**
 * JWT payload から認証 state を組み立てる。`exp` が数値でなければ null。
 * `exp` の未来判定はしない (呼び出し側が `findValidAuthCookieToken` で済ませる)。
 */
export declare function authStateFromToken(token: string): AuthCookieState | null
