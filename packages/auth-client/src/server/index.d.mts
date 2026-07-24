/**
 * `@ippoan/auth-client/server` の型定義 — 実装は index.mjs (理由はそちらの
 * doc comment 参照)。
 */
import type { H3Event, EventHandler } from 'h3'

// ----- authLogic -----

export interface AuthConfig {
  apiBackend: string
  authWorkerUrl: string
}

export interface AuthRequest {
  pathname: string
  origin: string
  hostname: string
  searchParams: URLSearchParams
  /** logi_auth_token */
  cookie: string | undefined
  /** lw_domain */
  lwDomainCookie: string | undefined
}

export type AuthAction =
  | { type: 'pass' }
  | { type: 'set-cookie-and-pass'; name: string; value: string; domain: string | undefined }
  | {
      type: 'set-cookie-and-redirect'
      name: string
      value: string
      domain: string | undefined
      redirectUrl: string
    }
  | { type: 'redirect'; redirectUrl: string }

export type TenantCheckResult = { type: 'pass' } | { type: 'forbidden'; reason: string }

export declare function getParentDomainFromHost(hostname: string): string | undefined

export declare function resolveAuthAction(config: AuthConfig, req: AuthRequest): AuthAction

export declare function checkTenantId(
  cookie: string | undefined,
  allowedTenantId: string,
): TenantCheckResult

// ----- introspect (issue #290 Phase 2) -----

/** auth-worker `/auth/introspect` の正規化済み結果。 */
export type IntrospectResult =
  | { active: false }
  | { active: true; tenant_id: string; role: string; email: string; sub: string; exp?: number}

export interface IntrospectTokenOptions {
  /** auth-worker origin (例: https://auth.ippoan.org) */
  authWorkerUrl: string
  /** INTERNAL_SHARED_SECRET (raw) */
  sharedSecret: string
  /** 検証対象の browser JWT */
  token: string
  /** 呼び出しアプリの origin (APP_TENANT_ACL 分割用) */
  origin: string
  /** fetch 実装 (test 用に注入可) */
  fetchImpl?: typeof fetch
  /** cache 実装 (test 用に注入可) */
  cache?: Map<string, { result: IntrospectResult; expiresAtMs: number }>
  /** cache TTL cap (ms, default 30000) */
  ttlMs?: number
  /** 現在時刻 (ms epoch, test 用に注入可) */
  nowMs?: number
}

export interface RequireAuthOptions {
  authWorkerUrl: string
  sharedSecret: string
  /** 明示 origin (proxy 環境で getRequestURL が内部 origin になる時) */
  origin?: string
  /** cookie 名 (default 'logi_auth_token') */
  cookieName?: string
  /** introspect cache TTL cap (ms) */
  ttlMs?: number
}

export declare const DEFAULT_TTL_MS: number

export declare function introspectToken(opts: IntrospectTokenOptions): Promise<IntrospectResult>

export declare function buildIntrospectRequest(opts: {
  authWorkerUrl: string
  sharedSecret: string
  token: string
  origin: string
}): { url: string; init: RequestInit }

export declare function normalizeIntrospectResult(data: unknown): IntrospectResult

export declare function cacheKey(token: string, origin: string): string

export declare function computeCacheExpiryMs(
  result: IntrospectResult,
  nowMs: number,
  ttlMs: number,
): number

export declare function _clearIntrospectCache(): void

/**
 * introspect ベースの h3 認証ガード。token を auth-worker `/auth/introspect`
 * で検証し、active なら結果を `event.context.auth` に載せて返す。inactive は
 * 401 (createError) を throw する。
 */
export declare function requireAuth(
  event: H3Event,
  options: RequireAuthOptions,
): Promise<{ active: true; tenant_id: string; role: string; email: string; sub: string; exp?: number}>

// ----- proxy -----

export interface ApiProxyOptions {
  /** backend の origin。文字列 or event から解決する関数 (runtimeConfig 参照用) */
  backendUrl: string | ((event: H3Event) => string)
  /** 転送先 path prefix (default: '/api/') */
  pathPrefix?: string
}

export declare function createApiProxyHandler(options: ApiProxyOptions): EventHandler

/** introspect 検証 + identity 注入 proxy のオプション (rust-alc-api#434 step 2)。 */
export interface IdentityProxyOptions {
  /** backend (rust-alc-api) の origin。値 or event から解決する関数 */
  backendUrl: string | ((event: H3Event) => string)
  /** auth-worker origin (introspect 先)。値 or event 解決関数 */
  authWorkerUrl: string | ((event: H3Event) => string)
  /** INTERNAL_SHARED_SECRET (raw)。値 or event 解決関数 */
  sharedSecret: string | ((event: H3Event) => string)
  /** introspect 用 fetch。CF service binding 推奨 (env.AUTH_WORKER.fetch)。 */
  introspectFetch?: (event: H3Event) => typeof fetch
  /** 明示 origin (default: request URL の origin) */
  origin?: string
  /** 転送先 path prefix (default: '/api/') */
  pathPrefix?: string
  /** cookie 名 (default 'logi_auth_token') */
  cookieName?: string
  /**
   * issue #423/#425: dev-login bridge を有効化する。true (または event 解決関数が
   * true を返す) の consumer は `cookieName` が無いとき `devCookieName` を
   * フォールバックとして拾い、backend へは通常 cookie と同様に転送する。
   * 未指定 (default false) の consumer には非破壊。
   */
  devLoginEnabled?: boolean | ((event: H3Event) => boolean)
  /** dev cookie 名 (default 'logi_auth_token_dev') */
  devCookieName?: string
  /** introspect cache TTL cap (ms) */
  ttlMs?: number
  /**
   * rust-alc-api#434 step 3: Cloud Run IAM lockdown 用の run.invoker SA key
   * (JSON 文字列、resolve 済み)。設定時のみ Google OIDC ID token を mint して
   * `Authorization: Bearer <id_token>` を付与する (未設定なら非破壊・無効)。
   */
  oidcServiceAccountKey?: string | ((event: H3Event) => string | undefined)
  /** OIDC `aud` (= 叩く Cloud Run service URL)。default: backendUrl の origin */
  oidcAudience?: string | ((event: H3Event) => string)
  /** OIDC token endpoint 用 fetch (test 注入)。default: global fetch */
  oidcFetch?: (event: H3Event) => typeof fetch
}

/**
 * introspect 検証 → X-Tenant-ID + X-User-ID/Email/Role 注入 → backend 転送を
 * 1 本化した h3 handler。inactive は 401。
 */
export declare function createIdentityProxyHandler(options: IdentityProxyOptions): EventHandler

/**
 * auth-worker `/alc-proxy/*` への thin-forward proxy のオプション
 * (rust-alc-api#434 step 3 方式 B)。consumer は SA key / OIDC mint / introspect
 * を持たず、service binding で auth-worker に丸投げする。
 */
export interface AuthWorkerProxyOptions {
  /** INTERNAL_SHARED_SECRET (raw)。`X-Alc-Proxy-Secret` に載せて consumer proof
   *  にする。値 or event 解決関数。 */
  sharedSecret: string | ((event: H3Event) => string)
  /** auth-worker `/alc-proxy/*` を叩く fetch。**CF service binding 必須**
   *  (`env.AUTH_WORKER.fetch.bind(env.AUTH_WORKER)`)。 */
  authWorkerFetch: (event: H3Event) => typeof fetch
  /** service binding fetch 用の絶対 URL base (host は binding が無視するので
   *  任意、path が `/alc-proxy/...` になればよい)。default: 内部 placeholder。 */
  authWorkerUrl?: string | ((event: H3Event) => string)
  /** 明示 origin (default: request URL の origin)。`X-Alc-Proxy-Origin` に載る。 */
  origin?: string
  /** rust-alc-api 側 path prefix (default: '/api/') */
  pathPrefix?: string
  /** auth-worker 側 route prefix (default: '/alc-proxy') */
  proxyPrefix?: string
  /** cookie 名 (default 'logi_auth_token') */
  cookieName?: string
  /** issue #423/#425: dev-login bridge を有効化する (`IdentityProxyOptions.devLoginEnabled` 参照)。 */
  devLoginEnabled?: boolean | ((event: H3Event) => boolean)
  /** dev cookie 名 (default 'logi_auth_token_dev') */
  devCookieName?: string
  /**
   * 2026-07-24: consumer が dev-login 用の `AUTH_WORKER` binding を prod に
   * 向けた時の安全弁。**未指定 (default) なら無制限** (既存 consumer に非破壊)。
   * 値 (または event 解決関数の戻り値) を渡すと、GET/HEAD/OPTIONS 以外の
   * method は path が配列のいずれかの prefix と一致しない限り 403 になる
   * (`isDevLoginWriteAllowed` 参照)。dev token は本番 JWT と同じ鍵で署名されて
   * おり (issue #423 の残存リスク)、権限昇格ではなく「検証中の未検証ローカル
   * コードが事故で prod に書き込む」事故を防ぐためのもの。
   */
  devLoginWriteAllowlist?: string[] | ((event: H3Event) => string[] | undefined)
}

/**
 * browser JWT + consumer proof secret + origin を `/alc-proxy/*` に service
 * binding で thin-forward する h3 handler。introspect / OIDC mint は auth-worker
 * 側で行われる。
 */
export declare function createAuthWorkerProxyHandler(options: AuthWorkerProxyOptions): EventHandler

/**
 * service account key で Google OIDC ID token を mint する (Cloud Run IAM 用)。
 * audience 単位で exp 手前まで cache。
 */
export declare function mintGoogleIdToken(
  saKeyJson: string | object,
  audience: string,
  opts?: {
    fetchImpl?: typeof fetch
    subtle?: SubtleCrypto
    now?: number
    nowMs?: number
    noCache?: boolean
  },
): Promise<string>

// ----- proxyCore -----

export interface ProxyHeaderInput {
  contentType?: string
  /** `Authorization: Bearer <jwt>` */
  authorization?: string
  /** `x-auth-token` ヘッダー (gRPC 時代の互換、nuxt_dtako_logs) */
  xAuthToken?: string
  /** 明示的な `X-Tenant-ID` ヘッダー (JWT 抽出より優先) */
  xTenantId?: string
}

export type ProxyResponseKind = 'binary' | 'empty' | 'json'

export declare function buildProxyHeaders(input: ProxyHeaderInput): Record<string, string>

/**
 * auth-worker `/alc-proxy/*` への thin-forward 用ヘッダーを構築する
 * (rust-alc-api#434 step 3 方式 B)。`X-Alc-Proxy-Secret` (consumer proof) +
 * `X-Alc-Proxy-Origin` を必ず載せ、browser JWT / content-type を素通しする。
 */
export declare function buildAlcProxyHeaders(input: {
  sharedSecret: string
  origin: string
  token?: string
  contentType?: string
  /** flip 前 preview override (`alc_api_preview_base` cookie 値)。あれば
   *  `X-Alc-Preview-Api-Base` に載せる。検証は auth-worker `/alc-proxy` 側
   *  (Refs ippoan/ci-dashboard#472)。 */
  previewApiBase?: string
}): Record<string, string>

/**
 * introspect 検証済み結果から `X-Tenant-ID` + `X-User-ID/Email/Role` を構築する
 * (rust-alc-api#434)。空フィールドは省略する。
 */
export declare function buildIdentityHeaders(
  result: { active: true; tenant_id: string; role: string; email: string; sub: string; exp?: number },
  opts?: { contentType?: string },
): Record<string, string>

export declare function classifyProxyResponse(
  status: number,
  contentType: string | null,
  path: string,
): ProxyResponseKind

export declare function parseJsonBody(text: string): unknown

export declare function buildTargetUrl(
  backendUrl: string,
  pathPrefix: string,
  path: string,
  query: Record<string, unknown>,
): string

// ----- jwt re-export -----

export {
  decodeJwtPayload,
  decodeJwtPayloadFromToken,
  extractTenantIdFromAuth,
} from '../jwt-core.mjs'

// ----- dev-login (issue #423/#425) -----

export declare const DEV_COOKIE_NAME: string

export declare function buildDevTokenExchangeRequest(opts: {
  authWorkerUrl: string
  code: string
}): { url: string; init: RequestInit }

export type DevTokenExchangeResult =
  | { ok: false }
  | { ok: true; token: string; expiresIn?: number }

export declare function normalizeDevTokenExchangeResult(
  status: number,
  data: unknown,
): DevTokenExchangeResult

export declare function devCookieOptions(expiresIn?: number): {
  httpOnly: true
  sameSite: 'lax'
  path: '/'
  maxAge?: number
}

/** GET/HEAD/OPTIONS は allowlist の対象外 (常に安全)。 */
export declare function isSafeMethod(method: string): boolean

/** カンマ区切りの path prefix 文字列を配列にパースする (空/undefined は空配列)。 */
export declare function parseDevLoginWriteAllowlist(raw: unknown): string[]

/**
 * method/path が allowlist で許可されているか判定する。safe method は
 * allowlist に関係なく常に許可、それ以外は prefix 完全一致 (`prefix` または
 * `${prefix}/...`) の時のみ許可。
 */
export declare function isDevLoginWriteAllowed(
  method: string,
  path: string,
  allowlist: string[],
): boolean

export interface DevLoginCallbackOptions {
  /** auth-worker origin (code 交換先)。値 or event から解決する関数 */
  authWorkerUrl: string | ((event: H3Event) => string)
  /** 成功時のリダイレクト先 (default '/') */
  redirectTo?: string
  /** code 交換用 fetch (test 注入 / CF service binding 用、default: global fetch) */
  fetchImpl?: typeof fetch
  /** dev cookie 名 (default 'logi_auth_token_dev') */
  cookieName?: string
}

/**
 * dev-login `__dev/callback` の h3 handler。code を auth-worker
 * `POST /dev-login/token` に交換し、`token_kind=dev` を確認できたら
 * dev cookie を Set-Cookie して redirectTo へ 302 する。DEV_LOGIN ガード
 * (本番 404) は consumer 側のルート登録責務。
 */
export declare function createDevLoginCallbackHandler(options: DevLoginCallbackOptions): EventHandler
