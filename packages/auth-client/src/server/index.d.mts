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
  /** introspect cache TTL cap (ms) */
  ttlMs?: number
}

/**
 * introspect 検証 → X-Tenant-ID + X-User-ID/Email/Role 注入 → backend 転送を
 * 1 本化した h3 handler。inactive は 401。
 */
export declare function createIdentityProxyHandler(options: IdentityProxyOptions): EventHandler

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
