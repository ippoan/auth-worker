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

// ----- proxy -----

export interface ApiProxyOptions {
  /** backend の origin。文字列 or event から解決する関数 (runtimeConfig 参照用) */
  backendUrl: string | ((event: H3Event) => string)
  /** 転送先 path prefix (default: '/api/') */
  pathPrefix?: string
}

export declare function createApiProxyHandler(options: ApiProxyOptions): EventHandler

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
