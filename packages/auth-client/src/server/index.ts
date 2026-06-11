/**
 * `@ippoan/auth-client/server` — Nitro server route / middleware 向けの
 * server-side ヘルパー (Refs ippoan/auth-worker#257)。
 *
 * client バンドルに h3 import を漏らさないため、root export (`.`) とは
 * 分離した subpath で公開する。
 */
export {
  getParentDomainFromHost,
  resolveAuthAction,
  checkTenantId,
  type AuthConfig,
  type AuthRequest,
  type AuthAction,
  type TenantCheckResult,
} from './authLogic'

export { createApiProxyHandler, type ApiProxyOptions } from './proxy'

export {
  buildProxyHeaders,
  buildTargetUrl,
  classifyProxyResponse,
  parseJsonBody,
  type ProxyHeaderInput,
  type ProxyResponseKind,
} from './proxyCore'

// server route でもよく使う JWT util を再 export
export {
  decodeJwtPayload,
  decodeJwtPayloadFromToken,
  extractTenantIdFromAuth,
} from '../jwt'
