/**
 * `@ippoan/auth-client/server` — Nitro server route / middleware 向けの
 * server-side ヘルパー (Refs ippoan/auth-worker#257)。
 *
 * - client バンドルに h3 import を漏らさないため、root export (`.`) とは
 *   分離した subpath で公開する
 * - **.mjs なのは Nitro (rollup) が node_modules の .ts を transpile しない
 *   ため** (.ts のままだと server route から import した consumer の
 *   `nuxt build` が RollupError: PARSE_ERROR で落ちる)。型は ./index.d.mts
 * - server route から root (`@ippoan/auth-client`) を import しないこと —
 *   root は .ts / .vue を含むため Nitro で同じ parse error になる
 */
export { getParentDomainFromHost, resolveAuthAction, checkTenantId } from './authLogic.mjs'

// createApiProxyHandler = 署名なし decode で X-Tenant-ID だけ載せる旧 proxy。
// createIdentityProxyHandler = introspect 検証 + X-Tenant-ID/X-User-* 注入
// (rust-alc-api#434 step 2、AuthUser 復元対応)。
export { createApiProxyHandler, createIdentityProxyHandler } from './proxy.mjs'

// issue #290 Phase 2: introspect ベースの認証 (署名検証 + APP_TENANT_ACL 判定を
// auth-worker に集約)。`requireAuth` は h3 ガード、core は h3 非依存で再利用可。
export { requireAuth } from './auth.mjs'

export {
  introspectToken,
  buildIntrospectRequest,
  normalizeIntrospectResult,
  cacheKey,
  computeCacheExpiryMs,
  DEFAULT_TTL_MS,
  _clearIntrospectCache,
} from './introspectCore.mjs'

export {
  buildProxyHeaders,
  buildTargetUrl,
  classifyProxyResponse,
  parseJsonBody,
} from './proxyCore.mjs'

// server route でもよく使う JWT util を再 export
export {
  decodeJwtPayload,
  decodeJwtPayloadFromToken,
  extractTenantIdFromAuth,
} from '../jwt-core.mjs'

// rust-alc-api#434 step 3: Cloud Run IAM lockdown 用の OIDC ID token mint。
export { mintGoogleIdToken } from './oidc.mjs'
