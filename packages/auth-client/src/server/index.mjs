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

export { createApiProxyHandler } from './proxy.mjs'

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
