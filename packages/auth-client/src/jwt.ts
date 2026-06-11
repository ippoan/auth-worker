/**
 * JWT デコードユーティリティ（framework-agnostic、client / server 両用）
 *
 * 実装は ./jwt-core.mjs — Nitro (rollup) が node_modules の .ts を transpile
 * しないため、server 経路で import 可能な .mjs に置いてある (型は
 * ./jwt-core.d.mts)。client からの公開 API はこのファイル経由で従来どおり。
 */
export {
  decodeJwtPayload,
  decodeJwtPayloadFromToken,
  decodeJwtClaims,
  extractTenantIdFromAuth,
} from './jwt-core.mjs'
