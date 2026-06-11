export { useAuth } from './useAuth'
export type { AuthState } from './useAuth'
export { initAuthSession } from './initAuthSession'
export type { InitAuthSessionOptions } from './initAuthSession'
export { createAuthFetch } from './createAuthFetch'
export type { AuthFetchOptions } from './createAuthFetch'
export {
  decodeJwtPayload,
  decodeJwtPayloadFromToken,
  decodeJwtClaims,
  extractTenantIdFromAuth,
} from './jwt'
export { authMiddleware } from './authMiddleware'
export type { AuthMiddlewareOptions } from './authMiddleware'
export { default as AuthToolbar } from './AuthToolbar.vue'
export { default as AuthCallback } from './AuthCallback.vue'
export { default as StagingFooter } from './StagingFooter.vue'
export { default as VersionBadge } from './VersionBadge.vue'
