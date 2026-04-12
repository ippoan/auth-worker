/**
 * Nuxt route middleware ファクトリ
 * 認証チェック + staging bypass + isLoading 待機
 */
import { useRuntimeConfig, navigateTo } from '#imports'
import { useAuth } from './useAuth'

export interface AuthMiddlewareOptions {
  publicPaths?: string[]
  loginPath?: string
}

/**
 * Nuxt route middleware を生成。defineNuxtRouteMiddleware() に渡して使用。
 *
 * @example
 * ```ts
 * import { authMiddleware } from '@ippoan/auth-client'
 * export default defineNuxtRouteMiddleware(
 *   authMiddleware({ publicPaths: ['/login', '/auth/callback'] })
 * )
 * ```
 */
export function authMiddleware(options: AuthMiddlewareOptions = {}) {
  const { publicPaths = ['/login'], loginPath = '/login' } = options

  return (to: { path: string }) => {
    const config = useRuntimeConfig()

    // Staging bypass
    if ((config.public.stagingTenantId as string | undefined)) return

    // Public paths
    if (publicPaths.some(p => to.path.startsWith(p))) return

    const { isAuthenticated, isLoading } = useAuth()

    // 初期化中はスキップ（loadFromStorage 完了待ち）
    if (isLoading.value) return

    if (!isAuthenticated.value) {
      return navigateTo(loginPath)
    }
  }
}
