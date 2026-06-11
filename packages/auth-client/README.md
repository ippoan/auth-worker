# @yhonda-ohishi-pub-dev/auth-client

フロントエンド共通の認証 composable（Nuxt 3 用）。LINE WORKS 自動ログイン対応。

## インストール

```bash
# .npmrc に追加
echo "@yhonda-ohishi-pub-dev:registry=https://npm.pkg.github.com" >> .npmrc

# インストール
npm install @yhonda-ohishi-pub-dev/auth-client
```

## セットアップ

### 1. nuxt.config.ts

```typescript
export default defineNuxtConfig({
  build: {
    transpile: ['@yhonda-ohishi-pub-dev/auth-client'],
  },
  runtimeConfig: {
    public: {
      authWorkerUrl: process.env.NUXT_PUBLIC_AUTH_WORKER_URL || '',
    },
  },
})
```

### 2. composables/useAuth.ts

```typescript
export { useAuth } from '@yhonda-ohishi-pub-dev/auth-client'
export type { AuthState } from '@yhonda-ohishi-pub-dev/auth-client'
```

## API

```typescript
const {
  authState,        // Ref<AuthState | null> — JWT状態
  isAuthenticated,  // ComputedRef<boolean> — 認証済みか
  token,            // ComputedRef<string | null> — JWTトークン
  orgId,            // ComputedRef<string | null> — 組織ID
  loadFromStorage,  // () => void — localStorageから復元
  consumeFragment,  // () => boolean — URL fragment (#token=...) を解析・保存
  redirectToLogin,  // () => void — ログイン画面へリダイレクト（LWドメイン保存済みなら自動ログイン）
  logout,           // () => void — ログアウト（LWドメインもクリア）
  saveLwDomain,     // (domain: string) => void — LINE WORKSドメインを保存
  getLwDomain,      // () => string | null — 保存済みLINE WORKSドメインを取得
  clearLwDomain,    // () => void — LINE WORKSドメインをクリア
} = useAuth()
```

## LINE WORKS 自動ログイン

Bot が `?lw=<domain>` パラメータ付き URL を送信:

```
https://carins.mtamaramu.com/?lw=ohishi
```

### フロー

1. **初回**: `?lw=ohishi` → ドメインを localStorage/cookie に保存 → LINE WORKS OAuth 自動開始
2. **2回目以降**: パラメータなしでも保存済みドメインで自動ログイン
3. **ログアウト**: `clearLwDomain()` でドメイン記憶を解除 → 通常ログインページ

### plugins/auth.client.ts での使い方

共通フローは `initAuthSession()` に集約済み (Refs ippoan/auth-worker#257)。
plugin は数行で済む:

```typescript
import { initAuthSession } from '@ippoan/auth-client'

export default defineNuxtPlugin({
  name: 'auth',
  enforce: 'pre',
  setup() {
    // ?lw= 保存 → fragment/localStorage/cookie 復元 → 未認証 redirect
    // → 組織一覧取得 → 期限切れタイマー、まで一括
    initAuthSession()
    // 組織一覧が不要なら: initAuthSession({ fetchOrganizations: false })
  },
})
```

WOFF 認証や backend 種別ガード等のアプリ固有処理は、消費側 plugin で
`initAuthSession()` の前に行う (自前で認証を確立したら呼ばない)。

### pages/auth/callback.vue での使い方

```vue
<script setup lang="ts">
definePageMeta({ layout: 'auth' })
</script>

<template>
  <AuthCallback redirect-to="/operations" login-path="/login" />
</template>
```

## server-side ヘルパー (`@ippoan/auth-client/server`)

Nitro server route / middleware 向け。client バンドルに h3 import を
漏らさないため subpath で公開している。

```typescript
// server/middleware/auth.ts — リダイレクト判定 (pure ロジック)
import { resolveAuthAction, checkTenantId } from '@ippoan/auth-client/server'

// server/api/proxy/[...path].ts — backend への REST プロキシ
import { createApiProxyHandler } from '@ippoan/auth-client/server'
export default createApiProxyHandler({
  backendUrl: event =>
    (useRuntimeConfig(event).alcApiUrl as string) || 'https://alc-api.ippoan.org',
})
```

- `resolveAuthAction` — 未認証時の LINE WORKS / login リダイレクト判定 (WOFF 対応)
- `checkTenantId` — JWT cookie のテナント制限チェック
- `createApiProxyHandler` — Authorization 転送 + JWT→X-Tenant-ID 変換 + binary/JSON 透過
- `extractTenantIdFromAuth` / `decodeJwtPayloadFromToken` — JWT util の再 export

## 使用先

- [nuxt-pwa-carins](https://github.com/yhonda-ohishi/nuxt-pwa-carins) — メインUI（carins.mtamaramu.com）
- [nuxt-dtako-logs](https://github.com/yhonda-ohishi/nuxt_dtako_logs) — DTakoログビューワー（ohishi2.mtamaramu.com）
