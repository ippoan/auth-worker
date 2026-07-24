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

### dev-login: localhost ブラウザ検証 (issue #423/#425)

`wrangler dev --remote` の localhost には本番 `.ippoan.org` cookie が届かないため、
MCP (`issue_dev_login_url` tool) が発行するワンタイム code を `__dev/callback` で
`logi_auth_token_dev` cookie に交換し、proxy handler 側で `logi_auth_token` として
backend に転送する。**localhost 専用**（`preview-*.ippoan.org` は SSO が素で効くため
対象外）。DEV_LOGIN ガードは consumer 側の責務 — `[env.dev.vars]` にのみ
`DEV_LOGIN="true"` を定義し、本番 vars には定義しない (未定義なら 404)。

```typescript
// server/routes/__dev/callback.get.ts
import { createDevLoginCallbackHandler } from '@ippoan/auth-client/server'

export default defineEventHandler((event) => {
  if (useRuntimeConfig(event).public.devLogin !== 'true') {
    throw createError({ statusCode: 404 })
  }
  return createDevLoginCallbackHandler({
    authWorkerUrl: () => useRuntimeConfig(event).public.authWorkerUrl as string,
  })(event)
})
```

```typescript
// server/api/proxy/[...path].ts — 既存 proxy handler に devLoginEnabled を足すだけ
export default createIdentityProxyHandler({
  // ...backendUrl / authWorkerUrl / sharedSecret は既存のまま
  devLoginEnabled: event => useRuntimeConfig(event).public.devLogin === 'true',
})
```

- `createDevLoginCallbackHandler` — code を `POST {authWorkerUrl}/dev-login/token`
  に server-to-server 交換し、`token_kind=dev` を確認できたら
  `logi_auth_token_dev` を HttpOnly / SameSite=Lax / host-only で Set-Cookie して
  `/#token=...` (fragment handoff、#442) へ 302 する。署名の再検証はしない
  （交換自体が TLS 越しの server-to-server 呼び出しで、auth-worker 自身が
  署名した token しか返らないため）
  - cookie は server route (`/api/proxy/*` の dev フォールバック) 用、fragment は
    SPA (`initAuthSession`/`consumeFragment`) のクライアント側セッション確立用。
    fragment が無いと SPA は httpOnly cookie を読めず未認証判定 → 通常ログイン →
    localhost は redirect_uri 許可外で "Invalid or missing redirect_uri" になる
    (#442 で修正)。org_id / expires は dev token の claims (`tenant_id` / `exp`)
    フォールバックで解決されるため fragment は token のみ
- `createApiProxyHandler` / `createAuthWorkerProxyHandler` / `createIdentityProxyHandler`
  の `devLoginEnabled` オプション — 通常 cookie (`logi_auth_token`) が無いとき
  `logi_auth_token_dev` をフォールバックとして拾う。`devLoginEnabled` 未指定
  (default) の consumer には非破壊
- dev token TTL は 30 分・refresh なし。期限切れ後は MCP で `issue_dev_login_url`
  を再発行する

## 使用先

- [nuxt-pwa-carins](https://github.com/yhonda-ohishi/nuxt-pwa-carins) — メインUI（carins.mtamaramu.com）
- [nuxt-dtako-logs](https://github.com/yhonda-ohishi/nuxt_dtako_logs) — DTakoログビューワー（ohishi2.mtamaramu.com）
