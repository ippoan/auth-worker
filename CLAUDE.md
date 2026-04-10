# auth-worker

Cloudflare Workers ベースの認証サービス + 共有パッケージ

## プロジェクト構成

- **auth-worker**: Cloudflare Workers (Hono) — OAuth フロー、JWT 発行、組織管理
- **packages/auth-client**: npm パッケージ `@ippoan/auth-client` — Nuxt フロントエンド共有コンポーネント

## auth-client パッケージ

### 型安全性

auth-client は `.vue` ソースファイルをそのまま ship する（ビルドステップなし）。
消費側の `nuxi typecheck` (vue-tsc) がソースを直接型チェックするため、**全ての `.vue` ファイルで strict な型注釈が必要**。

- `fetch().json()` の戻り値には必ず `as Type` を付ける（vue-tsc v5 では `unknown` になる）
- `Array()` リテラルには型注釈を付ける（`const parts: string[] = []`）
- `catch (e)` には `catch (e: unknown)` または `catch (e: any)` を明示

### publish フロー

- PR → CI `Publish Dev` で dev タグ publish
- merge + `v*` タグ → `Publish Release` で latest publish
- `npm_publish_directory: 'packages/auth-client'` (test.yml)

### 消費側リポジトリ

| リポジトリ | 使用コンポーネント |
|-----------|------------------|
| alc-app | StagingFooter, AuthToolbar, VersionBadge, useAuth |
| nuxt-trouble | StagingFooter |
| nuxt-pwa-carins | AuthToolbar, useAuth |
