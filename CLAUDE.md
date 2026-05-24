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

## MCP OAuth Provider

### scope の取扱

| scope | 公開区分 | 取得経路 |
|---|---|---|
| `mcp.read` / `mcp.write` / `offline_access` | **public** (AS metadata の `scopes_supported` で advertise) | DCR + `/mcp/authorize?scope=...`、device flow、pair flow |
| `mcp.admin` | **internal only** (`scopes_supported` に**意図的に出さない**) | `/mcp/elevate` 経由の browser 昇格フローでのみ付与 (#149) |

`auth.ippoan.org/.well-known/oauth-authorization-server` の `scopes_supported` に `mcp.admin` が無いのは仕様。client が `authorize?scope=mcp.admin` を要求できる public scope ではなく、server-side 昇格でだけ付く internal scope のため、advertise しないのが正。`mcp-as-metadata.ts` を編集する時に「`mcp.admin` が漏れている」と勘違いして足さないこと。

### INTERNAL_SHARED_SECRET multi-binding 規約 (#189)

`/mcp/introspect` Mode 2 は **`INTERNAL_SHARED_SECRET` で始まる全 binding** を accept する。consumer ごとに専用 secret を持たせたい場合は `wrangler.toml` に追加 binding を生やす:

```toml
[[env.staging.secrets_store_secrets]]
binding = "INTERNAL_SHARED_SECRET"                    # legacy / shared (cc-relay broker / github-mcp-server-rs / ref-files-worker)
secret_name = "INTERNAL_SHARED_SECRET"                # 2026-05-24: prod/staging 統合 (旧 mcp-internal-shared-secret-{prod,staging})

[[env.staging.secrets_store_secrets]]
binding = "INTERNAL_SHARED_SECRET_CI_DASHBOARD"       # per-consumer
secret_name = "ci-dashboard-internal-shared-secret-staging"
```

introspect handler は `resolveAllSharedSecrets(env)` で `Object.keys(env)` を走査し、prefix match した全 binding の値を constant-time で順次比較する。1 つでも一致すれば 200、全 unmatch なら 401。新規 consumer を増やすときに introspect の **コード変更は不要**、binding と Secrets Store entry の追加だけで済む。
