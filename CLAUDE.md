# auth-worker

Cloudflare Workers ベースの認証サービス + 共有パッケージ。

詳細 (アーキテクチャ・経緯・gotcha) は auth-worker-map skill を参照。

## プロジェクト構成

- **auth-worker**: Cloudflare Workers (Hono) — OAuth フロー、JWT 発行、組織管理
- **packages/auth-client**: npm パッケージ `@ippoan/auth-client` — Nuxt フロントエンド共有コンポーネント

## auth-client 型安全性 (規範)

auth-client は `.vue` ソースファイルをそのまま ship する（ビルドステップなし）。
消費側の `nuxi typecheck` (vue-tsc) がソースを直接型チェックするため、**全ての `.vue` ファイルで strict な型注釈が必要**。

- `fetch().json()` の戻り値には必ず `as Type` を付ける（vue-tsc v5 では `unknown` になる）
- `Array()` リテラルには型注釈を付ける（`const parts: string[] = []`）
- `catch (e)` には `catch (e: unknown)` または `catch (e: any)` を明示

## MCP OAuth Provider (規範)

- **`mcp.admin` は AS metadata の `scopes_supported` に意図的に出さない**（internal only、`/mcp/elevate` の browser 昇格フローでのみ付与 #149）。`mcp-as-metadata.ts` を編集する時に「漏れている」と勘違いして足さないこと。
- **`INTERNAL_SHARED_SECRET` multi-binding**: `/mcp/introspect` は `INTERNAL_SHARED_SECRET` で始まる全 binding を `resolveAllSharedSecrets` で prefix match accept。新規 consumer 追加は binding + Secrets Store entry の追加だけ (introspect コード変更不要)。
