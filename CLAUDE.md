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

## ユーザーの権限 (perms claim と X-User-Permissions)

- **ロールの持ち主は alc-auth-worker** (`ALC_AUTH`)。ロール = 権限の集合で、user を返す内部口 (upsert-google / upsert-lineworks / upsert-line / by-line-id) が展開済みの `permissions` を返す (admin は `["*"]`、休暇申請ロールは `["leave.use"]`)。auth-worker はロールを保存しない (Refs ohishi-exp/rust-leave-worker#1)
- ログインの callback が `createAccessToken` で JWT の claim `perms` に写す (空なら key ごと省略。dev token には載らない)。下流へは `alc-proxy.ts` だけが、検証済み JWT の `perms` から `X-User-Permissions` (空白区切り、形に合わない値は捨てる) を作って渡す。admin-proxy / identity-headers には足さない
- `/admin/users` の「休暇申請」トグルは `/api/users/roles` (GET 一覧 / POST 付け外し、admin のみ、tenant は JWT から) → alc-auth-worker の `/internal/tenants/{tenant_id}/...`。Cloud Run への退避は無い。付け外しは次のログインから JWT に効く

## staging だけ me・logout・my-orgs を alc-auth-worker から組む (`ALC_AUTH_SESSION`)

- staging の会社は alc-auth-worker と staging の DB が作るため、Cloud Run staging には無く `/api/auth/me` が 500 になる。`wrangler.toml` の **`[env.staging.vars]` だけ**に `ALC_AUTH_SESSION = "1"` を置き、`lib/alc-session.ts` が me・logout (alc-proxy) と my-orgs (`api-my-orgs.ts`・`top-page.ts`) を alc-auth-worker の `/internal/tenants/{id}` 系から組む。トップレベル (本番) には足さない = 本番は今までどおり Cloud Run
- 分岐は `alc-session.ts` の 1 か所だけ (呼び手に `ALC_AUTH_SESSION` の判定を書かない)。値は検証済み JWT の claims から作る。404 は本文が `tenant_not_found` のときだけ「会社が無い」 (me → 401 / my-orgs → 空)、それ以外は 502。preview override 付きは従来の経路。switch-org は対象外
