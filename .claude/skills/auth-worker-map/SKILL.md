---
name: auth-worker-map
generated-from: auth-worker:d7c1b21f2a130aa0db865218796c5532c068437b
paths: [src/, packages/]
description: ippoan/auth-worker (Cloudflare Workers + Hono の認証サービス) の構造ナビゲーション。OAuth フロー / JWT 発行 / MCP OAuth Provider / 組織管理 / 各 SSO provider (Google/GitHub/LINE WORKS/e-Gov) のハンドラ配置と、wrangler の prod/staging 構成・既知の gotcha を 1 枚にまとめる。auth-worker を触る前に「どのハンドラを見るか」を即断するための地図。トリガー:「auth-worker」「MCP OAuth」「grant-via-oat」「binding_jwt」「device flow」「mcp.admin / elevate」「introspect」「INTERNAL_SHARED_SECRET」「auth-client」「SSO」「pairing」「auth.ippoan.org」等。
---

# auth-worker-map — ippoan/auth-worker 構造ナビゲーション

Cloudflare Workers (Hono) ベースの認証サービス + 共有パッケージ。`src/index.ts` が
各 `src/handlers/*` を直接 import して route 登録する (router モジュールは無い)。

> 細部 (関数シグネチャ・正確な行) は repo 側が正。ここは「どこを見るか」の索引。
> frontmatter の `generated-from` が現在の repo tree-sha とズレたら
> session-start-skill-coverage hook が「この skill は code に追従してない」と警告する
> → その時は再生成して tree-sha を更新する。

## 区画 (handler グループ)

| 区画 | handler | 役割 |
|---|---|---|
| **MCP OAuth Provider** (主役・26 handler) | `src/handlers/mcp-*` | DCR / authorize / token / introspect / device flow / pairing / elevate。下表参照 |
| **SSO provider (login)** | `google-*` `ghapi-*` `lineworks-*` `egov-*` `woff-auth` `github-webhook` | 各 IdP の redirect/callback。`ghapi-*` = Google Health API OAuth pass-through (`/oauth/ghapi/*`、HealthConnectReaderWorker 連携用) |
| **組織管理 (admin)** | `admin-*` | config / users / requests / rich-menu / sso / notify (管理者向け) |
| **API (dashboard)** | `api-*` | my-orgs / switch-org / users / sso / rich-menu / access-requests / bot-config / branch-protection。**`api-my-orgs` / `api-switch-org` は rust-alc-api への前段 proxy 役**: Bearer JWT を `verifiedIdentityHeaders` (`src/lib/identity-headers.ts`) で検証し `X-Tenant-ID` + `X-User-ID/Email/Role` を注入してから `ALC_API_ORIGIN` に転送 (rust-alc-api#434、dumb backend 対応) |
| **alc-proxy** (data-proxy) | `src/handlers/alc-proxy.ts` (`/alc-proxy/*`) | consumer worker が service binding で forward する汎用 data-proxy (rust-alc-api#434 step 3 方式 B)。**① consumer proof**: `X-Alc-Proxy-Secret` を `INTERNAL_SHARED_SECRET*` と constant-time 比較 (fail-closed、未 bind/不一致は 401/503) → ② browser JWT ローカル検証 + ACL (`X-Alc-Proxy-Origin`) → ③ `ALC_API_PROXY_SA_KEY` で OIDC mint → ④ `X-Tenant-ID`/`X-User-*` 注入で `ALC_API_ORIGIN` 転送。**①が無いと公開 route なので「正当 JWT + 詐称 origin」で `checkAppTenant` を回避できる** (handoff の MEDIUM 修正) |
| **alc-internal-proxy** (内部 ingest proxy) | `src/handlers/alc-internal-proxy.ts` (`/alc-internal-proxy/*`) | **browser JWT を持たない server-to-server 内部呼び出し**向け (rust-alc-api#434 step 3d caller #4 = email-receiver)。① `X-Alc-Proxy-Secret` consumer proof → ② **path allowlist** (rust の `require_internal_shared_secret` ingest 経路 = `/api/dtako/tickets` 系のみ。data 経路を通すと shared secret だけで X-Tenant-ID 詐称 = #434 再現になるため厳格に列挙) → ③ `X-Tenant-ID` 必須 → ④ OIDC mint → ⑤ `Authorization: Bearer <OIDC>` + `X-Internal-Shared-Secret` (base、rust app 認証) + `X-Tenant-ID` で `ALC_API_ORIGIN` 転送。`/alc-proxy` (browser JWT データ経路) との違いは「JWT/ACL 無し・allowlist で ingest 限定・shared secret pass-through」 |
| **login / join / 雑** | `login-page` `login-api` `join-*` `logout` `top-page` `redirect` | ブラウザ login フロー |
| **device token** (無人 box / キオスク) | `device` `device-pair` + `src/lib/device{,-pair}.ts` | smb-watch 等の無人 box / alc-app キオスク向け。pairing (`/device/pair`・headless `/device/pair/start·approve·token`・server-to-server `/device/pair-internal`) で `device_id`+`device_secret` 発行 → `/device/token` で短命 device JWT (HS256・`JWT_SECRET` 共有・`/auth/introspect` 検証可) を mint。role は allowlist (`device-uploader` = carins upload / `device-kiosk` = alc-app、Refs rust-alc-api#434)。`/device/revoke` で失効。`/device/pair-internal` は `X-Internal-Shared-Secret` (`INTERNAL_SHARED_SECRET*`) 認証の server-to-server mint (AlcoholChecker provisioning / rust-alc-api#495 kiosk 端末 re-pair)。`replace_label: true` で同一 (tenant_id, label) の旧 credential を KV 二次索引 (`device-label:<tenant>:<label>`) 経由で revoke してから再発行 (dormant credential 対策) |
| **health** | `health` `health-oauth` | ヘルスチェック (health-oauth は Bearer JWT 要、Refs auth-worker#209) |
| **Durable Objects** | `src/durable_objects/{mcp-session-do,lineworks-webhook-do}.ts` | MCP session 状態 / LINE WORKS webhook |

### MCP OAuth Provider の handler (mcp-*)

| 機能 | handler |
|---|---|
| AS metadata / resource metadata | `mcp-as-metadata` `mcp-resource-metadata` |
| DCR (動的 client 登録) | `mcp-register` `mcp-pair-register-via-github-comment` |
| authorize / token / introspect / revoke | `mcp-authorize` `mcp-token` `mcp-introspect` `mcp-revoke` |
| device flow | `mcp-device-authorization` `mcp-device-page` `mcp-device-verify` `mcp-device-proceed` `mcp-device-callback` |
| **pairing** (CCoW silent bootstrap) | `mcp-pair-new` `mcp-pair-grant` `mcp-pair-grant-via-oat` `mcp-pair-grant-via-github` `mcp-pair-claim` `mcp-pair-callback` `mcp-auth-callback` |
| **elevate** (mcp.admin 昇格) | `mcp-elevate` `mcp-admin-exec` |
| jwt pickup / relay | `mcp-jwt-pickup` `mcp-relay-bridge` `mcp-relay-connect` |
| tools | `mcp-tools` |

## packages/

| package | 中身 |
|---|---|
| `auth-client` | `@ippoan/auth-client` — Nuxt 共有 Vue コンポーネント (StagingFooter / AuthToolbar / VersionBadge / useAuth)。**`.vue` をそのまま ship** (ビルド無し) → 消費側 vue-tsc が直接型チェック = 全 `.vue` で strict 型注釈必須 |
| `auth-client-worker` | Cloudflare Worker consumer 向け (ci-dashboard 等が使う `@ippoan/auth-client-worker`) |
| `nuxt-dev-preset` / `test-utils` | dev preset / テスト補助 |

## wrangler.toml の構成と gotcha (重要)

- **top-level = prod (`auth-worker`, auth.ippoan.org) / `[env.staging]` = staging (`auth-worker-staging`, auth-staging.ippoan.org)**。MCP スタックは **staging を実運用として扱う (staging=prod)**。
- **`MCP_OAUTH_KV` は prod に意図的に bind しない (guardrail)**。prod の `/mcp/pair/grant-via-oat` を 503 で無効化し OAT→JWT mint を staging 経由に限定する設計。「欠落」と勘違いして再追加しない (Refs auth-worker#241/#242/#243)。`AUTH_CONFIG` は両 env で同 id 共有。
- **`mcp.admin` は AS metadata の `scopes_supported` に出さない** (internal only、`/mcp/elevate` の browser 昇格でのみ付与)。漏れと勘違いして足さない。
- **`INTERNAL_SHARED_SECRET` multi-binding**: `/mcp/introspect` は `INTERNAL_SHARED_SECRET` で始まる全 binding を `resolveAllSharedSecrets` で prefix match accept。新 consumer 追加は binding + Secrets Store entry だけ (コード変更不要)。
- **`/api/my-orgs` / `/api/switch-org` で raw Bearer を rust-alc-api に素通ししない** (rust-alc-api#434)。rust-alc-api 側は `require_tenant_header` (dumb backend) で **Bearer を読まず X-Tenant-ID + X-User-ID/Email/Role を要求**するため、素通しすると 401 になる (= org 一覧/切替が無言で空になる)。auth-worker が `verifiedIdentityHeaders` で JWT を検証して 4 ヘッダを注入する。JWT には `tenant_id`(UUID) しか無いので tenant 名/slug は rust-alc-api lookup で取る (= この pass-through は必須、auth-worker → rust-alc-api の一方向)。

## CCoW から見た auth-worker

- CCoW container の OAT (`/home/claude/.claude/remote/.oauth_token`) → `POST {auth}/mcp/pair/grant-via-oat` で `binding_jwt` を mint (install.sh の silent bootstrap、`secret-inject` skill も同経路)。
- consumer (alc-app / nuxt-trouble / nuxt-pwa-carins) は `@ippoan/auth-client` を使う。
- **`@ippoan/auth-client/server`** (`packages/auth-client/src/server/`) — Nitro server route 向け
  helper (`.mjs`+`.d.mts`)。`requireAuth` (introspect ガード) / `createApiProxyHandler` (署名なし
  decode で X-Tenant-ID だけ載せる旧 proxy) / **`createIdentityProxyHandler`** (introspect 検証 →
  `X-Tenant-ID` + `X-User-ID/Email/Role` 注入 → backend 転送。rust-alc-api#434 step 2、AuthUser
  復元対応。`introspectFetch` に CF service binding を渡せば Worker→Worker in-process。**方式 A**:
  consumer が自前で introspect + OIDC mint) / **`createAuthWorkerProxyHandler`** (rust-alc-api#434
  step 3 **方式 B**: consumer は `X-Alc-Proxy-Secret` (=`INTERNAL_SHARED_SECRET`、consumer proof) +
  `X-Alc-Proxy-Origin` + browser JWT を載せて service binding で auth-worker `/alc-proxy/*` に
  thin-forward。introspect / OIDC mint / SA key は auth-worker 側に集約。pure header builder は
  `buildAlcProxyHeaders` (proxyCore.mjs))。
  pure core は `introspectCore.mjs` / `proxyCore.mjs` (`buildIdentityHeaders` 等、Vitest で test)。
  **`oidc.mjs` の `mintGoogleIdToken`** (rust-alc-api#434 step 3) — `run.invoker` SA key で
  Google OIDC ID token を mint (jwt-bearer assertion → token endpoint で交換、audience 単位
  cache)。`createIdentityProxyHandler` の `oidcServiceAccountKey` option を渡すと
  `Authorization: Bearer <id_token>` を付けて Cloud Run IAM lockdown 下の rust-alc-api に到達
  (未設定なら非破壊・無効)。`./server` の named export。

## CI / publish

- `test.yml` → `ci-workflows/frontend-ci.yml`。`npm_publish_directory: 'packages/auth-client,packages/auth-client-worker'` で 2 package を 1 CI で publish (dev tag = `0.0.<PR>-dev.<SHA>`、release = tag 共通)。
- branch protection preset: `ippoan-go-default` 等 (auth-worker が presets を保持)。

## 関連

- `ippoan-infra-map` — CCoW 基盤 5 repo の地図 (auth-worker はそこに出てこない consumer 群の認証元)
- `secret-inject` — OAT→binding_jwt→secret 投入 (auth-worker の grant-via-oat を使う)
- `cross-repo-symbol-index` — この per-repo map skill の運用方針 (generated-from 鮮度 hook)
