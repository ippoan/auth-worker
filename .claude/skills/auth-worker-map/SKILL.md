---
name: auth-worker-map
generated-from: auth-worker:977c813e1342e795d86e7dc51af5cb2578b462ac
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
| **API (dashboard)** | `api-*` | my-orgs / switch-org / users / sso / rich-menu / access-requests / bot-config / branch-protection |
| **login / join / 雑** | `login-page` `login-api` `join-*` `logout` `top-page` `redirect` | ブラウザ login フロー |
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

## CCoW から見た auth-worker

- CCoW container の OAT (`/home/claude/.claude/remote/.oauth_token`) → `POST {auth}/mcp/pair/grant-via-oat` で `binding_jwt` を mint (install.sh の silent bootstrap、`secret-inject` skill も同経路)。
- consumer (alc-app / nuxt-trouble / nuxt-pwa-carins) は `@ippoan/auth-client` を使う。

## CI / publish

- `test.yml` → `ci-workflows/frontend-ci.yml`。`npm_publish_directory: 'packages/auth-client,packages/auth-client-worker'` で 2 package を 1 CI で publish (dev tag = `0.0.<PR>-dev.<SHA>`、release = tag 共通)。
- branch protection preset: `ippoan-go-default` 等 (auth-worker が presets を保持)。

## 関連

- `ippoan-infra-map` — CCoW 基盤 5 repo の地図 (auth-worker はそこに出てこない consumer 群の認証元)
- `secret-inject` — OAT→binding_jwt→secret 投入 (auth-worker の grant-via-oat を使う)
- `cross-repo-symbol-index` — この per-repo map skill の運用方針 (generated-from 鮮度 hook)
