# auth-worker MCP OAuth Provider — Consumer Integration Guide

auth-worker (`auth.ippoan.org`) を **MCP OAuth Provider** として使う consumer 向け統合ガイド。
[issue #130](https://github.com/ippoan/auth-worker/issues/130) の「auth-worker 側で必要なもの」を明文化する。

対象 consumer:

| consumer | mode | repo |
|---|---|---|
| `github-mcp-server-rs` | device flow (CLI) | [ippoan/github-mcp-server-rs](https://github.com/ippoan/github-mcp-server-rs) |
| `cc-relay` broker | device flow (CLI) | [ippoan/cc-relay](https://github.com/ippoan/cc-relay) |
| Claude.ai | auth code + PKCE (browser) | (Anthropic) |

## 1. アーキテクチャ概観

```
┌──────────────────┐  device flow / authcode+PKCE  ┌─────────────────┐
│ consumer (CLI/  │ ─────────────────────────────▶ │ auth-worker     │
│ browser)         │                                │ auth.ippoan.org │
└──────────────────┘                                └────────┬────────┘
        │                                                    │
        │  ① MCP access JWT (aud=github-mcp-server-rs)       │
        │◀───────────────────────────────────────────────────┘
        │
        │  ② POST /mcp/introspect  (Authorization: <INTERNAL_SHARED_SECRET>)
        │     body: { "token": "<JWT>" }
        │  ◀── { active: true, github_login, github_token, ... }
        │
        │  ③ Bearer github_token で api.github.com を直叩き
        ▼
┌──────────────────┐
│ api.github.com   │
└──────────────────┘
```

GitHub OAuth App は auth-worker が保有 (`GITHUB_MCP_CLIENT_ID` / `_SECRET`)。
consumer は GitHub OAuth App を持たない。

## 2. consumer モード選択

### 2.1 Device flow (CLI consumer)

`github-mcp-server-rs` / `cc-relay` broker のような **TTY を持つ binary** 向け。
RFC 8628 Device Authorization Grant。

1. `POST /mcp/device_authorization` (form: `client_id`, optional `scope`)
   → `device_code`, `user_code`, `verification_uri_complete`, `interval`
2. ユーザーが `verification_uri_complete` をブラウザで開いて GitHub OAuth 認可
3. consumer は `POST /mcp/token` を `interval` 秒ごとに polling
   - `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code`, `client_id`
   - `pending` → `authorization_pending`、`approved` → `access_token` (JWT) + `refresh_token`
4. `access_token` を `~/.<consumer>/token` 等に保存 (`token_cache.rs` パターン)
5. broker は `POST /mcp/introspect` で JWT → `github_token` を取得し `api.github.com` を直叩き

### 2.2 Auth Code + PKCE (browser consumer)

Claude.ai / Anthropic web client 向け。RFC 6749 §4.1 + RFC 7636。

1. `POST /mcp/register` (RFC 7591 DCR) → `client_id` を取得 (TTL 90d)
2. `GET /mcp/authorize?response_type=code&client_id=...&redirect_uri=...&code_challenge=...&code_challenge_method=S256`
3. ユーザー GitHub 認可 → `redirect_uri?code=...`
4. `POST /mcp/token` (`grant_type=authorization_code`, `code`, `code_verifier`, `client_id`)
   → `access_token` + `refresh_token`

browser client は `INTERNAL_SHARED_SECRET` を持てないので `/mcp/introspect` は使えない。
MCP relay (`mcp.ippoan.org`) 経由で `Streamable HTTP` で MCP server を叩く設計
(Phase 6/7, [#117](https://github.com/ippoan/auth-worker/issues/117) / [#119](https://github.com/ippoan/auth-worker/issues/119))。

## 3. cc-relay 向けレシピ

### 3.1 client_id 発行

cc-relay broker は **device flow** なので、`client_id` 検証はされない
(`mcp-device-authorization.ts` の comment 参照)。次の 2 択:

- **静的 client_id (推奨)**: `cc-relay` のような固定文字列を ship する。
  KV 登録不要。github-mcp-server-rs と同じ運用。
- **DCR**: `POST /mcp/register` で UUID を発行 (TTL 90d)。インストール毎に
  expire を気にする必要があるので CLI には不向き。

cc-relay は **静的 `client_id = "cc-relay"`** を使うことを推奨。
device flow の実際の認可 gate は `GITHUB_MCP_USER_ALLOWLIST` (JSON array of
github logins) で決まり、`client_id` は通らない。

### 3.2 scope

device_authorization に `scope` を渡すこともできるが、現状の auth-worker は
GitHub OAuth App 側で固定 scope (Issues r/w + metadata r 相当) を要求しており、
`scope` 値は token response に echo されるだけ。cc-relay の broker が Issue
body の CAS + comments の post/list をやる用途なら現行 scope で十分。

### 3.3 INTERNAL_SHARED_SECRET 共有

cc-relay broker は `/mcp/introspect` を叩くため `INTERNAL_SHARED_SECRET` を
保持する必要がある。github-mcp-server-rs と **同じ値** を共有する。
将来 Service Binding 化される (Epic [#91](https://github.com/ippoan/auth-worker/issues/91))。

### 3.4 JWT `aud`

`/mcp/token` が発行する JWT の `aud` は固定 `"github-mcp-server-rs"`。
`/mcp/introspect` も `aud === "github-mcp-server-rs"` を strict 検証する
(`mcp-introspect.ts:31`)。

cc-relay も **同 aud の JWT を introspect する** 形になる。これは consumer
毎に aud を分けない単純化方針 (`aud` はトークンの「種別」ではなく
「auth-worker MCP token」自体を指す identifier として運用)。
将来 aud を consumer 毎に分けたくなったら `/mcp/token` を multi-aud 対応に
拡張する必要がある (現状は単一 aud)。

### 3.5 GITHUB_MCP_USER_ALLOWLIST

device_callback (`mcp-device-callback.ts`) は GitHub OAuth callback 後に
`GITHUB_MCP_USER_ALLOWLIST` (JSON array) で github_login を gate する。
**fail-closed**: JSON 不正 / 配列でない / 文字列以外混在 → deny all。

cc-relay で利用したい github_login がここに含まれていることを確認すること。
`wrangler secret put GITHUB_MCP_USER_ALLOWLIST` で更新。

## 4. Sandbox 到達性問題

### 4.1 症状

Claude Code on Web の sandbox から:

```
$ curl https://auth.ippoan.org/.well-known/oauth-authorization-server
HTTP 403 (proxy block)        # 2026-05-14 確認
```

`auth.ippoan.org` (および `mcp.ippoan.org`) は sandbox の outbound allowlist
に入っていないため device flow を sandbox 内で完結できない。
github-mcp-server-rs / cc-relay broker が Claude Code on Web 上で動く場合に
hit する。

### 4.2 解決策候補

| # | 方針 | 状態 |
|---|---|---|
| A | sandbox allowlist に `auth.ippoan.org` / `mcp.ippoan.org` を追加してもらう | TBD (Anthropic 側) |
| B | host 側で device flow を完了させ、token のみ sandbox にマウント (`~/.<consumer>/token`) | github-mcp-server-rs の現行 workaround |
| C | Phase 7 の WS relay (`mcp.ippoan.org/u/<github_login>/connect`) が sandbox-friendly な経路を提供 | relay 自体に到達性が必要なので A 解決が前提 |

cc-relay も github-mcp-server-rs と同様、当面 **(B) host-side login + token
mount** を前提とする。Phase 7 WS relay は sandbox の outbound 制約が解けた
後に直接利用可能になる。

### 4.3 token cache の永続化

`token_cache.rs` (encrypted local cache) を host 側 (`~/.<consumer>/token`)
に置き、sandbox は read-only mount する。`refresh_token` 期限 (30 日) 内は
host 側で flow を回す必要なし。期限切れ時は host 側でログイン再実行。

## 5. テスト手順 (auth-worker 側)

cc-relay 統合確認用の最小 smoke test:

```bash
# 1. device_authorization
curl -s -X POST https://auth.ippoan.org/mcp/device_authorization \
  -d 'client_id=cc-relay' | jq .

# → user_code / verification_uri_complete を取得 → ブラウザで approve

# 2. polling
curl -s -X POST https://auth.ippoan.org/mcp/token \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  -d "device_code=$DEVICE_CODE" \
  -d 'client_id=cc-relay' | jq .

# 3. introspect (INTERNAL_SHARED_SECRET 必要)
curl -s -X POST https://auth.ippoan.org/mcp/introspect \
  -H "Authorization: $INTERNAL_SHARED_SECRET" \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$ACCESS_TOKEN\"}" | jq .
# → { active: true, github_login, github_token, ... }

# 4. github_token で api.github.com に到達確認
curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/user | jq .login
```

## 6. 関連 issue

- Epic: [#91](https://github.com/ippoan/auth-worker/issues/91)
- Phase 5 (DCR + auth code + PKCE): [#128](https://github.com/ippoan/auth-worker/issues/128)
- Phase 6/7 (MCP relay): [#117](https://github.com/ippoan/auth-worker/issues/117) / [#119](https://github.com/ippoan/auth-worker/issues/119)
- cc-relay 統合 tracking: [#130](https://github.com/ippoan/auth-worker/issues/130)
- cc-relay 側 親 issue: [ippoan/cc-relay#33](https://github.com/ippoan/cc-relay/issues/33)
