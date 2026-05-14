# auth-worker

Cloudflare Worker による共有認証ゲートウェイ。
nuxt-pwa-carins / nuxt-dtako-logs のログイン画面・JWT 発行を担当。

## 認証フロー

```
ブラウザ → auth-worker (GET /login)
         → ID/PW or Google OAuth
         → AuthService RPC (cf-grpc-proxy → rust-logi)
         → JWT 発行
         → redirect_uri#token=...&org_id=...&expires_at=...
```

## エンドポイント

| Path | Method | 説明 |
|------|--------|------|
| `/login` | GET | ログイン画面 (HTML) |
| `/auth/login` | POST | ID/PW ログイン → JWT → リダイレクト |
| `/oauth/google/redirect` | GET | Google OAuth 開始 |
| `/oauth/google/callback` | GET | Google OAuth コールバック → JWT → リダイレクト |

## Service Binding

- `GRPC_PROXY` → `cf-grpc-proxy` (gRPC-Web プロキシ経由で rust-logi に接続)

## 環境変数

| 変数 | 説明 |
|------|------|
| `AUTH_WORKER_ORIGIN` | auth-worker 自身の URL |
| `ALLOWED_REDIRECT_ORIGINS` | リダイレクト許可オリジン (カンマ区切り) |

## Secrets (`wrangler secret put`)

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `OAUTH_STATE_SECRET`

## デプロイ

```bash
npx wrangler deploy
```

## MCP OAuth Provider

auth-worker は GitHub OAuth を delegation する **MCP OAuth Provider** でもある
(epic [#91](https://github.com/ippoan/auth-worker/issues/91))。
consumer (`github-mcp-server-rs`, `cc-relay` broker, Claude.ai) からの統合
手順は [`docs/consumer-integration.md`](docs/consumer-integration.md) を参照。
