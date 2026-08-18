# auth-worker を Cloudflare Access の generic OIDC プロバイダにする

社内サービスを公開ホスト名に出して Cloudflare Access で守るとき、Access の IdP を
Google 等の外部にすると利用者は「触ったことのない別の認証系」でログインすることに
なる。auth-worker 自身を Access の IdP にすれば、Access のリダイレクトは既存の
`logi_auth_token` セッションで無言に通り、**追加ログインがゼロ**になる。

RDP 中継 (`rdp.<domain>`) が最初の利用者だが、**この surface は RDP 専用ではない**。
一度作れば以後どの社内サービスも「Access の後ろ + 自社 identity + 追加ログインなし」で
置ける。

## 既存経路との関係 (重要)

| | 既存 (`/mcp/*`、`logi_auth_token`) | 新設 (`/oidc/*`) |
|---|---|---|
| 署名 | HS256 (共有秘密) | **ES256 (非対称)** |
| 鍵 | `JWT_SECRET` / `MCP_JWT_SECRET` | `ACCESS_OIDC_SIGNING_KEY` |
| 検証側 | rust-alc-api / MCP consumer (秘密を共有) | Cloudflare Access (JWKS で公開鍵検証) |

**既存経路には一切触っていない。** Access surface は「足しただけ」で、HS256 の
トークン形式・鍵・endpoint はすべて不変。Access が id_token を JWKS で検証する
以上、共有秘密の対称署名は原理的に使えないため、ここだけ非対称鍵を新設している。

`ACCESS_OIDC_SIGNING_KEY` が未 bind でも `/oidc/*` が 503 を返すだけで、
rust-alc-api / dtako / kyuyo-mcp を含む既存 consumer には影響しない。

## 鍵の形式とローテーション

Secrets Store の 1 entry に **私有 JWK (ES256 / P-256) の JSON 配列** を入れる。

```json
[ {"kty":"EC","crv":"P-256","x":"…","y":"…","d":"…"},   // 先頭 = 現用 (署名に使う)
  {"kty":"EC","crv":"P-256","x":"…","y":"…","d":"…"} ]  // 以降 = JWKS に出すだけの旧鍵
```

`kid` は RFC 7638 の JWK Thumbprint を**値から導出**する (人手で採番しない)。
鍵を差し替えれば kid も自動で変わるので取り違えが起きない。

### 生成

```bash
node scripts/gen-oidc-signing-key.mjs > /tmp/k.json
```

投入 (値が shell 履歴やプロセス一覧に残らないよう file 経由で渡す):

```bash
npx wrangler secrets-store secret create bd7bc91a3e5f4111add4acf6cb4b8733 --name ACCESS_OIDC_SIGNING_KEY --scopes workers --value "$(cat /tmp/k.json)"
```

```bash
shred -u /tmp/k.json
```

staging は `--name ACCESS_OIDC_SIGNING_KEY_STAGING` で **別 entry** にする。
issuer が環境ごとに違う以上、staging の鍵で署名された id_token が prod の JWKS で
検証できてしまう状態を作らないため (`MCP_JWT_SECRET` のような同 entry 共有はしない)。

### ローテーション (無停止 2 段)

1. 現在値を取得し、新鍵を**先頭に**挿して更新 → deploy
   ```bash
   node scripts/gen-oidc-signing-key.mjs --rotate /tmp/current.json > /tmp/next.json
   ```
   JWKS には新旧**両方**の公開鍵が出るので、切り替えの瞬間に Access 側の検証が
   落ちる窓が生まれない。
2. 旧 id_token の寿命を過ぎたら、末尾の旧鍵を削って更新 → deploy。

鍵の parse は **fail-closed** (配列に 1 つでも壊れた要素があれば全体を拒否)。
壊れた鍵を黙って読み飛ばすと「JWKS には出ているのに検証が通らない」という最も
追いにくい形の障害になるため。

## endpoint

| endpoint | 用途 |
|---|---|
| `GET /oidc/.well-known/jwks.json` | 公開鍵配布。Access IdP 設定の **Certs URL**。公開 (認証なし) |

私有鍵成分 `d` の除去は `toPublicJwk()` (`src/lib/oidc-signing-key.ts`) の 1 箇所に
閉じてあり、JWKS に出す経路はそこだけを通る。

## deploy に関する注意

`wrangler.toml` の `[[secrets_store_secrets]]` binding は、**Secrets Store 側に実体が
無いと `wrangler deploy` が失敗する**。auth-worker の deploy が失敗すると Release
Wave 全体が止まるので、順序を必ず守ること:

1. 上記の `secrets-store secret create` で prod / staging 両方の entry を作る
2. その**後で** `wrangler.toml` に binding を宣言する PR を merge する

このため binding 宣言は本体コードとは別 PR に分けてある。
