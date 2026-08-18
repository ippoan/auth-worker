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

issuer は **`<origin>/oidc`**。既存の MCP surface (issuer = `<origin>`) と同じ origin で
2 つの AS を名乗る形になるので、issuer が別であることが両者を分ける唯一の識別子になる。

| endpoint | 用途 | Access の設定欄 |
|---|---|---|
| `GET /oidc/.well-known/openid-configuration` | discovery | — |
| `GET /oidc/authorize` | 認可。**既存セッションがあれば IdP に飛ばさず即 code** | Auth URL |
| `POST /oidc/token` | code → `id_token` 交換 | Token URL |
| `GET /oidc/.well-known/jwks.json` | 公開鍵配布 (認証なし) | Certs URL |
| `GET /oidc/userinfo` | access_token → identity | — |

私有鍵成分 `d` の除去は `toPublicJwk()` (`src/lib/oidc-signing-key.ts`) の 1 箇所に
閉じてあり、JWKS に出す経路はそこだけを通る。

## 追加ログインがゼロになる仕組み

`/oidc/authorize` は `logi_auth_token` cookie を検証し、**有効ならその場で code を
発行して Access に返す**。外部 IdP へのリダイレクトが一切起きないので、利用者から
見ると Access の画面を素通りする。cookie が無い / 期限切れの時だけ既存の `/login` に
送り、戻り先として同じ authorize URL をそのまま渡す。

そのため `/login` の redirect_uri 許可リスト (KV `origins:<WORKER_ENV>`) に
**auth-worker 自身の origin が入っている必要がある**。`/login` は redirect_uri 省略時に
自分の `/top` へ飛ばす作りなので、この条件は既存の login フローが動いている時点で
満たされている。

`id_token` には `sub` / `email` に加えて `tenant_id` / `role` / `org_slug` を custom
claim として載せる。Access のポリシーで「この組織の admin だけ」といった絞り込みが
できる。

## client (Access) の登録

**DCR ではなく静的設定**にしている。既存 MCP surface の DCR は public client
(`token_endpoint_auth_methods_supported: ["none"]`) 前提で、client_secret を持たない。
Access は client_secret を持つ confidential client であり、しかも「管理画面で 1 回
設定して長期間動かす」種類の client なので動的登録の利点が無い。DCR で発行した
public client を Access に流用すると、secret 無しで token endpoint を叩ける client を
公開することになり逆に危ない。

`ACCESS_OIDC_CLIENTS` に JSON 配列で入れる:

```json
[ { "client_id": "cf-access",
    "client_secret": "<32 byte 以上のランダム>",
    "redirect_uris": ["https://<team>.cloudflareaccess.com/cdn-cgi/access/callback"],
    "name": "cloudflare-access" } ]
```

`redirect_uris` は **完全一致**で照合する (query や path を足した変種は通さない)。
client を足したいときはこの配列に追加するだけで、コード変更は要らない。

### Access 側の設定

Zero Trust → Settings → Authentication → Login methods → Add → **OpenID Connect**:

| 欄 | 値 |
|---|---|
| App ID | `cf-access` (= `client_id`) |
| Client secret | 上の `client_secret` |
| Auth URL | `https://auth.ippoan.org/oidc/authorize` |
| Token URL | `https://auth.ippoan.org/oidc/token` |
| Certs URL | `https://auth.ippoan.org/oidc/.well-known/jwks.json` |

`email` は id_token から自動で取れる。`tenant_id` / `role` をポリシーで使うときは
OIDC Claims に claim 名を足す。

**Access アプリはホスト名ベースで作ること。** Worker-level ポリシーは WebSocket が
403 になるとドキュメントに明記があり、RDP-over-WebSocket が名指しされている。

## セキュリティ上の作り

- **open redirect を作らない** — `client_id` / `redirect_uri` が不正な場合は
  redirect せず 400 を返す (未検証の redirect_uri へ飛ばさない)。
- **authorization code は single-use / TTL 60 秒**。読み出した時点で必ず KV から消す。
- **code は発行先の client にしか渡さない**。`redirect_uri` の再提示も突き合わせる。
- **未登録 client と secret 不一致は同じ応答**にして `client_id` の存在を漏らさない。
- **PKCE (S256)** に対応。Access 側で有効にすれば自動的に検証される。
- `id_token` の寿命は 5 分。refresh token は発行しない (Access は自分の session
  cookie で寿命を管理するので、IdP 側に refresh を持たせる必要が無い)。

## deploy に関する注意

`wrangler.toml` の `[[secrets_store_secrets]]` binding は、**Secrets Store 側に実体が
無いと `wrangler deploy` が失敗する**。auth-worker の deploy が失敗すると Release
Wave 全体が止まるので、順序を必ず守ること:

1. 上記の `secrets-store secret create` で prod / staging 両方の entry を作る
   (`ACCESS_OIDC_SIGNING_KEY` と `ACCESS_OIDC_CLIENTS` の 2 つ)
2. その**後で** `wrangler.toml` に binding を宣言する PR を merge する

このため binding 宣言は本体コードとは別 PR に分けてある。binding が無い間、
`/oidc/*` は 503 を返すだけで既存経路には影響しない。
