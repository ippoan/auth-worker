---
name: auth-worker-map
generated-from: auth-worker:7b43c7d05e5358a33e1380a5e2946a7415455a3c
paths: [src/, packages/]
description: ippoan/auth-worker (Cloudflare Workers + Hono の認証サービス) の構造ナビゲーション。OAuth フロー / JWT 発行 / MCP OAuth Provider / 組織管理 / 各 SSO provider (Google/GitHub/LINE WORKS/e-Gov) のハンドラ配置と、wrangler の prod/staging 構成・既知の gotcha を 1 枚にまとめる。auth-worker を触る前に「どのハンドラを見るか」を即断するための地図。トリガー:「auth-worker」「MCP OAuth」「grant-via-oat」「binding_jwt」「device flow」「mcp.admin / elevate」「introspect」「INTERNAL_SHARED_SECRET」「auth-client」「SSO」「pairing」「auth.ippoan.org」「Cloudflare Access」「generic OIDC」「/oidc」「id_token」「ES256」「ACCESS_OIDC_SIGNING_KEY」「ACCESS_OIDC_CLIENTS」等。
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
| **backend の振り分け表** (domain worker への段階移行) | `src/lib/alc-backend-route.ts` | rust-alc-api の口を、Cloud Run でなく domain 別の Worker (Service Binding) へ流すための表 `ALC_BINDING_ROUTES` と判定 `resolveAlcBinding(backendPath, env, proxy)`。行は「一致の種別 (`prefix` / `exact`)・path・binding・転送先のダミーの host・引いてよい proxy (`browser` = alc-proxy / `internal` = alc-internal-proxy / `device` = device-data-proxy)」。**行に一致し、その proxy が行に入っていて、binding が env に定義されているときだけ**転送先を返す (どれかが欠ければ `null` = 従来どおり Cloud Run。method は見ない)。行: `/api/vein/` (prefix。browser・device → `ALC_VEIN`) / `/api/upload` (**完全一致** — 下位の path は別の口。browser・internal → `ALC_DTAKO`) / `/api/split-csv/` (prefix。browser → `ALC_DTAKO`) / `/api/split-csv-all` (完全一致。browser → `ALC_DTAKO`)。各 proxy は**認証・ACL・ヘッダの付け直しを終えた後**に表を引き、binding 経路では Cloud Run 用の token を作らない (`forwardViaAlcBinding`。`redirect: "manual"`)。alc-internal-proxy は shared-secret クラスの path だけ引き、binding へ渡すヘッダは `X-Tenant-ID` と `Content-Type` だけ。**`ALC_VEIN`・`ALC_DTAKO` の binding は `wrangler.toml` のトップレベル (本番) にだけ在る** (`[[services]]`。`env.staging` には bind しないので、staging は表の行に一致しても Cloud Run のまま)。`src/lib/alc-backend-route.ts` は coverage 100% (branches 込み) の登録対象。テストは `test/handlers/alc-binding-route.test.ts` |
| **login / join / 雑** | `login-page` `login-api` `join-*` `logout` `top-page` `redirect` | ブラウザ login フロー。`top-page` は session JWT 検証に加えて **dangling tenant 検知**: rust `/api/my-orgs` (verifiedIdentityHeaders 前段 proxy) が 0 件なら **`/logout` へ 302** (tenants 行欠落セッションの早期検出、2026-07-13 本番で hub ingest FK 500 の形で顕在化)。**`/login` へ飛ばすと「同 account→同 tenant_id→同じ空 my-orgs」で login 無限ループになる** (初版のバグ、本番で発生) ため、session を破棄して login で止まる `/logout` にする。判定不能 (rust 障害・claim 不足・応答形不正) は fail-open、`?woff=1` は gate 対象外。**`/logout` は cookie を捨てたあと Cloudflare Access のログアウトへ chain する** (Refs #477、`src/lib/access-logout.ts`): `https://<ACCESS_TEAM_DOMAIN>/cdn-cgi/access/logout?returnTo=<元の遷移先>`。cookie だけ消すと Access のセッション (24h) が生き残り、守られたアプリに戻ると「ログアウトしたのに Access だけ入ったまま」になる。**順序は auth-worker → Access で固定** (逆だと Access からの戻り先を `/logout` に向けることになる)。**`returnTo` は Access が知っているホストにしか戻せず、それ以外は 400** (2026-08-26 実測) なので、戻り先が共有 cookie の届く親ドメイン配下の https URL のときだけ chain し、`ACCESS_TEAM_DOMAIN` 未設定なら従来どおり素通しする。**★ さらに「直前にも /logout に来たか」のマーカー cookie (`access_logout_chained`, 60秒) が生きている間は chain しない** — auth-client の `initAuthSession` は `?lw_callback=1` で戻ったのにセッションを復元できないと`redirectToLogin({reauth:true})` = `/logout` を叩くので、無条件に Access を切ると**1 周ごとに Cloudflare Access を往復する無限ループ**になる (本番で発生) |
| **device token** (無人 box / キオスク) | `device` `device-pair` + `src/lib/device{,-pair}.ts` | smb-watch 等の無人 box / alc-app キオスク向け。pairing (`/device/pair`・headless `/device/pair/start·approve·token`・server-to-server `/device/pair-internal`) で `device_id`+`device_secret` 発行 → `/device/token` で短命 device JWT (HS256・`JWT_SECRET` 共有・`/auth/introspect` 検証可) を mint。role は allowlist (`device-uploader` = carins upload / `device-kiosk` = alc-app、Refs rust-alc-api#434)。`/device/revoke` で失効。`/device/pair-internal` は `X-Internal-Shared-Secret` (`INTERNAL_SHARED_SECRET*`) 認証の server-to-server mint (AlcoholChecker provisioning / rust-alc-api#495 kiosk 端末 re-pair)。`replace_label: true` で同一 (tenant_id, label) の旧 credential を KV 二次索引 (`device-label:<tenant>:<label>`) 経由で revoke してから再発行 (dormant credential 対策)。OTA 後のバージョン再照会は queryVersion 成功まで期限内リトライ (再起動でゾンビ WS が /connected に残り初回照会がタイムアウトするため #389)。**毒 cookie 自動破棄 (#387)**: /top と /device/setup は「cookie 有り + 検証全滅」応答に `clearAuthCookieVariants` (Domain 付き/host-only 両方の Max-Age=0) を付けて自動回復させる。/top は `getAuthCookies` で同名 cookie 全候補を verify (host-only と Domain 付き併存の shadowing 耐性)。staging↔prod は同じ `logi_auth_token`/Domain=.ippoan.org を共有するため env claim 不一致の毒 cookie が発生し得る。CoreS3 / AtomS3 印刷ブリッジの USB provisioning は `device-setup` — **機種 (kind) 分離** (ippoan/alc-app-s3#38): `DEVICE_KINDS` テーブル (cores3 = `device-hub` / atoms3-print = `device-print`) が role・OTA firmware URL・manifest を 1:1 に束ね、pair は body.kind で role を決定、list は両 role を kind 付きで返し (一覧の各行に「再登録」ボタン — その行の label/kind のまま WebSerial provisioning を再実行。Web インストーラーの再フラッシュは NVS ごと消して credential が飛ぶため、その復旧導線)、OTA/version の gate (`managedDeviceKind`) と `latest?kind=` の最新版照会も機種別。developer アカウント (`DEVELOPER_EMAILS`) には CoreS3 の OTA URL を dev ビルド (mem-hud、`devAppUrl` = alc-hub-cores3-dev-app.bin) へ切り替える checkbox を表示 — 開発機の /device/setup 更新でメモリ HUD が消える問題への対処 (ippoan/alc-app-s3#44。URL 欄は誰でも自由編集可のため UI 出し分けのみ、server 側 enforcement 無し)。**p4-gw (Unit PoE-P4 GW、ippoan/alc-gw-p4#15)**: cf-alc-recorder への WS常設接続 (recorder_link) と OTA (esp_https_ota) を実装済みなので `DEVICE_KINDS["p4-gw"]` の appUrl/manifestUrl は GitHub Releases (alc-gw-p4/.github/workflows/release.yml、Cloudflare Pages 配布の cores3/atoms3-print とは別経路) の固定URL — 安定版は `releases/latest`、dev版は main push の度に上書きされる `releases/download/dev`。CoreS3と同じ developer 限定 dev-build checkbox (`dev-build-p4-gw`) も追加済み — 詳細は従来どおり (`GET /device/setup` = WebSerial ページ / `POST /device/setup/pair` = cookie session mint / `GET /device/setup/list` = テナントの登録済み一覧、`listDeviceRecordsByTenant` で `device:` prefix 全走査 + tenant filter / **OTA**: `POST /device/setup/ota` = 遠隔更新トリガ・`GET /device/setup/ota/:id` = 進捗ポーリング。`ALC_RECORDER` service binding 経由で cf-alc-recorder の下り command API (`Authorization: <INTERNAL_SHARED_SECRET>`) に `{action:"ota",url}` を push、進捗は device が返す command_result を透過。device_id は tenant 所属を verify してから叩く。**GW**: `POST /device/setup/gw` = Windows GW (alc-gw) ハブ URL の遠隔設定 (`{action:"gw_url",url}` — url は ws(s):// のみ) / url 省略で接続状態照会 (`{action:"gw_status"}` → `{connected,url}`)。同じ command 経路・結果は `/device/setup/ota/:id` 透過で取得。UI は一覧行の「GW設定 / GW確認」ボタン (CoreS3 かつ WS 接続中のみ、alc-app-s3#81 の firmware 側 action と対))。**拠点デバイス相互認証 (Refs #406、2026-07-19)**: `role=device-gateway` (alc-gw / P4) を追加し、`DeviceRecord.site_id` で hub/gateway の 1:1 束縛を表す。**site_id の既定は hub 自身の `device_id`** (`createDeviceCredential` が role=device-hub かつ siteId 省略時に自動付与、人手採番不要 — hub 交換で device_id が変われば site_id も変わり GW 側の再ポイントで追従する設計、alc-app に拠点レジストリができるまでの暫定)。`POST /device/hub-token` (`device_id`+`device_secret`+`nonce` → TTL60s・`aud:"hub"` の JWT mint、role が `HUB_TOKEN_ELIGIBLE_ROLES` かつ site_id 設定済みのみ) / `POST /device/introspect` (device credential 認証 + 他デバイスの hub token を検証、ESP32 側に JWKS 検証を実装させないための REST 代替) / `POST /device/site/backfill` (shared-secret、server-to-server で既存 hub に site_id 事後付与) / `POST /device/setup/site` (cookie session、`/device/setup` 一覧の「設定」ボタンから — site_id 省略時は device_id 自身を既定にする、`managedDeviceKind` で tenant 越境を防ぐ)。JWKS は意図的に新設していない (検証は introspection のみで完結させる設計、本リポジトリに非対称鍵基盤が無いこととも整合)。 |
| **印刷ブリッジ テスト** | `print-test` | AtomS3 印刷ブリッジ (ippoan/alc-app-s3#38) の検証支援。`GET /print/test.pdf` = 生成時刻入りテスト PDF (**公開・認証無し** — デバイスの HTTP GET は認証ヘッダを付けないため。PDF は xref オフセットを計算した正規構造で、プリンターの PDF ダイレクトプリント検証も兼ねる #37)。`GET /device/print-test` = login-gated WebSerial ページ (device-setup と同作法): PING 準備ハンドシェイク → `PRINTER ADDR` → `PRINT <PDF url>` を注入し `EVT PRINT_*` の進捗/結果を表示 |
| **Cloudflare Access 向け OIDC surface** | `src/handlers/oidc-*` (`/oidc/*`) | Access の generic OIDC IdP になる (issuer = `<origin>/oidc`)。**既存セッションで無言に通すのが目的** — 下表参照。MCP surface (`/mcp/*`) とは issuer も鍵も client 種別も別 |
| **health** | `health` `health-oauth` | ヘルスチェック (health-oauth は Bearer JWT 要、Refs auth-worker#209) |
| **Durable Objects** | `src/durable_objects/{mcp-session-do,lineworks-webhook-do}.ts` | MCP session 状態 / LINE WORKS webhook |

### MCP OAuth Provider の handler (mcp-*)

| 機能 | handler |
|---|---|
| AS metadata / resource metadata | `mcp-as-metadata` `mcp-resource-metadata` |
| DCR (動的 client 登録) | `mcp-register` `mcp-pair-register-via-github-comment` |
| authorize / token / introspect / revoke | `mcp-authorize` `mcp-token` `mcp-introspect` `mcp-revoke` |
| **Google IdP surface** (issue #438) | path surface `/mcp/google` — `POST /mcp/google` = `mcp-tools` と同一 handler (401 の WWW-Authenticate だけ surface 専用 PRM `/.well-known/oauth-protected-resource/mcp/google` を指す)、`GET /mcp/google/authorize` = `mcp-authorize` に `idpDefault:"google"`、AS metadata は `/.well-known/oauth-authorization-server/mcp/google` 等 4 alias (issuer=`<origin>/mcp/google`)。**claude.ai の custom connector は `/mcp/authorize` に RFC 8707 `resource` を送らない** (実ログ確認) ため resource origin ベースの `MCP_RESOURCE_GOOGLE_ORIGINS` では IdP を切り替えられない — dev-login 用 connector はこの surface の URL (`https://auth.ippoan.org/mcp/google`) を直接入力させる。既定 surface (`/mcp/authorize`・`/mcp/tools`) は GitHub 既定のまま |
| device flow | `mcp-device-authorization` `mcp-device-page` `mcp-device-verify` `mcp-device-proceed` `mcp-device-callback` |
| **pairing** (CCoW silent bootstrap) | `mcp-pair-new` `mcp-pair-grant` `mcp-pair-grant-via-oat` `mcp-pair-grant-via-github` `mcp-pair-claim` `mcp-pair-callback` `mcp-auth-callback` |
| **elevate** (mcp.admin 昇格) | `mcp-elevate` `mcp-admin-exec` |
| jwt pickup / relay | `mcp-jwt-pickup` `mcp-relay-bridge` `mcp-relay-connect` |
| tools | `mcp-tools` |
| **dev-login** (issue #423/#424、localhost 検証用 dev JWT) | `mcp-tools` の `issue_dev_token`/`issue_dev_login_url` tool (`src/lib/dev-login.ts`) + `dev-login-token` (`POST /dev-login/token`、code→JWT 交換) |

## packages/

| package | 中身 |
|---|---|
| `auth-client` | `@ippoan/auth-client` — Nuxt 共有 Vue コンポーネント (StagingFooter / AuthToolbar / VersionBadge / useAuth)。**`.vue` をそのまま ship** (ビルド無し) → 消費側 vue-tsc が直接型チェック = 全 `.vue` で strict 型注釈必須 |
| `auth-client-worker` | Cloudflare Worker consumer 向け (ci-dashboard 等が使う `@ippoan/auth-client-worker`) |
| `nuxt-dev-preset` / `test-utils` | dev preset / テスト補助 |

## wrangler.toml の構成と gotcha (重要)

- **top-level = prod (`auth-worker`, auth.ippoan.org) / `[env.staging]` = staging (`auth-worker-staging`, auth-staging.ippoan.org)**。MCP スタックは **staging を実運用として扱う (staging=prod)**。
- **`MCP_OAUTH_KV` は prod にも bind 済み (issue #432 で解禁)**。旧 guardrail (prod 非 bind で grant-via-oat を 503 に落とす、auth-worker#241/#242/#243) は、headless grant 3 経路 (grant-via-oat / grant-via-github / register-via-github-comment) 共通の kill switch `MCP_HEADLESS_GRANT_ENABLED` (`"1"` の時のみ有効) に置き換わった。prod KV は staging とは別 namespace (staging データを持ち込まない)。`AUTH_CONFIG` は両 env で同 id 共有。
- **`MCP_RESOURCE_GOOGLE_ORIGINS` に `https://mcp.ippoan.org` (relay origin) を入れない** (issue #438 の教訓)。resource を送る既存 GitHub 系 consumer が Google に飛んで壊れる。この env は kyuyo-mcp 型 (別 RS が resource を明示送信する構成) 専用で、claude.ai 直結 connector の IdP 切替には効かない (resource 未送信のため) — そちらは `/mcp/google` surface を使う。
- **`mcp.admin` は AS metadata の `scopes_supported` に出さない** (internal only、`/mcp/elevate` の browser 昇格でのみ付与)。漏れと勘違いして足さない。
- **`INTERNAL_SHARED_SECRET` multi-binding**: `/mcp/introspect` は `INTERNAL_SHARED_SECRET` で始まる全 binding を `resolveAllSharedSecrets` で prefix match accept。新 consumer 追加は binding + Secrets Store entry だけ (コード変更不要)。
- **`/api/my-orgs` / `/api/switch-org` で raw Bearer を rust-alc-api に素通ししない** (rust-alc-api#434)。rust-alc-api 側は `require_tenant_header` (dumb backend) で **Bearer を読まず X-Tenant-ID + X-User-ID/Email/Role を要求**するため、素通しすると 401 になる (= org 一覧/切替が無言で空になる)。auth-worker が `verifiedIdentityHeaders` で JWT を検証して 4 ヘッダを注入する。JWT には `tenant_id`(UUID) しか無いので tenant 名/slug は rust-alc-api lookup で取る (= この pass-through は必須、auth-worker → rust-alc-api の一方向)。
- **dev-login (issue #423/#424) は `google_sub` を cache する専用経路が要る**: MCP Google IdP flow (`mcp-auth-callback-google.ts`) は scope が `openid email` のみのため、通常は ID token の `sub` (google_sub) を捨てて `email` だけ auth code に積む。`issue_dev_token`/`issue_dev_login_url` (`mcp-tools.ts`) は既存 `upsertGoogleUser` (rust-alc-api の tenant_id/role lookup) を呼ぶのに google_sub が要るため、callback 側で `google_sub:<email>` を KV に 30日 cache しておく (`mintDevToken` はこの cache が無いと `google_sub_not_cached` で 403)。rust-alc-api への upsert は **既存ユーザーの google_sub 一致時は name/email を書き換えない** ので、この経路は副作用ゼロ (rust-alc-api 側は無修正)。dev JWT は `mcp-jwt.ts` の MCP access token とは別物 — `logi_auth_token` と同じ `JWT_SECRET`/AppClaims 形式に `token_kind:"dev"` を足しただけ (TTL 30分・refresh 無し)。**許可 subject は Secrets Store secret ではなく `MCP_OAUTH_KV` の plain key** (`dev-login.ts::DEV_LOGIN_ALLOWED_SUBJECTS_KV_KEY` = `dev_login_allowed_subjects`) — 秘密の値ではなく allowlist 設定なので、`wrangler kv key put --binding=MCP_OAUTH_KV dev_login_allowed_subjects '["google:you@example.com"]'` で直接投入する (secret-inject 不要。prod でも #432 以降 KV bind 済みなので、prod で dev-login を使うには prod 側 namespace にも同 key の投入が必要)。

## ローカルで動かすときの罠 (`wrangler dev`、Refs #474)

**症状から原因が推測しにくい**ものだけ列挙する。`--remote` は使わない前提 (local workerd)。

1. **`.dev.vars` に `JWT_SECRET` を書いても効かない → admin API が全部 401。**
   `JWT_SECRET` / `GOOGLE_CLIENT_*` 等は `wrangler.toml` の `[[secrets_store_secrets]]`
   binding で、**binding が `.dev.vars` に勝つ**。local の Secrets Store は空なので
   `resolveSecret(env.JWT_SECRET)` が `null` を返し、`buildAdminForwardHeaders` が
   検証に入る前に諦めて **401** になる (理由はログに出ない — `DEBUG` も同じ理由で
   効かないことがある)。local store に直接入れる (`--remote` を **付けない** = local):

   ```bash
   npx wrangler secrets-store secret create <store_id> --name JWT_SECRET --value <値> --scopes workers
   ```

   `<store_id>` は `wrangler.toml` の `[[secrets_store_secrets]]` に書いてある。
2. **worktree では bundle が build error で落ちる** — `@ippoan/egov-shinsei-sdk` が
   GitHub Packages の private registry にあり `npm ci` が 401 で入らないため、
   `src/handlers/egov-redirect.ts` の import が解決できない。`node_modules` を
   main clone から symlink しているだけだと書き足せないので、**worktree 側の
   `node_modules` を実ディレクトリにして共有 `node_modules` の各エントリへ symlink を
   張り直し**、そこに stub package (exports に `./auth` を持つもの) を置く。
   **stub を置いたままにすると `test/handlers/egov-redirect.test.ts` が
   「import error」から「assertion 失敗」に変わる**ので、テスト結果を報告する前に
   元の symlink へ戻すこと。
3. **`/login` の `isAllowedRedirectUri` を通すには local KV に origin を入れる。**

   ```bash
   npx wrangler kv key put --binding AUTH_CONFIG --local "origins:prod" "http://<ip>:8787"
   ```

### cookie 配送を伴う画面をローカルで確認する型

`google-callback` は redirect 先が共有 cookie の届くホストなら token を fragment に
載せず `Set-Cookie` だけで返す (`authCookieReachesHost`)。**この分岐はローカルでは
そのまま再現できない**:

- `authCookieReachesHost()` は `localhost` / `127.0.0.1` で **false** を返す
  (`getParentDomain` が `.` 始まりの親ドメインにならない)。
- `Domain=.ippoan.org` はローカルホストに張れず、http origin には `Secure` cookie も
  張れない。

**諦めずに、cookie 名 (`logi_auth_token`) だけ同じにして `Domain` / `Secure` を落とした
host-only cookie をブラウザ側で仕込む。** これで「cookie あり + `sessionStorage` 空」=
Google ログイン直後の本番状態が再現でき、ページ側の門番 (`admin-auth-script.ts`) から
見える情報は本番と同一になる。prod で cookie 配送分岐が成立すること自体は
`authCookieReachesHost('auth.ippoan.org','auth.ippoan.org') === true` の unit test
(`test/lib/cookies.test.ts`) が担保しているので、そこをローカルで踏み直す必要はない。


## 開発用の鍵 (`dev_device`) は USB で鍵を書き込む時点で決まる (Refs ippoan/alc-app#387)

登録簿 2 種 (`DeviceRecord` = `src/lib/device.ts`、`AlarmKeyRecord` = `src/handlers/alarm-key.ts`)
の `dev_device`。開発用の鍵で書いた記録は本番の記録簿に出ず、webhook と通知も止まる。

**登録簿の旗を後から倒す口は無い** (`/device/setup/dev-device`・`/device/setup/alarm-key/dev-device`・
`setDeviceDevFlag` は消した)。旗だけ倒しても、端末の鍵は変わらず、発行済みの token (TTL 900 秒 /
3600 秒) と接続時に値を固定する WS が古い値のまま残り、切替の直後の点呼・打刻が本番に入った
(2 回)。**切り替えは「USB で鍵を書き直す」** (古い鍵は revoke) の 1 通り。足し直さないこと。

| 口 | body の欄 | 規則 |
|---|---|---|
| `POST /device/setup/pair` (`device-setup.ts::handleDeviceSetupPair`) | `dev_device?: boolean` | 下の「書く規則」 |
| `POST /device/setup/alarm-key` (`alarm-key.ts::handleAlarmKeyRegister`) | `dev_device?: boolean`、`replaces_pubkey?: string` | 下の「書く規則」と「差し替え」 |

- **`dev_device` を書く規則は 1 つ** (`device-setup.ts::explicitDevDevice`。2 つの口で共用):
  - **明示 (true でも false でも) できるのは開発者アカウントが Google でログインした session だけ**
    (`isDeveloperGoogleSession`)。それ以外が欄を送ると 403 `developer_google_session_required` で、
    record は作られず旧 record も失効しない。boolean 以外 (文字列・数値・null) は 400。
  - **明示が無いとき**: 置き換え (`replace_label: true` / `replaces_pubkey`) は**旧 record の値を引き継ぎ**、
    新規は非 dev。開発者でない運用者の再ペアリングと `/device/pair-internal` (shared secret。`dev_device` を
    受けない = 常に明示なし) は値を変えられない — 開発用の端末が黙って本番にならず、本番の端末が
    開発用にもならない。引き継ぎの実体は `lib/device.ts::createDeviceCredentialReplacingLabel`
    (第 7 引数 `devDevice` が `undefined` なら旧 record の値)。**既に失効している旧 record からは引き継がない**
    (新規と同じ非 dev) — ラベル索引は失効しても残るので、引き継ぐと、開発用の端末を失効した後に同じラベルで
    登録した別の機体が黙って開発用になる。
  - 明示して書いたときだけ監査ログ `{event:"dev_device_set", registry:"device"|"alarm-key", dev_device}`
    (`logDevDeviceSet`。鍵の id・tenant・メールアドレスは出さない)。
  - 本番の record は**欄ごと持たない** (`false` を書かない)。
- **署名鍵の差し替え (`replaces_pubkey`)**: 機体が鍵を作り直した (`AUTH KEYGEN FORCE`) ときに、作り直す前の
  公開鍵を添える。その record (同じ tenant・未失効・用途あり) の **`label` と `usage` を新しい record に写し**
  (body の label / usage は見ない)、新しい record を保存した**後に**古い record を失効させる。古い record が
  見つからなければ (形式不正・不在・別 tenant・失効済みを区別せず) 409 `replaced_key_not_found` で何も書かない。
  ラベル一致で端末と署名鍵を結ぶ処理はサーバに無い。
- **開発者の判定は `src/lib/developer.ts` の 1 か所** (`DEVELOPER_EMAILS` / `isDeveloperEmail` /
  `isDeveloperGoogleSession`。`coverage_100.toml` 登録済み)。`isDeveloperEmail` は画面の出し分け
  だけ、サーバ側の認可は `isDeveloperGoogleSession`。`lib/admin-html.ts` の同名の定数は
  ブラウザに埋め込む表示用で別物 (ここへ寄せていない)。
- **`idp` claim**: `createAccessToken` の第 5 引数。**Google の callback (`google-callback.ts`) だけ**が
  `idp: "google"` を載せ、ほかの経路の token には key ごと無い。**読むのは
  `isDeveloperGoogleSession` だけ** — ほかの認可・振り分け・introspect の応答に使わない・出さない。
  claim を足す前の cookie と、auth-worker 以外が発行し直した token (`/api/switch-org` が返す
  rust-alc-api 発行の token 等) には無いので、その session では 403 になる (Google で入り直す)。
- **token の側は変えていない**: `dev_device` は token の発行時に record から claim へ焼かれ
  (`mintDeviceJwt`。`/device/token`・`/device/alarm-token`)、`/device-data-proxy` と `/auth/introspect` は
  claim だけを見る。鍵を書き直すと旧 record が revoke されるので、古い鍵では次の token が出ない。
- 一覧 (`GET /device/setup/list`、`GET /device/setup/alarm-keys`) の各行に `dev_device: boolean`。
  `/device/setup` の画面は「開発用」の印 (`devDeviceMark`) を全員に出す。

### 画面の入口は 1 つ —「接続中の機体を開発用 / 本番として書き直す」

`/device/setup` の「セットアップ実行」の下に、**開発者アカウントにだけ** (`isDeveloper` → HTML の出し分けと
`IS_DEVELOPER`。権限の根拠は上のサーバ側の検査) ボタン 1 組と機種の select (`rewrite-kind`。`DEVICE_KINDS` の
全機種)。ペアリングの画面・署名鍵の登録の画面に「開発用」のチェックは無い (新しい機体は普通に登録してから書き直す)。

`rewriteConnectedDevice` は手順を持たず、既存の 2 つを引数 `rewrite` で順に呼ぶだけ (**手順の複製を作らない**):

1. **端末の鍵** — `run(undefined, rewrite)` → `runCoreS3OrPrint` / `runP4Gateway`。pair の body に
   `dev_device` を足す (`replace_label: true` は今までどおり)。**ラベル (と GW の拠点) は聞かない**:
   `AUTH STATUS` / `cred show` が返す device_id で一覧の行を引き (`rewriteRowOf`)、その行の値で発行する
   (フォームのラベルで発行すると、同じラベルの別の端末の鍵を失効させる)。一覧に無い機体・機種違いは止める。
   `pairRole` を持たない機種 (bp-station・alarm = 署名鍵だけ) はこの手順を飛ばす。
2. **署名鍵** — `registerAlarmKey(rewrite)`。`AUTH PUBKEY` で古い公開鍵を控え → `AUTH KEYGEN FORCE` →
   `{pubkey, replaces_pubkey, dev_device}` を POST (ラベルと用途は聞かない)。`AUTH PUBKEY` が ERR
   (鍵なし) の機体は、端末の鍵を書き直した後なら何もせず済み。P4 GW (別の console) はこの手順を飛ばす。
3. 完了の文言 (キオスクの画面の再読み込み・古いファームは電源の入れ直し) を出し、2 つの表を読み直す。

- **機体の選択 (`requestPort`) は confirm より前** — ブラウザの許可ダイアログは押した操作が有効なうちにしか
  出せない。書き込みは confirm の後。同じ port を 2 つの手順で開き直して使う。
- **途中で失敗すると食い違いが残る** (端末の鍵だけ替わり、署名鍵が古いまま 等)。**1 台の CoreS3 は 2 つの
  登録簿に別の行で出る** (上の「デバイス」= `DeviceRecord`、本体の測定・打刻の鍵 / 下の「デバイスの署名鍵」=
  `AlarmKeyRecord` 用途 `kiosk`、キオスクの画面の token) ので、画面が**ラベルの完全一致で相方を探し**
  (`findKioskKeysFor` / `findHubDevicesFor`。相方が両側から見てちょうど 1 つのときだけ)、片方だけ
  `dev_device` なら**全員に**赤系のバッジ (`.tag.warn`、`refreshPairWarnings`) を両方の行に出す。表示だけで、
  書き込みはしない。直すにはもう一度書き直す。
- `AUTH KEYGEN FORCE` の後に POST が失敗すると、機体の鍵は新しく、登録簿は古い鍵のまま (未失効) になる。
  もう一度書き直すと `replaced_key_not_found` になるので、画面の案内どおり下の登録から登録し、古い行は手で失効する。
- **既知の前提 (未対応)**: staging と本番は `AUTH_CONFIG` (KV) と JWT の署名の秘密を共有し、
  ログインの JWT に環境を示す claim が無いので、staging で発行された cookie は本番でも通る。
  既存の書き込み口 (登録・失効・拠点 ID) と同じ根で、この規則の強さも署名の秘密の保持者と
  staging を含む backend の利用者表に依存する。

## 血圧計のボンドを外す (`POST /device/setup/bp_unbond`、Refs ippoan/alc-app#401)

`device-setup.ts::handleDeviceSetupBpUnbond`。body `{device_id}` → 端末へ `{action:"bp_unbond"}` (引数なし) を送り
command id を返す。結果は `/device/setup/ota/:id` で `{ok:true}` (受理しただけ) / `{ok:false,error:"busy"}`
(点呼中・OTA 中) / 古いファームは空 ack。

- **書き込み系**: `deviceCommandRequest` の第 4 引数 (read-only token 許可) を**渡さない**ので dev / device-key の
  token は 403 `dev_token_write_forbidden`。**照会の `bp_status` / `bus5v` の形を写さない** (写すと
  その token でボンドを外せる)。写す先例は `reboot`。
- 実際に外れたかは返らない。**結果は `bp_status` の照会で見る** (画面は受理の 3 秒後に `queryBpStatus` を呼び直す)。
- 画面は血圧計の列 (`bpSpan`) の隣のボタン。出す条件は照会と同じ (接続中だけ、`applyConnected` で切替)。
- MCP の道具からは送れない (`mcp-tools.ts` は action 固定。足さない)。

## 端末のラベルを返す内部 route (`GET /internal/device-labels?tenant_id=`、Refs ippoan/alc-app#403)

`internal-device-labels.ts`。**shared secret** (`Authorization: <INTERNAL_SHARED_SECRET*>`。検査は
`internal-hub-devices.ts::rejectUnlessSharedSecret` を `/internal/hub-devices` と共用 — 未 bind 503 / 不一致 401)。
テナントの**未失効の端末の `device_id` と `label` だけ**を返す (`{devices:[{device_id,label|null}]}`、`tenant_id` 無し 400)。
alc-app のサーバが端末一覧の表示と、キオスクが報告した `device_id` の登録済み照合に使う。
**`/internal/hub-devices` は label を返さないまま** (cron 用の最小参照。混ぜない)。

## RLS の確認を MCP の tool 1 回で受け取る (`verify_rls`、Refs #605)

`mcp-tools.ts` の tool `verify_rls`。本番 DB で RLS の不変条件・backend の実行用ロールの属性・いま繋いでいる
ロール・migration の適用履歴・履歴との食い違いを、backend (rust-alc-api) に固定された検査で確かめ、分割 worker
(vein) の DB 接続のロールと合わせて返す。DB に繋ぐのは backend と vein で、auth-worker が出す要求は 2 つだけ:
`lib/alc-internal.ts::fetchRlsCheck` の `GET /api/internal/rls-check` **1 回** (body なし・テナントのヘッダなし・
15 秒で打ち切り) と、`fetchVeinDbRole` の `GET /internal/db-role` **1 回** (Service Binding `ALC_VEIN`。
ヘッダなし・body なし・10 秒で打ち切り)。行のデータは返さない (vein からはロール名と真偽だけ)。

- **引数を足さない** (`inputSchema.properties` は空)。SQL・表名・式・テナントを受ける入口を作らない。
  `call` は `args` を読まない。
- **テナントをまたぐ値 (ロール名・表名・件数) を返す唯一の tool。** gate は
  `lib/dev-login.ts::checkDevLoginAllowlist` (許可リストの判定だけ。未設定・壊れた値は 403
  `dev_login_not_configured`、リスト外は 403 `not_in_allowlist`)。**`resolveTenantId` / `mintDevToken` を
  通さない** — 後段は `upsert-google` の POST (利用者登録) を伴い、「自テナントの操作」用の検査だから。
  `resolveTenantId` は冒頭で同じ `checkDevLoginAllowlist` を呼ぶ (判定の複製は無い)。
  **gate より前に backend も vein も呼ばない。**
- **呼ぶ順**: gate → `fetchRlsCheck` → (null なら 502 で終わり。**vein は呼ばない**) → `fetchVeinDbRole` →
  `buildVerifyRlsResult` (純粋な関数。`ok` と `verdicts` を組み立てる)。
- **`fetchRlsCheck` は契約の key だけを名指しで写す** (`parseRlsCheck`。入れ子の中まで。スプレッドで写さない)。
  backend が key を足しても tool からは出ない。fetch の例外・非 200・JSON 不正・型違い・key 欠けはすべて `null` →
  tool は `dev-login error 502: rls_check_unavailable`。key を増やすときは型 `RlsCheckResult`・`parseRlsCheck`・
  tool の `description` の 3 か所。
- **`invariants.checks`** = 検査ごとの `{check_no, title, violations}`。違反が無くても毎回返る (何を確かめたかの
  一覧)。名指しで写す (型違い・欠けは全体が `null`)。
- **`state`** = 観測したカタログの値 (状態が同じ表の組・policy の式・view・SECURITY DEFINER の関数・sequence)。
  **`drift`** = 履歴との食い違い (食い違った表・関数・view を、期待 = 履歴を 0 から当てた状態 と実物で並べたもの)。
  **この 2 つだけは入れ子まで写さない** — object であることと大きさ (`RLS_STATE_MAX_LENGTH` = 256KB を共用) だけ
  見てそのまま返す。形の正本は alc-migrations の固定の SQL と backend の比較で、形が育つたびにここの写しを直す
  二重管理にしないため。object でない・欠け・大きすぎるときはその key を `null` にするだけで、**全体を `null` に
  しない**。`drift: null` は「比べられなかった」(古い backend、または backend が状態を取れなかった)。
- **backend の `verdicts`** (合否の内訳 `{invariants, runtime_role, migrations, drift}`) は**無くてよい key**。
  返さない backend (古い版) では `RlsCheckResult.verdicts` が `null`。在るなら 4 つとも boolean であること —
  欠け・型違いは応答全体を不正として `null` (→ 502。内訳を読めないまま合否だけ返さない)。
- **`workers.vein`** = `{bound, current_user, is_runtime_role}`。vein は backend と別の接続の secret を持ち、
  所有者ロールで繋いでいると RLS が掛からないので、ここで確かめる。`ALC_VEIN` が無い (staging・テスト) →
  `bound: false` で値は null。在るのに取れない (fetch の例外・非 200・JSON 不正・型違い) → `bound: true` で値は
  null。**vein が失敗しても backend の結果は返す** (502 にしない)。
- **`fetchVeinDbRole` は `/api/vein/` の proxy (`forwardViaAlcBinding`) を通らず、binding を直接呼ぶ。**
  vein の口の path が `/api` の外に在るのは、proxy の振り分け (`ALC_BINDING_ROUTES` = `/api/vein/`) から
  届かないようにするため — 届くのは auth-worker のコードが binding で直接呼んだときだけ。
- **tool が返す `verdicts`** は 5 個ちょうど: backend の 4 つ + `vein`。**`ok` が false のときは `verdicts` で
  どれが原因かを読む** (`invariants` = 不変条件の違反が 0 件 / `runtime_role` = backend が実行用ロールで繋いでいる /
  `migrations` = 適用履歴が backend の想定と一致 / `drift` = 本番の実物が migration の履歴どおり / `vein` = vein が
  実行用ロールで繋いでいる)。値が `null` の項目は「その backend・その環境では判定していない」(backend が内訳を
  返さない → 4 つとも null、vein が bind されていない → `vein: null`)。`vein` は bind されていれば
  `is_runtime_role === true` のときだけ true (呼べなかった・形が違う = false。fail-closed)。
- **`ok`** = backend の `ok` かつ (backend が内訳を返したなら 4 つとも true) かつ (`vein` が null か true)。
  **backend の `ok` が false なら tool の `ok` は true にならない** (テストで全組み合わせを固定)。合否を足すなら
  alc-migrations の検査 SQL か backend の内訳に足す (auth-worker は vein 以外の判定を持たない)。
  `owner_role_connected` は注意の表示で `ok` に入らない (migration の job の実行中は true になりうる)。
- **`matches_binary` の窓**: migration の直後は、新しい backend への切り替えが終わるまで `matches_binary: false`
  (= `ok: false`)。`binary_max_version` が古ければ切り替え前 — 壊れているのではない。
- **staging では `ok: false` が正しい結果** (staging の backend は実行用ロールで繋いでいない。vein は bind されて
  いないので `verdicts.vein` は null)。
- scope は `mcp.write` (許可リストで絞る他の tool と同じ)。新しい secret・binding・scope は無い (`ALC_VEIN` は既存)。

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

## Cloudflare Access 向け OIDC surface (`/oidc/*`)

Cloudflare Access の **generic OIDC プロバイダ**として auth-worker を使う口。
Access に守らせたホスト名 (実例: オンプレ RDP 中継の `rdp.ippoan.org`) へ入るとき、
**管理画面に既にログインしている利用者に追加ログインを一切させない**のが目的。

| path | handler | 備考 |
|---|---|---|
| `GET /oidc/.well-known/openid-configuration` (+ `/.well-known/openid-configuration/oidc`) | `oidc-discovery` | issuer は **`<origin>/oidc`**。Access の設定は URL 手入力なので必須ではないが、issuer を名乗る以上 publish する |
| `GET /oidc/authorize` | `oidc-authorize` | **`logi_auth_token` があればその場で code を出す** (IdP へ飛ばさない)。無い/期限切れの時だけ既存 `/login` に送り、戻り先に自分を渡す |
| `POST /oidc/token` | `oidc-token` | code → `id_token` (ES256) + userinfo 用 access_token。`authorization_code` のみ (refresh は出さない — 寿命は Access の session が持つ) |
| `GET /oidc/userinfo` | `oidc-userinfo` | `tenant_id` / `role` / `org_slug` を custom claim として返す |
| `GET /oidc/.well-known/jwks.json` | `oidc-jwks` | Access が `id_token` を検証する鍵 |

### `/mcp/*` と混ぜない

| | MCP surface | この surface |
|---|---|---|
| issuer | `<origin>` / `<origin>/mcp/google` | **`<origin>/oidc`** |
| client | public (DCR、`auth_methods: ["none"]`) | **confidential** (`client_secret_post/basic`)。管理画面で 1 回設定して長く使う種類なので動的登録の利点が無い |
| 署名 | HS256 (`JWT_SECRET` / `MCP_JWT_SECRET`) | **ES256** (`ACCESS_OIDC_SIGNING_KEY`)。Access は JWKS で検証するので対称鍵が原理的に使えない |
| 目的 | 外部 IdP の identity を**取りに行く** | 自分が持っている identity を**渡す** |

**`ACCESS_OIDC_SIGNING_KEY` は id_token 以外の署名に使わない** (`logi_auth_token` /
MCP access token の形式は不変)。`ACCESS_OIDC_CLIENTS` (`{client_id, client_secret,
redirect_uris[]}` の JSON 配列) と併せて未 bind なら **`/oidc/*` だけが 503** になり、
既存経路には影響しない (fail-closed かつ局所)。

### 消費側

Access アプリの policy は `tenant_id` claim / email で書ける。origin 側 (例:
`ohishi-exp/rust-ichibanboshi` の `rdp-relay`) は `Cf-Access-Jwt-Assertion` を team の
JWKS で検証する二段目の壁を持つ。ブラウザ側の作法 (WebSocket は 302 を辿れないので
接続前に Access cookie を確保する) は `nuxt-dtako-admin-map` skill。


## CI / publish

- `test.yml` → `ci-workflows/frontend-ci.yml`。`npm_publish_directory: 'packages/auth-client,packages/auth-client-worker'` で 2 package を 1 CI で publish (dev tag = `0.0.<PR>-dev.<SHA>`、release = tag 共通)。
- branch protection preset: `ippoan-go-default` 等 (auth-worker が presets を保持)。

## 関連

- `ippoan-infra-map` — CCoW 基盤 5 repo の地図 (auth-worker はそこに出てこない consumer 群の認証元)
- `secret-inject` — OAT→binding_jwt→secret 投入 (auth-worker の grant-via-oat を使う)
- `cross-repo-symbol-index` — この per-repo map skill の運用方針 (generated-from 鮮度 hook)

## CLAUDE.md から移設 (2026-07-07)

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
