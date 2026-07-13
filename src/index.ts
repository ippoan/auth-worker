import { handleLoginPage } from "./handlers/login-page";
import { handleAuthLogin } from "./handlers/login-api";
import { handleGoogleRedirect } from "./handlers/google-redirect";
import { handleGoogleCallback } from "./handlers/google-callback";
import { handleEgovRedirect } from "./handlers/egov-redirect";
import { handleEgovCallback } from "./handlers/egov-callback";
import { handleGhapiRedirect } from "./handlers/ghapi-redirect";
import { handleGhapiCallback } from "./handlers/ghapi-callback";
import { handleLineworksRedirect } from "./handlers/lineworks-redirect";
import { handleLineworksCallback } from "./handlers/lineworks-callback";
import { handleLineRedirect } from "./handlers/line-redirect";
import { handleLineCallback } from "./handlers/line-callback";
import { handleLineSelectTenant } from "./handlers/line-select-tenant";
import { handleAdminSsoPage, handleAdminSsoCallback } from "./handlers/admin-sso";
import { handleAdminUsersPage, handleAdminUsersCallback } from "./handlers/admin-users";
import { handleSsoList, handleSsoUpsert, handleSsoDelete } from "./handlers/api-sso";
import { handleAdminLineUsersPage, handleAdminLineUsersCallback } from "./handlers/admin-line-users";
import { handleLineUsersList, handleLineUserDelete } from "./handlers/api-line-users";
import { handleBotConfigList, handleBotConfigUpsert, handleBotConfigDelete, handleBotConfigExport, handleBotConfigImport } from "./handlers/api-bot-config";
import { handleWoffAuth, handleWoffConfig } from "./handlers/woff-auth";
import { handleMyOrgs } from "./handlers/api-my-orgs";
import { handleAlcProxy } from "./handlers/alc-proxy";
import { handleAlcInternalProxy } from "./handlers/alc-internal-proxy";
import { handleDeviceDataProxy } from "./handlers/device-data-proxy";
import { handleOhishiLogiProxy } from "./handlers/ohishi-logi-proxy";
import { handleCfFlickrCamWorkerProxy } from "./handlers/cf-flickr-cam-worker-proxy";
import { handleAdminNotifyApi } from "./handlers/admin-notify-api";
import { handleSwitchOrg } from "./handlers/api-switch-org";
import {
  handleRichMenuList, handleRichMenuCreate, handleRichMenuDelete,
  handleRichMenuImageUpload, handleRichMenuDefaultSet, handleRichMenuDefaultDelete,
} from "./handlers/api-rich-menu";
import { handleAdminRichMenuPage, handleAdminRichMenuCallback } from "./handlers/admin-rich-menu";
import { handleTopPage } from "./handlers/top-page";
import { handleAuthCallback } from "./handlers/auth-callback";
import { handleHealthProxy } from "./handlers/health";
import { handleHealthOAuth } from "./handlers/health-oauth";
import { handleSecretFingerprint } from "./handlers/health-fingerprints";
import { handleHealthWif } from "./handlers/health-wif";
import {
  handleUsersList, handleInvitationsList, handleInviteUser,
  handleDeleteInvitation, handleDeleteUser,
} from "./handlers/api-users";
import { handleLogout } from "./handlers/logout";
import { handleJoinPage } from "./handlers/join-page";
import { handleJoinDone } from "./handlers/join-callback";
import { handleRedirect } from "./handlers/redirect";
import { handleAdminRequestsPage, handleAdminRequestsCallback } from "./handlers/admin-requests";
import { handleAdminNotifyPage, handleAdminNotifyCallback } from "./handlers/admin-notify";
import {
  handleAccessRequestCreate, handleAccessRequestList,
  handleAccessRequestApprove, handleAccessRequestDecline,
} from "./handlers/api-access-requests";
import { corsPreflight } from "./lib/errors";
import { handleLineworksWebhook, handleLineworksRefresh } from "./handlers/lineworks-webhook";
import { handleLineWebhook } from "./handlers/line-webhook";
import { handleMcpAsMetadata } from "./handlers/mcp-as-metadata";
import { handleMcpResourceMetadata } from "./handlers/mcp-resource-metadata";
import { handleMcpDeviceAuthorization } from "./handlers/mcp-device-authorization";
import { handleMcpDevicePage } from "./handlers/mcp-device-page";
import { handleMcpDeviceVerify } from "./handlers/mcp-device-verify";
import { handleMcpDeviceProceed } from "./handlers/mcp-device-proceed";
import { handleMcpDeviceCallback } from "./handlers/mcp-device-callback";
import { handleMcpToken } from "./handlers/mcp-token";
import { handleMcpIntrospect } from "./handlers/mcp-introspect";
import { handleAuthIntrospect } from "./handlers/auth-introspect";
import { handleMcpJwtPickup } from "./handlers/mcp-jwt-pickup";
import { handleMcpRelayConnect } from "./handlers/mcp-relay-connect";
import { handleMcpRelayBridge, handleMcpRelaySse } from "./handlers/mcp-relay-bridge";
import { handleMcpRegister } from "./handlers/mcp-register";
import { handleMcpAuthorize } from "./handlers/mcp-authorize";
import {
  handleDevicePair,
  handleDevicePairInternal,
  handleDeviceToken,
  handleDeviceRevoke,
} from "./handlers/device";
import {
  handleDevicePairStart,
  handleDevicePairApprovePage,
  handleDevicePairApprove,
  handleDevicePairToken,
} from "./handlers/device-pair";
import {
  handleDeviceSetupPage,
  handleDeviceSetupPair,
  handleDeviceSetupList,
} from "./handlers/device-setup";
import { handleMcpAuthCallback } from "./handlers/mcp-auth-callback";
import { handleMcpPairNew } from "./handlers/mcp-pair-new";
import { handleMcpPairClaim } from "./handlers/mcp-pair-claim";
import { handleMcpPairCallback } from "./handlers/mcp-pair-callback";
import { handleMcpPairGrant } from "./handlers/mcp-pair-grant";
import { handleMcpPairGrantViaGithub } from "./handlers/mcp-pair-grant-via-github";
import { handleMcpPairGrantViaOat } from "./handlers/mcp-pair-grant-via-oat";
import { handleMcpPairRegisterViaGithubComment } from "./handlers/mcp-pair-register-via-github-comment";
import { handleMcpTools } from "./handlers/mcp-tools";
import { handleMcpRevoke } from "./handlers/mcp-revoke";
import { handleGithubWebhook } from "./handlers/github-webhook";
import { handleMcpElevateStart, handleMcpElevateCallback } from "./handlers/mcp-elevate";
import { handleMcpAdminExec } from "./handlers/mcp-admin-exec";
import { handleDashboardBranchProtection } from "./handlers/dashboard-branch-protection";
import {
  handleApiDashboardListRepos,
  handleApiDashboardApplyProtection,
  handleApiDashboardRemoveProtection,
  handleApiDashboardFixRepoSettings,
} from "./handlers/api-dashboard-branch-protection";
export { LineworksWebhookDO } from "./durable_objects/lineworks-webhook-do";
export { McpSession } from "./durable_objects/mcp-session-do";

import type { SecretBinding } from "./lib/secret";

export interface Env {
  /** Refs #206: `.dev.vars` 由来 prod secret 一式を CF Secrets Store binding に移行
   *  (PR #205)。`string` (vitest / `wrangler dev`) と `SecretsStoreSecret`
   *  (`.get()` 持ち) の両形態を `resolveSecret()` で `string | null` に正規化して
   *  使う。直接 `env.X` を string として読むと `[object Fetcher]` が漏れる。 */
  GOOGLE_CLIENT_ID: SecretBinding;
  GOOGLE_CLIENT_SECRET: SecretBinding;
  OAUTH_STATE_SECRET: string;
  AUTH_WORKER_ORIGIN: string;
  ALC_API_ORIGIN: string;
  /** flip 前 preview override (Refs ippoan/ci-dashboard#472) が許可する
   *  rust-alc-api の Cloud Run host suffix。`/alc-proxy/*` は
   *  `X-Alc-Preview-Api-Base` header の host が `<tag>---<この suffix>`
   *  (= 同一 service の tagged revision URL) に一致する時だけ forward 先と
   *  OIDC aud を差し替える。未設定なら override 要求は 400 (fail-closed)。 */
  ALC_API_PREVIEW_HOST_SUFFIX?: string;
  /** staging Cloud Run の rust-alc-api。Bot Config Import (developer 専用) 用 proxy 先。
   *  未設定なら handler 内で本番 staging URL に fallback する。 */
  ALC_API_STAGING_ORIGIN?: string;
  /** staging `/api/staging/import` の `X-Staging-Key` (rust-alc-api#391)。
   *  GCP `ALC_STAGING_API_KEY` から sync した Secrets Store binding (staging 専用)。
   *  未設定なら Bot Config Import は key 無しで投げ rust が 401 を返す。 */
  ALC_STAGING_API_KEY?: SecretBinding;
  VERSION: string;
  WORKER_ENV: string;
  /** `"true"` のとき admin proxy 等が網羅ログ (verify 結果 / 注入 claims / rust 応答) を
   *  emit する。staging の [vars] でのみ有効化 (Refs rust-alc-api#434 admin 401 調査)。 */
  DEBUG?: string;
  AUTH_CONFIG: KVNamespace;
  /** HS256 JWT secret, shared with rust-alc-api. Used by /top to verify the
   *  `logi_auth_token` cookie before serving the page. Missing → /top
   *  redirects everyone to /login (fail-closed).
   *  Refs #206: Secrets Store binding 化済。`resolveSecret()` 経由でアクセス。 */
  JWT_SECRET: SecretBinding;
  /** rust-alc-api#434 step 3 (方式 B): run.invoker SA key (JSON)。`/alc-proxy/*`
   *  が Google OIDC ID token を mint して Cloud Run IAM lockdown 後の
   *  rust-alc-api に到達するために使う。Secrets Store binding、未設定なら
   *  `/alc-proxy` は 503 (fail-closed)。auth-worker のみ bind (SA key 集約)。 */
  ALC_API_PROXY_SA_KEY?: SecretBinding;
  /** ohishi-logi (Cloud Run、無状態 camera fetcher) の origin。`/ohishi-logi-proxy/*`
   *  が forward 先として使う。未設定なら 503 (fail-closed)。Refs
   *  ohishi-exp/ohishi-logi#1。新規 GCP project 確定後に投入する (2026-07-08
   *  時点は未デプロイのため未設定)。 */
  OHISHI_LOGI_ORIGIN?: string;
  /** `/ohishi-logi-proxy/*` が Google OIDC ID token を mint して Cloud Run IAM
   *  lockdown 後の ohishi-logi に到達するための run.invoker SA key (JSON)。
   *  ALC_API_PROXY_SA_KEY とは別の SA (ohishi-logi service 限定の run.invoker
   *  のみ付与、blast radius を分離)。Secrets Store binding、未設定なら
   *  `/ohishi-logi-proxy` は 503 (fail-closed)。 */
  OHISHI_LOGI_PROXY_SA_KEY?: SecretBinding;
  /** `/cf-flickr-cam-worker-proxy/*` の forward 先 (service binding)。
   *  Flickr OAuth1.0a callback (ブラウザ経由リダイレクト) と運用者向け UI だけを
   *  公開するための唯一の到達経路。cf-flickr-cam-worker 自体は `workers_dev: false`
   *  で完全非公開 (Refs ippoan/cf-flickr-cam-worker#3, #4)。SA key/OIDC 不要
   *  (Cloud Run ではなく同じ Cloudflare account 内 Worker 間の service binding)。
   *  未 bind なら `/cf-flickr-cam-worker-proxy/*` は 503 (fail-closed)。 */
  CF_FLICKR_CAM_WORKER?: Fetcher;
  /** rust-alc-api#434 lockdown cutover フラグ。`"1"` で internal-auth 呼び出し
   *  (`lib/alc-internal.ts`) を HS256 internal JWT → Google OIDC (aud=alc-api-internal) mint に
   *  切替える。allUsers 削除 + Cloud Run `--add-custom-audiences=alc-api-internal` + rust 側
   *  dual-accept deploy が揃ってから立てる (それまでは未設定 = HS256 のまま、非破壊)。 */
  INTERNAL_AUTH_OIDC?: string;
  /** e-Gov (Keycloak) OAuth — all optional; handlers return 503 if unset. */
  EGOV_CLIENT_ID?: string;
  EGOV_CLIENT_SECRET?: string;
  EGOV_AUTH_BASE?: string;
  /** JSON map of github-org → allowlisted tenant_ids. Example:
   *  `{"ohishi-exp":["<uuid-1>","<uuid-2>"]}`.
   *  Missing / malformed → deny all ohishi-exp access (fail-closed). */
  TENANT_ACL?: string;
  /** JSON map of github-org → allowlisted user emails (lowercase). Example:
   *  `{"ohishi-exp":["alice@example.com"]}`.
   *  OR-composed with TENANT_ACL: a request is allowed if *either* the
   *  tenant_id or the email is in its org's allowlist. Useful when the
   *  tenant_id is not stable (e.g. staging DB with volatile UUIDs). */
  USER_ACL?: string;
  /** JSON config for per-app tenant ACL with optional global email bypass.
   *  Example:
   *  ```
   *  {
   *    "bypass_emails": ["m.tama.ramu@gmail.com"],
   *    "apps": {
   *      "https://ichibanboshi.ippoan.org":         ["<uuid>"],
   *      "https://ichibanboshi-staging.ippoan.org": ["<uuid>"]
   *    }
   *  }
   *  ```
   *  `bypass_emails` (typically set on staging only): a JWT whose `email`
   *  matches (case-insensitive) passes the app-level check for any origin.
   *  `apps`: per-origin tenant allowlist. Keys must match
   *  `new URL(redirectUri).origin` exactly (no trailing slash). Use `"*"`
   *  to allow any tenant. Origins not in `apps` pass (opt-in).
   *  Missing / malformed → pass (fail-open). Checked AFTER `checkOrgAccess`
   *  to partition tenants across apps within the same org. */
  APP_TENANT_ACL?: string;
  /** When set, /login delegates OAuth to the given auth-worker origin instead of
   *  running OAuth locally. Used by /wt-quick worktree tunnels whose random
   *  `*.trycloudflare.com` URLs cannot be registered in Google OAuth console. */
  LOGIN_DELEGATE_TO?: string;
  /** AES-256-GCM 鍵素材 (rust-alc-api と共有、GCP `sso-encryption-key` を Secrets Store
   *  binding として注入)。bot_secret_encrypted / LINE WORKS client_secret 復号 + MCP
   *  github-token 暗号化で SHA-256(SSO_ENCRYPTION_KEY) を 32B 鍵に使う。値は
   *  `resolveSecret()` で解決すること (legacy plain string でも Secrets Store でも可)。 */
  SSO_ENCRYPTION_KEY: SecretBinding;
  /** LINE Login (notify recipient OAuth) のグローバル channel (rust-alc-api#434 Phase 3、
   *  GCP `line-login-channel-{id,secret}` を Secrets Store binding として注入)。
   *  未設定なら `/oauth/line/*` は 503。`resolveSecret()` で解決する。 */
  LINE_LOGIN_CHANNEL_ID?: SecretBinding;
  LINE_LOGIN_CHANNEL_SECRET?: SecretBinding;
  /** LINE WORKS webhook 受信用 Durable Object Namespace (bot_id ごとに 1 instance)。 */
  LINEWORKS_WEBHOOK_DO: DurableObjectNamespace;
  /** MCP OAuth Provider 用 GitHub OAuth App credentials.
   *  staging/prod で別 App (callback URL が異なるため)。
   *  Refs #206: Secrets Store binding 化済。`resolveSecret()` 経由でアクセス。 */
  GITHUB_MCP_CLIENT_ID?: SecretBinding;
  GITHUB_MCP_CLIENT_SECRET?: SecretBinding;
  /** HS256 secret for MCP access tokens (JWT)。既存 JWT_SECRET とは別管理。
   *
   *  2026-05-25 (Refs ippoan/ref-files-worker#6): `wrangler secret put` の
   *  Worker secret から **Secrets Store binding** に移行。auth-worker と
   *  ref-files-worker が同 entry `INTERNAL_SHARED_SECRET` を point して鍵を
   *  物理共有する設計に揃え、worker 間で HS256 鍵が drift しなくなる。
   *  - `string`            — vitest binding / 移行前互換
   *  - `SecretsStoreSecret` — 実 deploy 環境 (`.get()` 経由で値取得)
   *  値の取り出しは `resolveMcpJwtSecret(env.MCP_JWT_SECRET)` を必ず通すこと。 */
  MCP_JWT_SECRET?: string | SecretsStoreSecret;
  /** Rust binary (github-mcp-server-rs / ref-files-mcp-server-rs) が
   *  /mcp/introspect を叩く際の認証用。Bearer header で送られる固定共有鍵。
   *
   *  Two binding shapes are tolerated while we migrate to Cloudflare
   *  Secrets Store:
   *    - `string`     — legacy `wrangler secret put` (and mock-env tests).
   *    - `SecretsStoreSecret` — account-level Secrets Store binding via
   *                   `[[secrets_store_secrets]]`. Async `.get()`.
   *  The same store_id + secret_name is bound on ref-files-worker so the
   *  binary sees one physical value across both workers
   *  (Refs ippoan/ref-files-worker#4). `resolveAllSharedSecrets(env)` in
   *  mcp-introspect.ts iterates every `INTERNAL_SHARED_SECRET*` binding
   *  and normalises each to a string (issue #189). */
  INTERNAL_SHARED_SECRET?: string | SecretsStoreSecret;
  /** JSON array of github logins allowed to use MCP server.
   *  Example: `["yhonda-ohishi"]`. Missing / malformed → deny all (fail-closed).
   *  Refs #206: Secrets Store binding 化済。`resolveSecret()` 経由でアクセス。 */
  GITHUB_MCP_USER_ALLOWLIST?: SecretBinding;
  /** KV namespace for MCP OAuth state (device_codes, sessions, refresh tokens)。
   *  Phase 1+ で binding 参照開始。Phase 0 では wrangler.toml に binding 追加のみ。 */
  MCP_OAUTH_KV?: KVNamespace;
  /** MCP relay 用 Durable Object Namespace (github_login ごとに 1 instance)。
   *  binary 側 (`github-mcp-server-rs`) からの outbound WebSocket を保持し、
   *  Claude Code Web からの bridge request を frame に変換して転送する。
   *  Phase 6 で binding 追加、Phase 7 で実 frame 変換を実装する (issue #117)。 */
  MCP_SESSION_DO?: DurableObjectNamespace;
  /** ADR-004: GitHub webhook の HMAC-SHA256 検証用共有 secret。public issue
   *  前提なので authentication ではなく spam 対策。全 repo の webhook 設定で
   *  同じ値を使う。
   *  Refs #206: Secrets Store binding 化済。`resolveSecret()` 経由でアクセス。 */
  GITHUB_WEBHOOK_SECRET?: SecretBinding;
  /** issue #144: 1-click pair flow 用の auth-worker ブラウザ session cookie 署名鍵。
   *  既存 `MCP_JWT_SECRET` と分けるのは scope を局所化するため (pair session が
   *  漏洩しても device-flow JWT には影響しない)。未設定 → /mcp/pair/* は 503。 */
  SESSION_COOKIE_SECRET?: string;
  /** Google Health API OAuth Client (= `ippoan/HealthConnectReaderWorker` 連携用)。
   *  既存ログイン用 (`GOOGLE_CLIENT_ID`) とは別 OAuth Client。Google Cloud で
   *  `${AUTH_WORKER_ORIGIN}/oauth/ghapi/callback` を redirect URI として登録した
   *  staging 側 client を bind する。未設定 → `/oauth/ghapi/*` は 503。
   *  Refs ippoan/HealthConnectReaderWorker#60, #61 */
  GOOGLE_HEALTH_CLIENT_ID?: SecretBinding;
  GOOGLE_HEALTH_CLIENT_SECRET?: SecretBinding;
  /** OAuth 認可リクエストで送る scope (space 区切り)。未設定なら handler 内
   *  default (openid email + Google Fit Exercise / heart_rate / location / body)
   *  を使う。Google Health Data Platform GA で scope 名が変わったら vars で上書く。 */
  GOOGLE_HEALTH_SCOPES?: string;
  /** hcreader-worker (`ippoan/HealthConnectReaderWorker`) の origin。
   *  ghapi callback 内部から `${HCREADER_WORKER_ORIGIN}/api/ghapi/store-tokens`
   *  に refresh_token を内部 POST するのに使う。
   *  例: `https://hcreader.ippoan.org` */
  HCREADER_WORKER_ORIGIN?: string;
}

function errorResponse(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * MCP relay route dispatcher (issue #117 / Phase 6 + ADR-003 user-less).
 *
 * `mcp.ippoan.org` / `mcp-staging.ippoan.org` host で来た request を以下に振り分ける:
 *
 * - `GET  /u/:user/connect` (WS upgrade)  — github-mcp-server-rs 互換 (Phase 6)
 * - `POST /u/:user/mcp`     (HTTP bridge) — github-mcp-server-rs 互換 (Phase 6)
 * - `GET  /connect`         (WS upgrade)  — ADR-003 user-less: DO id from JWT
 * - `POST /mcp`             (HTTP bridge) — ADR-003 user-less: DO id from JWT
 * - `POST /register`        (DCR)         — Phase 5 / #128
 * - `GET  /authorize`       (Auth Code)   — Phase 5 / #128
 *
 * マッチしなければ 404 を返す (auth routes は通さない)。戻り値が `null` なら
 * relay host ではなかったので caller は既存処理に進む。
 */
async function dispatchMcpRelay(
  request: Request,
  env: Env,
  url: URL,
): Promise<Response | null> {
  if (!url.host.startsWith("mcp.") && !url.host.startsWith("mcp-staging.")) {
    return null;
  }
  // [^/]+ で 1 文字以上を強制しているので、マッチ時は両 capture group が必ず存在する。
  const m = /^\/u\/([^/]+)\/(connect|mcp)$/.exec(url.pathname);
  if (m) {
    const user = m[1] as string;
    const action = m[2];
    if (action === "connect" && request.method === "GET") {
      return handleMcpRelayConnect(request, env, user);
    }
    if (action === "mcp" && request.method === "POST") {
      return handleMcpRelayBridge(request, env, user);
    }
    // ADR-004 Phase D: GET /u/:user/mcp → SSE stream (Streamable HTTP transport)。
    if (action === "mcp" && request.method === "GET") {
      return handleMcpRelaySse(request, env, user);
    }
  }
  // ADR-003 (ippoan/cc-relay#35): user-less variants. `.mcp.json` committed
  // to a consumer repo root can point at `/mcp` / `/connect` (no user
  // segment); the DO id is derived from the JWT's `github_login` claim
  // inside the handlers. The user-scoped routes above remain for
  // `github-mcp-server-rs` backward compatibility.
  if (url.pathname === "/mcp" && request.method === "POST") {
    return handleMcpRelayBridge(request, env, null);
  }
  // ADR-004 Phase D: GET /mcp → SSE stream (Streamable HTTP transport for
  // Anthropic Claude.ai / Claude Code Web `notifications/message` push)。
  if (url.pathname === "/mcp" && request.method === "GET") {
    return handleMcpRelaySse(request, env, null);
  }
  if (url.pathname === "/connect" && request.method === "GET") {
    return handleMcpRelayConnect(request, env, null);
  }
  // Phase 5 (issue #128): Browser-based MCP client (Anthropic Claude.ai 等) は
  // resource server URL の host (`mcp(-staging).ippoan.org`) 上で `/register`
  // (DCR, RFC 7591) と `/authorize` (Auth Code, RFC 6749) を期待する。
  // auth-worker は同 script なので、これらも relay host 上で受け付ける。
  if (url.pathname === "/register" && request.method === "POST") {
    return handleMcpRegister(request, env);
  }
  if (url.pathname === "/authorize" && request.method === "GET") {
    return handleMcpAuthorize(request, env);
  }
  // issue #144: 1-click pair の起点。binary が `POST /mcp/pair/new` を
  // mcp(-staging).ippoan.org に叩いて pair_code + pair_url を取得する。
  // 認証なしの匿名 endpoint だが rate-limit を入れる (mcp-pair-new.ts)。
  if (url.pathname === "/mcp/pair/new" && request.method === "POST") {
    return handleMcpPairNew(request, env);
  }
  // issue #157 Phase B: refresh_token → binding_jwt 交換 endpoint。
  // pair_url を browser で踏まずに次回 container を bootstrap するための path。
  // Authorization: Bearer <refresh_token>。relay host 経由 (binary 側) と
  // AS host 経由 (debug / curl) の両方で叩けるよう、auth-worker 側 POST
  // dispatcher にも下で同 case を入れる。
  if (url.pathname === "/mcp/pair/grant" && request.method === "POST") {
    return handleMcpPairGrant(request, env);
  }
  // issue ippoan/mcp-relay-rs#15: GitHub OAuth token を identity proof として
  // 受け取って binding_jwt を 1 発で mint する endpoint。CCoW container のように
  // browser cookie も pre-staged env も無い環境で bootstrap するための path。
  if (url.pathname === "/mcp/pair/grant-via-github" && request.method === "POST") {
    return handleMcpPairGrantViaGithub(request, env);
  }
  // issue ippoan/auth-worker#174: Anthropic OAT を identity proof として受け取り、
  // OAT_hash → github_login mapping を引いて binding_jwt を mint する。
  // 引けなかったら 404 + register_endpoint hint で setup フローへ誘導。
  if (url.pathname === "/mcp/pair/grant-via-oat" && request.method === "POST") {
    return handleMcpPairGrantViaOat(request, env);
  }
  // issue ippoan/auth-worker#174: GitHub issue comment の `comment.user.login` を
  // root-of-trust に OAT_hash → github_login mapping を KV に書く endpoint。
  // CCoW container 内 Claude が `mcp__github__add_issue_comment` で初回 1 回だけ
  // 叩く想定。
  if (url.pathname === "/mcp/pair/register-via-github-comment" && request.method === "POST") {
    return handleMcpPairRegisterViaGithubComment(request, env);
  }
  // ADR-004 (cc-relay/ARCHITECTURE.md): GitHub webhook を受け、既存
  // McpSession DO 経由で attached binary に broadcast する (multiplex)。
  if (url.pathname === "/webhooks/github" && request.method === "POST") {
    return handleGithubWebhook(request, env);
  }
  // issue #145: native MCP JSON-RPC endpoint (GitHub API proxy tools).
  // relay host 経由でも叩けるようにここでも受ける (binary 不要の "native mode")。
  if (url.pathname === "/mcp/tools" && request.method === "POST") {
    return handleMcpTools(request, env);
  }
  return errorResponse(404, "Not found");
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    console.log(JSON.stringify({
      event: "request",
      method: request.method,
      path: url.pathname,
      search: url.search,
    }));

    try {
      const relay = await dispatchMcpRelay(request, env, url);
      if (relay) return relay;

      // rust-alc-api#434 step 3 (方式 B): consumer の CF Worker が service binding
      // (AUTH_WORKER) で forward する rust-alc-api data-proxy。全 method・全 host
      // (binding 越し) で到達させたいので host 別 routing より前に置く。
      if (url.pathname.startsWith("/alc-proxy/")) {
        return handleAlcProxy(request, env);
      }

      // rust-alc-api#434 step 3d (caller #4): browser JWT を持たない server-to-server
      // 内部呼び出し (email-receiver 等) 向け。shared-secret proof + path allowlist で
      // ingest 経路だけを OIDC mint して forward する (data 経路は /alc-proxy 専用)。
      if (url.pathname.startsWith("/alc-internal-proxy/")) {
        return handleAlcInternalProxy(request, env);
      }

      // rust-alc-api#434 followup: 無人デバイス (browser-render-rust の Kagoya VPS
      // cron 等) が device JWT (`/device/token` 発行) で data 経路 (require_tenant_header)
      // を叩く経路。tenant は device pairing 時に確定済み (client からは詐称不能)。
      if (url.pathname.startsWith("/device-data-proxy/")) {
        return handleDeviceDataProxy(request, env);
      }

      // ohishi-exp/ohishi-logi#1 / ippoan/cf-flickr-cam-worker#1: cf-flickr-cam-worker
      // (無人 cron) が device JWT で ohishi-logi (無状態 camera fetcher) の
      // `/cam/*` RPC を叩く経路。device-data-proxy と同パターンだが tenant 束縛は無い。
      if (url.pathname.startsWith("/ohishi-logi-proxy/")) {
        return handleOhishiLogiProxy(request, env);
      }

      // ippoan/cf-flickr-cam-worker#3, #4: Flickr OAuth1.0a callback (ブラウザ
      // 経由リダイレクト) + 運用者向け UI を公開するための唯一の到達経路。
      // CF Access Application が edge で path-scoped 保護する (handler 側は
      // 認証を検証しない、境界は CF Access 側)。末尾スラッシュ無し (bare prefix)
      // もトップページ (`/`) 相当として受け付ける (Refs #16)。
      if (
        url.pathname === "/cf-flickr-cam-worker-proxy" ||
        url.pathname.startsWith("/cf-flickr-cam-worker-proxy/")
      ) {
        return handleCfFlickrCamWorkerProxy(request, env);
      }

      // admin/notify ページ用 rust forward proxy (#434)。ページ client JS が
      // 同一オリジンで叩き、ここで JWT 検証 + X-Tenant-ID 注入して rust へ転送する。
      if (url.pathname.startsWith("/admin/notify/api/")) {
        return handleAdminNotifyApi(request, env);
      }

      if (request.method === "GET") {
        // issue #144: 1-click pair の claim endpoint。`/mcp/pair/<code>` を
        // ブラウザが踏むと cookie verify → KV approve → success HTML。
        // cookie 不在なら GitHub OAuth に飛ばし、`/mcp/pair_callback` で
        // cookie 確立後にこの URL に戻ってくる。
        if (url.pathname.startsWith("/mcp/pair/")) {
          const rest = url.pathname.slice("/mcp/pair/".length);
          // `/mcp/pair/new` は POST 専用 (relay host にも置いた)。GET で来たら 405。
          if (rest === "new") {
            return errorResponse(405, "Method not allowed");
          }
          if (rest && !rest.includes("/")) {
            return await handleMcpPairClaim(request, env, rest);
          }
          return errorResponse(404, "Not found");
        }
        // Dynamic path: /join/:slug and /join/:slug/done
        if (url.pathname.startsWith("/join/")) {
          const parts = url.pathname.split("/");
          const slug = parts[2];
          if (parts.length === 3 && slug) {
            return await handleJoinPage(request, env, slug);
          }
          if (parts.length === 4 && parts[3] === "done" && slug) {
            return handleJoinDone(slug);
          }
          return errorResponse(404, "Not found");
        }

        // Per-resource Protected Resource Metadata (RFC 9728) — switch では
        // 末尾 segment が動的なため prefix で先取りする (slug は handler 側で
        // MCP_RESOURCE_ORIGINS_ALLOWLIST 突合して 404 か正常応答かを判定)。
        // base path 単体は下の switch case でそのまま受ける。
        if (url.pathname.startsWith("/.well-known/oauth-protected-resource/")) {
          return handleMcpResourceMetadata(request, env);
        }

        switch (url.pathname) {
          case "/api/health":
            return await handleHealthProxy(env);
          // issue #209: OAuth client_id 死活チェック (Bearer JWT 必須)。
          // /api/health (ALC proxy) と分離した独立ハンドラ。
          case "/health/oauth":
            return await handleHealthOAuth(request, env);
          // Refs ippoan/auth-worker#274 / ippoan/email-receiver#1: 任意 env /
          // Secrets Store binding の sha256[0..8] が `expected` と一致するかを
          // {match: bool} で返す。CI drift-check (ippoan/ci-workflows
          // drift-check.yml) が GCP SM 値の hash を投げてくる入口。
          case "/health/secret-fingerprint":
            return await handleSecretFingerprint(request, env);
          // Refs ippoan/rust-alc-api#434 step 3: OIDC mint (run.invoker SA key)
          // が生きているかの死活チェック (Bearer JWT 必須)。Cloud Run IAM
          // lockdown 後に data-proxy が backend へ到達できるかと等価。
          case "/health/wif":
            return await handleHealthWif(request, env);
          case "/login":
            return await handleLoginPage(request, env);
          case "/top":
            return await handleTopPage(request, env);
          case "/auth/callback":
            return handleAuthCallback();
          case "/oauth/google/redirect":
            return await handleGoogleRedirect(request, env);
          case "/oauth/google/callback":
            return await handleGoogleCallback(request, env);
          case "/oauth/egov/redirect":
            return await handleEgovRedirect(request, env);
          case "/oauth/egov/callback":
            return await handleEgovCallback(request, env);
          // Google Health API OAuth pass-through for hcreader-worker.
          // Refs ippoan/HealthConnectReaderWorker#60, #61
          case "/oauth/ghapi/redirect":
            return await handleGhapiRedirect(request, env);
          case "/oauth/ghapi/callback":
            return await handleGhapiCallback(request, env);
          case "/oauth/lineworks/redirect":
            return await handleLineworksRedirect(request, env);
          case "/oauth/lineworks/callback":
            return await handleLineworksCallback(request, env);
          case "/oauth/line/redirect":
            return await handleLineRedirect(request, env);
          case "/oauth/line/callback":
            return await handleLineCallback(request, env);
          case "/oauth/line/select-tenant":
            return await handleLineSelectTenant(request, env);
          case "/auth/woff-config":
            return await handleWoffConfig(request, env);
          case "/admin/sso":
            return await handleAdminSsoPage(request, env);
          case "/admin/sso/callback":
            return await handleAdminSsoCallback();
          case "/admin/users":
            return await handleAdminUsersPage(request, env);
          case "/admin/users/callback":
            return await handleAdminUsersCallback();
          case "/admin/rich-menu":
            return await handleAdminRichMenuPage(request, env);
          case "/admin/rich-menu/callback":
            return await handleAdminRichMenuCallback();
          case "/admin/requests":
            return await handleAdminRequestsPage(request, env);
          case "/admin/requests/callback":
            return await handleAdminRequestsCallback();
          case "/admin/notify":
            return await handleAdminNotifyPage(request, env);
          case "/admin/notify/callback":
            return await handleAdminNotifyCallback();
          case "/admin/line-users":
            return await handleAdminLineUsersPage(request, env);
          case "/admin/line-users/callback":
            return await handleAdminLineUsersCallback();
          case "/api/bot-config/export":
            return await handleBotConfigExport(request, env);
          case "/redirect":
            return await handleRedirect(request, env);
          case "/logout":
            return await handleLogout(request, env);
          // MCP OAuth Provider — AS metadata (RFC 8414)
          case "/.well-known/oauth-authorization-server":
            return handleMcpAsMetadata(request, env);
          // MCP OAuth Provider — Protected Resource metadata (RFC 9728, Phase 4 / issue #126)
          // client は MCP relay URL の 401 応答 `WWW-Authenticate.resource_metadata`
          // 経由で本 endpoint を踏み、authorization_servers から AS metadata を発見する
          case "/.well-known/oauth-protected-resource":
            return handleMcpResourceMetadata(request, env);
          // MCP OAuth Provider — Device authorization page (RFC 8628 §3.3)
          case "/device":
            return handleMcpDevicePage(request, env);
          // Phase 2.5 (ohishi-exp/smb-watch#1): headless pairing 承認ページ。
          case "/device/pair/approve":
            return await handleDevicePairApprovePage(request, env);
          // CoreS3 の USB provisioning ページ (WebSerial、Refs #365)。
          case "/device/setup":
            return await handleDeviceSetupPage(request, env);
          // 登録済みデバイス一覧 (cookie session、ページの表示用)。
          case "/device/setup/list":
            return await handleDeviceSetupList(request, env);
          // MCP OAuth Provider — GitHub OAuth callback (Phase 3, RFC 8628 §3.4)
          case "/mcp/device_callback":
            return await handleMcpDeviceCallback(request, env);
          // MCP OAuth Provider — Authorization Code flow start (Phase 5 / issue #128)
          case "/mcp/authorize":
            return await handleMcpAuthorize(request, env);
          // MCP OAuth Provider — Authorization Code GitHub OAuth callback (Phase 5)
          case "/mcp/auth_callback":
            return await handleMcpAuthCallback(request, env);
          // MCP OAuth Provider — 1-click pair GitHub OAuth callback (issue #144)
          case "/mcp/pair_callback":
            return await handleMcpPairCallback(request, env);
          // Phase 1 admin auth (issue #42 follow-up) — browser elevate start
          case "/mcp/elevate":
            return await handleMcpElevateStart(request, env);
          // Phase 1 admin auth — browser elevate GitHub OAuth callback
          case "/mcp/elevate_callback":
            return await handleMcpElevateCallback(request, env);
          // issue #159 Phase 1: branch-protection dashboard.
          case "/dashboard/branch-protection":
            return await handleDashboardBranchProtection(request, env);
          case "/api/dashboard/repos":
            return await handleApiDashboardListRepos(request, env);
          default: {
            // issue #159 Phase 1: API path `/api/dashboard/repos/:owner/:repo/protection`
            // は default 句で dynamic match する。GET は未対応 (Phase 1 では POST/DELETE のみ)。
            if (url.pathname.startsWith("/api/dashboard/repos/")) {
              return errorResponse(405, "Method not allowed");
            }
            return errorResponse(404, "Not found");
          }
        }
      }

      if (request.method === "POST") {
        // issue #159 Phase 1: dashboard preset apply — POST
        // /api/dashboard/repos/:owner/:repo/protection
        {
          const m = /^\/api\/dashboard\/repos\/([^/]+)\/([^/]+)\/protection$/.exec(
            url.pathname,
          );
          if (m && m[1] && m[2]) {
            return await handleApiDashboardApplyProtection(request, env, m[1], m[2]);
          }
        }
        // issue #159 Phase 2 follow-up: turn on allow_auto_merge +
        // delete_branch_on_merge — POST /api/dashboard/repos/:o/:r/fix-settings
        {
          const m = /^\/api\/dashboard\/repos\/([^/]+)\/([^/]+)\/fix-settings$/.exec(
            url.pathname,
          );
          if (m && m[1] && m[2]) {
            return await handleApiDashboardFixRepoSettings(request, env, m[1], m[2]);
          }
        }
        // Dynamic path: /lineworks/webhook/:bot_id (LINE WORKS callback)
        if (url.pathname.startsWith("/lineworks/webhook/")) {
          const botId = url.pathname.slice("/lineworks/webhook/".length);
          return await handleLineworksWebhook(request, env, botId);
        }
        // Dynamic path: /lineworks/refresh/:bot_id (DO bot_secret cache invalidation, internal)
        if (url.pathname.startsWith("/lineworks/refresh/")) {
          const botId = url.pathname.slice("/lineworks/refresh/".length);
          return await handleLineworksRefresh(request, env, botId);
        }
        // LINE Messaging inbound webhook (#434 lockdown): LINE platform → auth-worker
        // public 受け口 → OIDC mint で rust internal (/api/internal/notify/line/webhook)
        // へ raw body + x-line-signature を forward。署名検証は rust 側。
        if (url.pathname === "/line/webhook" && request.method === "POST") {
          return await handleLineWebhook(request, env);
        }

        switch (url.pathname) {
          case "/api/sso/list":
            return await handleSsoList(request, env);
          case "/api/sso/upsert":
            return await handleSsoUpsert(request, env);
          case "/api/sso/delete":
            return await handleSsoDelete(request, env);
          case "/api/line-users/list":
            return await handleLineUsersList(request, env);
          case "/api/line-users/delete":
            return await handleLineUserDelete(request, env);
          // Bot Config API
          case "/api/bot-config/list":
            return await handleBotConfigList(request, env);
          case "/api/bot-config/upsert":
            return await handleBotConfigUpsert(request, env);
          case "/api/bot-config/delete":
            return await handleBotConfigDelete(request, env);
          case "/api/bot-config/import":
            return await handleBotConfigImport(request, env);
          // User Management API
          case "/api/users/list":
            return await handleUsersList(request, env);
          case "/api/users/invitations":
            return await handleInvitationsList(request, env);
          case "/api/users/invite":
            return await handleInviteUser(request, env);
          case "/api/users/invite/delete":
            return await handleDeleteInvitation(request, env);
          case "/api/users/delete":
            return await handleDeleteUser(request, env);
          // WOFF Auth
          case "/auth/woff":
            return await handleWoffAuth(request, env);
          // Password login
          case "/auth/login":
            return await handleAuthLogin(request, env);
          // Browser JWT introspection (issue #290) — server-proxy consumer 用に
          // 署名検証 + APP_TENANT_ACL 判定を auth-worker に集約する。
          case "/auth/introspect":
            return await handleAuthIntrospect(request, env);
          // Phase 2 (ohishi-exp/smb-watch#1): 無人デバイス向け device-token。
          // pair/revoke は operator の Bearer session、token は box の device credential。
          case "/device/pair":
            return await handleDevicePair(request, env);
          // rust-alc-api#434 caller #5: alc-app が claim 中に server-to-server で
          // device credential を発行する (operator session 不要、shared-secret 認証)。
          case "/device/pair-internal":
            return await handleDevicePairInternal(request, env);
          case "/device/token":
            return await handleDeviceToken(request, env);
          case "/device/revoke":
            return await handleDeviceRevoke(request, env);
          // CoreS3 の USB provisioning: browser (cookie session) からの credential mint。
          case "/device/setup/pair":
            return await handleDeviceSetupPair(request, env);
          // Phase 2.5 (ohishi-exp/smb-watch#1): headless pairing (box ↔ operator)。
          case "/device/pair/start":
            return await handleDevicePairStart(request, env);
          case "/device/pair/approve":
            return await handleDevicePairApprove(request, env);
          case "/device/pair/token":
            return await handleDevicePairToken(request, env);
          // Rich Menu API
          case "/api/richmenu/list":
            return await handleRichMenuList(request, env);
          case "/api/richmenu/create":
            return await handleRichMenuCreate(request, env);
          case "/api/richmenu/delete":
            return await handleRichMenuDelete(request, env);
          case "/api/richmenu/image":
            return await handleRichMenuImageUpload(request, env);
          case "/api/richmenu/default/set":
            return await handleRichMenuDefaultSet(request, env);
          case "/api/richmenu/default/delete":
            return await handleRichMenuDefaultDelete(request, env);
          // Access Request API
          case "/api/access-requests/create":
            return await handleAccessRequestCreate(request, env);
          case "/api/access-requests/list":
            return await handleAccessRequestList(request, env);
          case "/api/access-requests/approve":
            return await handleAccessRequestApprove(request, env);
          case "/api/access-requests/decline":
            return await handleAccessRequestDecline(request, env);
          // Organization API
          case "/api/switch-org":
            return await handleSwitchOrg(request, env);
          case "/api/my-orgs":
            return await handleMyOrgs(request, env);
          // MCP OAuth Provider — Device Authorization (RFC 8628 §3.1)
          case "/mcp/device_authorization":
            return await handleMcpDeviceAuthorization(request, env);
          // MCP OAuth Provider — Device verify / proceed (RFC 8628 §3.3)
          case "/device/verify":
            return await handleMcpDeviceVerify(request, env);
          case "/device/proceed":
            return await handleMcpDeviceProceed(request, env);
          // MCP OAuth Provider — Token endpoint (Phase 3 device_code/refresh + Phase 5 authorization_code)
          case "/mcp/token":
            return await handleMcpToken(request, env);
          // MCP OAuth Provider — Dynamic Client Registration (Phase 5 / issue #128, RFC 7591)
          case "/mcp/register":
            return await handleMcpRegister(request, env);
          // MCP OAuth Provider — Token Introspection (Phase 5, RFC 7662 + GitHub token 返却)
          case "/mcp/introspect":
            return await handleMcpIntrospect(request, env);
          // MCP OAuth Provider — Binary recovery pickup for elevated JWTs.
          // `/mcp/elevate` 完了時に mint された fresh pair を、binary が
          // (signature-only verified) JWT で 1 回だけ取りに来る用。
          case "/mcp/jwt/pickup":
            return await handleMcpJwtPickup(request, env);
          // MCP OAuth Provider — Token Revocation (RFC 7009, issue #145)
          case "/mcp/revoke":
            return await handleMcpRevoke(request, env);
          // issue #157 Phase B: refresh_token → binding_jwt 交換 endpoint
          // (debug / curl 用に auth host にも置く。binary は通常 relay host 経由)。
          case "/mcp/pair/grant":
            return await handleMcpPairGrant(request, env);
          // issue ippoan/mcp-relay-rs#15: GitHub OAuth token → binding_jwt
          // (debug / curl 用に auth host にも置く。binary は relay host 経由)。
          case "/mcp/pair/grant-via-github":
            return await handleMcpPairGrantViaGithub(request, env);
          // issue ippoan/auth-worker#174: Anthropic OAT → binding_jwt (KV-bound)
          // (debug / curl 用に auth host にも置く。binary は relay host 経由)。
          case "/mcp/pair/grant-via-oat":
            return await handleMcpPairGrantViaOat(request, env);
          // issue ippoan/auth-worker#174: register OAT_hash → github_login via
          // GitHub issue-comment identity proof (debug / curl 用 dual placement)。
          case "/mcp/pair/register-via-github-comment":
            return await handleMcpPairRegisterViaGithubComment(request, env);
          // MCP OAuth Provider — Native MCP JSON-RPC tools (issue #145)
          // auth host 上でも受けることで binary なしで MCP server として機能する。
          // 同じ handler は dispatchMcpRelay (mcp.ippoan.org host) 経由でも到達可能。
          case "/mcp/tools":
            return await handleMcpTools(request, env);
          // Phase 1 admin auth (issue #42 follow-up) — binary-facing admin proxy。
          // MCP JWT + KV elevate flag で gate して GitHub App installation token
          // 経由で branch protection 系を実行する。
          case "/mcp/admin/exec":
            return await handleMcpAdminExec(request, env);
          default:
            return errorResponse(404, "Not found");
        }
      }

      // CORS preflight
      if (request.method === "OPTIONS") {
        return corsPreflight();
      }

      // issue #159 Phase 1: dashboard preset remove — DELETE
      // /api/dashboard/repos/:owner/:repo/protection
      if (request.method === "DELETE") {
        const m = /^\/api\/dashboard\/repos\/([^/]+)\/([^/]+)\/protection$/.exec(
          url.pathname,
        );
        if (m && m[1] && m[2]) {
          return await handleApiDashboardRemoveProtection(request, env, m[1], m[2]);
        }
        return errorResponse(404, "Not found");
      }

      return errorResponse(405, "Method not allowed");
    } catch (err) {
      console.error(JSON.stringify({
        event: "unhandled_error",
        method: request.method,
        path: url.pathname,
        error: err instanceof Error ? err.message : String(err),
        stack: err instanceof Error ? err.stack : undefined,
      }));
      return errorResponse(
        500,
        err instanceof Error ? err.message : "Internal server error",
      );
    }
  },
};
