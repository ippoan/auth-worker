import { handleLoginPage } from "./handlers/login-page";
import { handleAuthLogin } from "./handlers/login-api";
import { handleGoogleRedirect } from "./handlers/google-redirect";
import { handleGoogleCallback } from "./handlers/google-callback";
import { handleEgovRedirect } from "./handlers/egov-redirect";
import { handleEgovCallback } from "./handlers/egov-callback";
import { handleLineworksRedirect } from "./handlers/lineworks-redirect";
import { handleLineworksCallback } from "./handlers/lineworks-callback";
import { handleAdminSsoPage, handleAdminSsoCallback } from "./handlers/admin-sso";
import { handleAdminUsersPage, handleAdminUsersCallback } from "./handlers/admin-users";
import { handleSsoList, handleSsoUpsert, handleSsoDelete } from "./handlers/api-sso";
import { handleBotConfigList, handleBotConfigUpsert, handleBotConfigDelete, handleBotConfigExport, handleBotConfigImport } from "./handlers/api-bot-config";
import { handleWoffAuth, handleWoffConfig } from "./handlers/woff-auth";
import { handleMyOrgs } from "./handlers/api-my-orgs";
import { handleSwitchOrg } from "./handlers/api-switch-org";
import {
  handleRichMenuList, handleRichMenuCreate, handleRichMenuDelete,
  handleRichMenuImageUpload, handleRichMenuDefaultSet, handleRichMenuDefaultDelete,
} from "./handlers/api-rich-menu";
import { handleAdminRichMenuPage, handleAdminRichMenuCallback } from "./handlers/admin-rich-menu";
import { handleTopPage } from "./handlers/top-page";
import { handleHealthProxy } from "./handlers/health";
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
import { handleMcpAsMetadata } from "./handlers/mcp-as-metadata";
import { handleMcpResourceMetadata } from "./handlers/mcp-resource-metadata";
import { handleMcpDeviceAuthorization } from "./handlers/mcp-device-authorization";
import { handleMcpDevicePage } from "./handlers/mcp-device-page";
import { handleMcpDeviceVerify } from "./handlers/mcp-device-verify";
import { handleMcpDeviceProceed } from "./handlers/mcp-device-proceed";
import { handleMcpDeviceCallback } from "./handlers/mcp-device-callback";
import { handleMcpToken } from "./handlers/mcp-token";
import { handleMcpIntrospect } from "./handlers/mcp-introspect";
import { handleMcpRelayConnect } from "./handlers/mcp-relay-connect";
import { handleMcpRelayBridge, handleMcpRelaySse } from "./handlers/mcp-relay-bridge";
import { handleMcpRegister } from "./handlers/mcp-register";
import { handleMcpAuthorize } from "./handlers/mcp-authorize";
import { handleMcpAuthCallback } from "./handlers/mcp-auth-callback";
import { handleMcpPairNew } from "./handlers/mcp-pair-new";
import { handleMcpPairClaim } from "./handlers/mcp-pair-claim";
import { handleMcpPairCallback } from "./handlers/mcp-pair-callback";
import { handleMcpTools } from "./handlers/mcp-tools";
import { handleMcpRevoke } from "./handlers/mcp-revoke";
import { handleGithubWebhook } from "./handlers/github-webhook";
import { handleMcpElevateStart, handleMcpElevateCallback } from "./handlers/mcp-elevate";
import { handleMcpAdminExec } from "./handlers/mcp-admin-exec";
export { LineworksWebhookDO } from "./durable_objects/lineworks-webhook-do";
export { McpSession } from "./durable_objects/mcp-session-do";

export interface Env {
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  OAUTH_STATE_SECRET: string;
  AUTH_WORKER_ORIGIN: string;
  ALC_API_ORIGIN: string;
  /** staging Cloud Run の rust-alc-api。Bot Config Import (developer 専用) 用 proxy 先。
   *  未設定なら handler 内で本番 staging URL に fallback する。 */
  ALC_API_STAGING_ORIGIN?: string;
  VERSION: string;
  WORKER_ENV: string;
  AUTH_CONFIG: KVNamespace;
  /** HS256 JWT secret, shared with rust-alc-api. Used by /top to verify the
   *  `logi_auth_token` cookie before serving the page. Missing → /top
   *  redirects everyone to /login (fail-closed). */
  JWT_SECRET: string;
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
  /** AES-256-GCM 鍵素材 (rust-alc-api と共有)。bot_secret_encrypted の復号で SHA-256(SSO_ENCRYPTION_KEY) を 32B 鍵として使う。 */
  SSO_ENCRYPTION_KEY: string;
  /** LINE WORKS webhook 受信用 Durable Object Namespace (bot_id ごとに 1 instance)。 */
  LINEWORKS_WEBHOOK_DO: DurableObjectNamespace;
  /** MCP OAuth Provider 用 GitHub OAuth App credentials.
   *  staging/prod で別 App (callback URL が異なるため)。 */
  GITHUB_MCP_CLIENT_ID?: string;
  GITHUB_MCP_CLIENT_SECRET?: string;
  /** HS256 secret for MCP access tokens (JWT)。既存 JWT_SECRET とは別管理。
   *  Phase 1+ で MCP endpoint が実装されるまでは未参照。 */
  MCP_JWT_SECRET?: string;
  /** Rust binary (github-mcp-server-rs) が /mcp/introspect 叩く際の認証用。
   *  Bearer header で送られる固定共有鍵。 */
  INTERNAL_SHARED_SECRET?: string;
  /** JSON array of github logins allowed to use MCP server.
   *  Example: `["yhonda-ohishi"]`. Missing / malformed → deny all (fail-closed). */
  GITHUB_MCP_USER_ALLOWLIST?: string;
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
   *  同じ値を使う。 */
  GITHUB_WEBHOOK_SECRET?: string;
  /** issue #144: 1-click pair flow 用の auth-worker ブラウザ session cookie 署名鍵。
   *  既存 `MCP_JWT_SECRET` と分けるのは scope を局所化するため (pair session が
   *  漏洩しても device-flow JWT には影響しない)。未設定 → /mcp/pair/* は 503。 */
  SESSION_COOKIE_SECRET?: string;
  /** Phase 1 admin auth: JSON array of github logins allowed to elevate.
   *  `["yhonda-ohishi"]` 等。missing / malformed → fail-closed (admin 不可)。 */
  MCP_ADMIN_ALLOWLIST?: string;
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

        switch (url.pathname) {
          case "/api/health":
            return await handleHealthProxy(env);
          case "/login":
            return await handleLoginPage(request, env);
          case "/top":
            return await handleTopPage(request, env);
          case "/oauth/google/redirect":
            return await handleGoogleRedirect(request, env);
          case "/oauth/google/callback":
            return await handleGoogleCallback(request, env);
          case "/oauth/egov/redirect":
            return await handleEgovRedirect(request, env);
          case "/oauth/egov/callback":
            return await handleEgovCallback(request, env);
          case "/oauth/lineworks/redirect":
            return await handleLineworksRedirect(request, env);
          case "/oauth/lineworks/callback":
            return await handleLineworksCallback(request, env);
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
          default:
            return errorResponse(404, "Not found");
        }
      }

      if (request.method === "POST") {
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

        switch (url.pathname) {
          case "/api/sso/list":
            return await handleSsoList(request, env);
          case "/api/sso/upsert":
            return await handleSsoUpsert(request, env);
          case "/api/sso/delete":
            return await handleSsoDelete(request, env);
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
          // MCP OAuth Provider — Token Revocation (RFC 7009, issue #145)
          case "/mcp/revoke":
            return await handleMcpRevoke(request, env);
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
