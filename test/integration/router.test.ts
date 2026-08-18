import { describe, it, expect, vi, beforeEach } from "vitest";
import { TEST_JWT_SECRET, createMockDONamespace } from "../helpers/mock-env";

// Mock handler modules
vi.mock("../../src/handlers/api-sso", () => ({
  handleSsoList: vi.fn(() => new Response("sso-list")),
  handleSsoUpsert: vi.fn(() => new Response("sso-upsert")),
  handleSsoDelete: vi.fn(() => new Response("sso-delete")),
}));
vi.mock("../../src/handlers/api-bot-config", () => ({
  handleBotConfigList: vi.fn(() => new Response("bot-list")),
  handleBotConfigUpsert: vi.fn(() => new Response("bot-upsert")),
  handleBotConfigDelete: vi.fn(() => new Response("bot-delete")),
  handleBotConfigExport: vi.fn(() => new Response("bot-export")),
  handleBotConfigImport: vi.fn(() => new Response("bot-import")),
}));
vi.mock("../../src/handlers/api-users", () => ({
  handleUsersList: vi.fn(() => new Response("users-list")),
  handleInvitationsList: vi.fn(() => new Response("inv-list")),
  handleInviteUser: vi.fn(() => new Response("invite")),
  handleDeleteInvitation: vi.fn(() => new Response("del-inv")),
  handleDeleteUser: vi.fn(() => new Response("del-user")),
}));
vi.mock("../../src/handlers/health", () => ({
  handleHealthProxy: vi.fn(() => new Response(JSON.stringify({ status: "ok" }), {
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  })),
}));
vi.mock("../../src/handlers/health-oauth", () => ({
  handleHealthOAuth: vi.fn(() => new Response("health-oauth")),
}));
vi.mock("../../src/handlers/login-page", () => ({
  handleLoginPage: vi.fn(() => new Response("login-page")),
}));
vi.mock("../../src/handlers/login-api", () => ({
  handleAuthLogin: vi.fn(() => new Response("auth-login")),
}));
vi.mock("../../src/handlers/top-page", () => ({
  handleTopPage: vi.fn(() => new Response("top-page")),
}));
vi.mock("../../src/handlers/google-redirect", () => ({
  handleGoogleRedirect: vi.fn(() => new Response("google-redirect")),
}));
vi.mock("../../src/handlers/google-callback", () => ({
  handleGoogleCallback: vi.fn(() => new Response("google-callback")),
}));
vi.mock("../../src/handlers/lineworks-redirect", () => ({
  handleLineworksRedirect: vi.fn(() => new Response("lw-redirect")),
}));
vi.mock("../../src/handlers/lineworks-callback", () => ({
  handleLineworksCallback: vi.fn(() => new Response("lw-callback")),
}));
vi.mock("../../src/handlers/egov-redirect", () => ({
  handleEgovRedirect: vi.fn(() => new Response("egov-redirect")),
}));
vi.mock("../../src/handlers/egov-callback", () => ({
  handleEgovCallback: vi.fn(() => new Response("egov-callback")),
}));
vi.mock("../../src/handlers/ghapi-redirect", () => ({
  handleGhapiRedirect: vi.fn(() => new Response("ghapi-redirect")),
}));
vi.mock("../../src/handlers/ghapi-callback", () => ({
  handleGhapiCallback: vi.fn(() => new Response("ghapi-callback")),
}));
vi.mock("../../src/handlers/woff-auth", () => ({
  handleWoffAuth: vi.fn(() => new Response("woff-auth")),
  handleWoffConfig: vi.fn(() => new Response("woff-config")),
}));
vi.mock("../../src/handlers/admin-sso", () => ({
  handleAdminSsoPage: vi.fn(() => new Response("admin-sso")),
  handleAdminSsoCallback: vi.fn(() => new Response("admin-sso-cb")),
}));
vi.mock("../../src/handlers/admin-users", () => ({
  handleAdminUsersPage: vi.fn(() => new Response("admin-users")),
  handleAdminUsersCallback: vi.fn(() => new Response("admin-users-cb")),
}));
vi.mock("../../src/handlers/admin-rich-menu", () => ({
  handleAdminRichMenuPage: vi.fn(() => new Response("admin-rich-menu")),
  handleAdminRichMenuCallback: vi.fn(() => new Response("admin-rich-menu-cb")),
}));
vi.mock("../../src/handlers/admin-requests", () => ({
  handleAdminRequestsPage: vi.fn(() => new Response("admin-requests")),
  handleAdminRequestsCallback: vi.fn(() => new Response("admin-requests-cb")),
}));
vi.mock("../../src/handlers/admin-notify", () => ({
  handleAdminNotifyPage: vi.fn(() => new Response("admin-notify")),
  handleAdminNotifyCallback: vi.fn(() => new Response("admin-notify-cb")),
}));
vi.mock("../../src/handlers/logout", () => ({
  handleLogout: vi.fn(() => new Response("logout")),
}));
vi.mock("../../src/handlers/api-my-orgs", () => ({
  handleMyOrgs: vi.fn(() => new Response("my-orgs")),
}));
vi.mock("../../src/handlers/api-switch-org", () => ({
  handleSwitchOrg: vi.fn(() => new Response("switch-org")),
}));
vi.mock("../../src/handlers/api-rich-menu", () => ({
  handleRichMenuList: vi.fn(() => new Response("rm-list")),
  handleRichMenuCreate: vi.fn(() => new Response("rm-create")),
  handleRichMenuDelete: vi.fn(() => new Response("rm-delete")),
  handleRichMenuImageUpload: vi.fn(() => new Response("rm-image")),
  handleRichMenuDefaultSet: vi.fn(() => new Response("rm-default-set")),
  handleRichMenuDefaultDelete: vi.fn(() => new Response("rm-default-delete")),
}));
vi.mock("../../src/handlers/api-access-requests", () => ({
  handleAccessRequestCreate: vi.fn(() => new Response("ar-create")),
  handleAccessRequestList: vi.fn(() => new Response("ar-list")),
  handleAccessRequestApprove: vi.fn(() => new Response("ar-approve")),
  handleAccessRequestDecline: vi.fn(() => new Response("ar-decline")),
}));
vi.mock("../../src/handlers/redirect", () => ({
  handleRedirect: vi.fn(() => new Response("redirect")),
}));
vi.mock("../../src/handlers/join-page", () => ({
  handleJoinPage: vi.fn(() => new Response("join-page")),
}));
vi.mock("../../src/handlers/join-callback", () => ({
  handleJoinDone: vi.fn(() => new Response("join-done")),
}));
vi.mock("../../src/handlers/lineworks-webhook", () => ({
  handleLineworksWebhook: vi.fn((_req, _env, botId: string) =>
    new Response(`lw-webhook:${botId}`),
  ),
  handleLineworksRefresh: vi.fn((_req, _env, botId: string) =>
    new Response(`lw-refresh:${botId}`),
  ),
}));
vi.mock("../../src/handlers/line-webhook", () => ({
  handleLineWebhook: vi.fn(() => new Response("line-webhook")),
}));
vi.mock("../../src/handlers/oidc-jwks", () => ({
  handleOidcJwks: vi.fn(() => new Response("oidc-jwks")),
}));
vi.mock("../../src/handlers/mcp-as-metadata", () => ({
  handleMcpAsMetadata: vi.fn(() => new Response("mcp-as-metadata")),
}));
vi.mock("../../src/handlers/mcp-resource-metadata", () => ({
  handleMcpResourceMetadata: vi.fn(() => new Response("mcp-resource-metadata")),
}));
vi.mock("../../src/handlers/mcp-register", () => ({
  handleMcpRegister: vi.fn(() => new Response("mcp-register")),
}));
vi.mock("../../src/handlers/mcp-authorize", () => ({
  handleMcpAuthorize: vi.fn(() => new Response("mcp-authorize")),
}));
vi.mock("../../src/handlers/mcp-auth-callback", () => ({
  handleMcpAuthCallback: vi.fn(() => new Response("mcp-auth-callback")),
}));
vi.mock("../../src/handlers/mcp-device-authorization", () => ({
  handleMcpDeviceAuthorization: vi.fn(() => new Response("mcp-device-authorization")),
}));
vi.mock("../../src/handlers/mcp-device-page", () => ({
  handleMcpDevicePage: vi.fn(() => new Response("mcp-device-page")),
}));
vi.mock("../../src/handlers/mcp-device-verify", () => ({
  handleMcpDeviceVerify: vi.fn(() => new Response("mcp-device-verify")),
}));
vi.mock("../../src/handlers/mcp-device-proceed", () => ({
  handleMcpDeviceProceed: vi.fn(() => new Response("mcp-device-proceed")),
}));
vi.mock("../../src/handlers/mcp-device-callback", () => ({
  handleMcpDeviceCallback: vi.fn(() => new Response("mcp-device-callback")),
}));
vi.mock("../../src/handlers/mcp-token", () => ({
  handleMcpToken: vi.fn(() => new Response("mcp-token")),
}));
vi.mock("../../src/handlers/mcp-introspect", () => ({
  handleMcpIntrospect: vi.fn(() => new Response("mcp-introspect")),
}));
vi.mock("../../src/handlers/mcp-jwt-pickup", () => ({
  handleMcpJwtPickup: vi.fn(() => new Response("mcp-jwt-pickup")),
}));
vi.mock("../../src/handlers/mcp-tools", () => ({
  handleMcpTools: vi.fn(() => new Response("mcp-tools")),
}));
vi.mock("../../src/handlers/dev-login-token", () => ({
  handleDevLoginToken: vi.fn(() => new Response("dev-login-token")),
}));
vi.mock("../../src/handlers/mcp-revoke", () => ({
  handleMcpRevoke: vi.fn(() => new Response("mcp-revoke")),
}));
// ADR-003: handler signature now accepts `string | null`. The mock tags the
// user-less variant as `(jwt)` so the dispatch tests can tell the two
// callsites apart.
vi.mock("../../src/handlers/mcp-relay-connect", () => ({
  handleMcpRelayConnect: vi.fn((_req, _env, user: string | null) =>
    new Response(`relay-connect:${user ?? "(jwt)"}`),
  ),
}));
vi.mock("../../src/handlers/mcp-relay-bridge", () => ({
  handleMcpRelayBridge: vi.fn((_req, _env, user: string | null) =>
    new Response(`relay-bridge:${user ?? "(jwt)"}`),
  ),
  // ADR-004 Phase D: GET /mcp → SSE stream handler。本 integration test では
  // dispatchMcpRelay の routing 経路だけ検証すればよく、SSE body は不要。
  handleMcpRelaySse: vi.fn((_req, _env, user: string | null) =>
    new Response(`relay-sse:${user ?? "(jwt)"}`),
  ),
}));
// ADR-004 (multiplex): GitHub webhook receiver。専用 IssueRoom route は
// 廃止し、既存 McpSession DO に push する形に変更されたので handler は 1 つ。
vi.mock("../../src/handlers/github-webhook", () => ({
  handleGithubWebhook: vi.fn(() => new Response("github-webhook")),
}));
// issue #144: 1-click pair endpoints (consumer side: github-mcp-server-rs#42)。
// integration test では routing 経路だけ検証すればよく、本物の KV / OAuth は不要。
vi.mock("../../src/handlers/mcp-pair-new", () => ({
  handleMcpPairNew: vi.fn(() => new Response("mcp-pair-new")),
}));
vi.mock("../../src/handlers/device", () => ({
  handleDevicePair: vi.fn(() => new Response("device-pair")),
  handleDeviceToken: vi.fn(() => new Response("device-token")),
  handleDeviceRevoke: vi.fn(() => new Response("device-revoke")),
}));
vi.mock("../../src/handlers/device-pair", () => ({
  handleDevicePairStart: vi.fn(() => new Response("device-pair-start")),
  handleDevicePairApprovePage: vi.fn(() => new Response("device-pair-approve-page")),
  handleDevicePairApprove: vi.fn(() => new Response("device-pair-approve")),
  handleDevicePairToken: vi.fn(() => new Response("device-pair-token")),
}));
vi.mock("../../src/handlers/auth-introspect", () => ({
  handleAuthIntrospect: vi.fn(() => new Response("auth-introspect")),
}));
vi.mock("../../src/handlers/health-fingerprints", () => ({
  handleSecretFingerprint: vi.fn(() => new Response("secret-fingerprint")),
}));
vi.mock("../../src/handlers/mcp-pair-claim", () => ({
  handleMcpPairClaim: vi.fn((_req, _env, code: string) =>
    new Response(`mcp-pair-claim:${code}`),
  ),
}));
vi.mock("../../src/handlers/mcp-pair-callback", () => ({
  handleMcpPairCallback: vi.fn(() => new Response("mcp-pair-callback")),
}));
vi.mock("../../src/handlers/mcp-pair-grant", () => ({
  handleMcpPairGrant: vi.fn(() => new Response("mcp-pair-grant")),
}));
vi.mock("../../src/handlers/mcp-pair-grant-via-github", () => ({
  handleMcpPairGrantViaGithub: vi.fn(
    () => new Response("mcp-pair-grant-via-github"),
  ),
}));
// issue ippoan/auth-worker#174: OAT identity binding endpoints。
vi.mock("../../src/handlers/mcp-pair-grant-via-oat", () => ({
  handleMcpPairGrantViaOat: vi.fn(() => new Response("mcp-pair-grant-via-oat")),
}));
vi.mock("../../src/handlers/mcp-pair-register-via-github-comment", () => ({
  handleMcpPairRegisterViaGithubComment: vi.fn(
    () => new Response("mcp-pair-register-via-github-comment"),
  ),
}));
// Phase 1 admin auth (issue #42 follow-up): browser elevate + admin-exec proxy。
vi.mock("../../src/handlers/mcp-elevate", () => ({
  handleMcpElevateStart: vi.fn(() => new Response("mcp-elevate-start")),
  handleMcpElevateCallback: vi.fn(() => new Response("mcp-elevate-callback")),
}));
vi.mock("../../src/handlers/mcp-admin-exec", () => ({
  handleMcpAdminExec: vi.fn(() => new Response("mcp-admin-exec")),
}));
// issue #159 Phase 1: branch-protection dashboard + API.
vi.mock("../../src/handlers/dashboard-branch-protection", () => ({
  handleDashboardBranchProtection: vi.fn(() => new Response("dashboard-branch-protection")),
}));
vi.mock("../../src/handlers/api-dashboard-branch-protection", () => ({
  handleApiDashboardListRepos: vi.fn(() => new Response("api-dashboard-list")),
  handleApiDashboardApplyProtection: vi.fn(
    (_req, _env, owner: string, repo: string) =>
      new Response(`api-dashboard-apply:${owner}/${repo}`),
  ),
  handleApiDashboardRemoveProtection: vi.fn(
    (_req, _env, owner: string, repo: string) =>
      new Response(`api-dashboard-remove:${owner}/${repo}`),
  ),
  handleApiDashboardFixRepoSettings: vi.fn(
    (_req, _env, owner: string, repo: string) =>
      new Response(`api-dashboard-fix-settings:${owner}/${repo}`),
  ),
}));
// Stub the DurableObject exports so importing index.ts doesn't blow up
vi.mock("../../src/durable_objects/lineworks-webhook-do", () => ({
  LineworksWebhookDO: class {},
}));
vi.mock("../../src/durable_objects/mcp-session-do", () => ({
  McpSession: class {},
}));

import worker from "../../src/index";

const env = {
  GOOGLE_CLIENT_ID: "cid",
  GOOGLE_CLIENT_SECRET: "cs",
  OAUTH_STATE_SECRET: "os",
  JWT_SECRET: TEST_JWT_SECRET,
  AUTH_WORKER_ORIGIN: "https://auth.test.example",
  ALC_API_ORIGIN: "https://alc-api.test.example",
  VERSION: "test",
  WORKER_ENV: "prod",
  SSO_ENCRYPTION_KEY: "test-encryption-key",
  AUTH_CONFIG: {
    get: async (key: string) =>
      key === "origins:prod" ? "https://app.test.example" : null,
  } as unknown as KVNamespace,
  // Mocked handler doesn't actually use this binding
  LINEWORKS_WEBHOOK_DO: createMockDONamespace(),
};

describe("Router (index.ts)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // --- GET routes ---
  const getRoutes: [string, string][] = [
    ["/top", "top-page"],
    ["/login?redirect_uri=https%3A%2F%2Fapp.test.example", "login-page"],
    ["/oauth/google/redirect", "google-redirect"],
    ["/oauth/google/callback", "google-callback"],
    ["/oauth/lineworks/redirect", "lw-redirect"],
    ["/oauth/lineworks/callback", "lw-callback"],
    ["/oauth/egov/redirect", "egov-redirect"],
    ["/oauth/egov/callback", "egov-callback"],
    ["/auth/woff-config", "woff-config"],
    ["/admin/sso", "admin-sso"],
    ["/admin/sso/callback", "admin-sso-cb"],
    ["/admin/users", "admin-users"],
    ["/admin/users/callback", "admin-users-cb"],
    ["/admin/rich-menu", "admin-rich-menu"],
    ["/admin/rich-menu/callback", "admin-rich-menu-cb"],
    ["/admin/requests", "admin-requests"],
    ["/admin/requests/callback", "admin-requests-cb"],
    ["/admin/notify", "admin-notify"],
    ["/admin/notify/callback", "admin-notify-cb"],
    ["/redirect?to=https://app1.test.example", "redirect"],
    ["/logout", "logout"],
    ["/api/bot-config/export?tenant_id=abc", "bot-export"],
    // Cloudflare Access 向け OIDC surface の JWKS (issuer `<origin>/oidc`)。
    ["/oidc/.well-known/jwks.json", "oidc-jwks"],
    ["/.well-known/oauth-authorization-server", "mcp-as-metadata"],
    // issue #438: Google IdP surface の AS metadata alias 4 種。
    ["/.well-known/oauth-authorization-server/mcp/google", "mcp-as-metadata"],
    ["/mcp/google/.well-known/oauth-authorization-server", "mcp-as-metadata"],
    ["/.well-known/openid-configuration/mcp/google", "mcp-as-metadata"],
    ["/mcp/google/.well-known/openid-configuration", "mcp-as-metadata"],
    ["/.well-known/oauth-protected-resource", "mcp-resource-metadata"],
    // issue #438: Google IdP surface の PRM (path-inserted 形、prefix branch 経由)。
    ["/.well-known/oauth-protected-resource/mcp/google", "mcp-resource-metadata"],
    // ippoan/secrets-inventory#45 / auth-worker#195: per-resource variant
    // (= dynamic slug suffix routes through the `startsWith` branch in
    // index.ts dispatch).
    ["/.well-known/oauth-protected-resource/security-inventory", "mcp-resource-metadata"],
    ["/device", "mcp-device-page"],
    ["/device?user_code=BCDF-GHJK", "mcp-device-page"],
    ["/mcp/device_callback?code=abc&state=xyz", "mcp-device-callback"],
    ["/mcp/authorize?response_type=code&client_id=x", "mcp-authorize"],
    // issue #438: Google IdP surface の authorize (idpDefault: "google" 付き —
    // 引数は下の専用 it で検証)。
    ["/mcp/google/authorize?response_type=code&client_id=x", "mcp-authorize"],
    ["/mcp/auth_callback?code=ghc&state=xyz", "mcp-auth-callback"],
    ["/mcp/elevate", "mcp-elevate-start"],
    ["/mcp/elevate?return_to=https%3A%2F%2Fclient.example", "mcp-elevate-start"],
    ["/mcp/elevate_callback?code=ghc&state=xyz", "mcp-elevate-callback"],
    // issue #159 Phase 1: branch-protection dashboard.
    ["/dashboard/branch-protection", "dashboard-branch-protection"],
    ["/api/dashboard/repos", "api-dashboard-list"],
    // issue #209: OAuth client_id health check (JWT-guarded).
    ["/health/oauth", "health-oauth"],
    // Refs ippoan/HealthConnectReaderWorker#60, #61: Google Health API pass-through.
    ["/oauth/ghapi/redirect", "ghapi-redirect"],
    ["/oauth/ghapi/callback", "ghapi-callback"],
  ];

  it("GET /api/health → health proxy", async () => {
    const req = new Request("https://auth.test.example/api/health");
    const res = await worker.fetch(req, env);
    const body = await res.json() as { status: string };
    expect(body.status).toBe("ok");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  for (const [path, expected] of getRoutes) {
    it(`GET ${path.split("?")[0]} → ${expected}`, async () => {
      const req = new Request(`https://auth.test.example${path}`);
      const res = await worker.fetch(req, env);
      expect(await res.text()).toBe(expected);
    });
  }

  // --- Dynamic GET routes ---
  it("GET /join/:slug → join-page", async () => {
    const req = new Request("https://auth.test.example/join/test-org");
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("join-page");
  });

  it("GET /join/:slug/done → join-done", async () => {
    const req = new Request("https://auth.test.example/join/test-org/done");
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("join-done");
  });

  it("GET /join/ with invalid path returns 404", async () => {
    const req = new Request("https://auth.test.example/join/test-org/invalid/extra");
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(404);
  });

  // --- POST routes ---
  const postRoutes: [string, string][] = [
    ["/api/sso/list", "sso-list"],
    ["/api/sso/upsert", "sso-upsert"],
    ["/api/sso/delete", "sso-delete"],
    ["/api/bot-config/list", "bot-list"],
    ["/api/bot-config/upsert", "bot-upsert"],
    ["/api/bot-config/delete", "bot-delete"],
    ["/api/bot-config/import", "bot-import"],
    ["/api/users/list", "users-list"],
    ["/api/users/invitations", "inv-list"],
    ["/api/users/invite", "invite"],
    ["/api/users/invite/delete", "del-inv"],
    ["/api/users/delete", "del-user"],
    ["/auth/login", "auth-login"],
    ["/auth/woff", "woff-auth"],
    ["/api/richmenu/list", "rm-list"],
    ["/api/richmenu/create", "rm-create"],
    ["/api/richmenu/delete", "rm-delete"],
    ["/api/richmenu/image", "rm-image"],
    ["/api/richmenu/default/set", "rm-default-set"],
    ["/api/richmenu/default/delete", "rm-default-delete"],
    ["/api/access-requests/create", "ar-create"],
    ["/api/access-requests/list", "ar-list"],
    ["/api/access-requests/approve", "ar-approve"],
    ["/api/access-requests/decline", "ar-decline"],
    ["/api/switch-org", "switch-org"],
    ["/api/my-orgs", "my-orgs"],
    ["/mcp/device_authorization", "mcp-device-authorization"],
    ["/device/verify", "mcp-device-verify"],
    ["/device/proceed", "mcp-device-proceed"],
    ["/mcp/token", "mcp-token"],
    ["/mcp/introspect", "mcp-introspect"],
    ["/mcp/jwt/pickup", "mcp-jwt-pickup"],
    ["/mcp/revoke", "mcp-revoke"],
    ["/mcp/tools", "mcp-tools"],
    // issue #438: Google IdP surface の MCP data plane (同 handler)。
    ["/mcp/google", "mcp-tools"],
    ["/dev-login/token", "dev-login-token"],
    ["/mcp/admin/exec", "mcp-admin-exec"],
  ];

  for (const [path, expected] of postRoutes) {
    it(`POST ${path} → ${expected}`, async () => {
      const req = new Request(`https://auth.test.example${path}`, { method: "POST" });
      const res = await worker.fetch(req, env);
      expect(await res.text()).toBe(expected);
    });
  }

  // --- Dynamic POST routes (lineworks webhook + refresh) ---
  it("POST /lineworks/webhook/:bot_id → lw-webhook handler with bot_id", async () => {
    const req = new Request("https://auth.test.example/lineworks/webhook/bot-abc", {
      method: "POST",
    });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("lw-webhook:bot-abc");
  });

  it("POST /lineworks/refresh/:bot_id → lw-refresh handler with bot_id", async () => {
    const req = new Request("https://auth.test.example/lineworks/refresh/bot-xyz", {
      method: "POST",
    });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("lw-refresh:bot-xyz");
  });

  it("POST /line/webhook → line-webhook forwarder (#434)", async () => {
    const req = new Request("https://auth.test.example/line/webhook", { method: "POST" });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("line-webhook");
  });

  // --- MCP relay host dispatcher (mcp.ippoan.org / mcp-staging.ippoan.org) ---
  it("GET mcp.* /u/:user/connect → relay-connect:<user>", async () => {
    const req = new Request("https://mcp.ippoan.org/u/yhonda-ohishi/connect");
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("relay-connect:yhonda-ohishi");
  });

  it("POST mcp.* /u/:user/mcp → relay-bridge:<user>", async () => {
    const req = new Request("https://mcp.ippoan.org/u/yhonda-ohishi/mcp", {
      method: "POST",
    });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("relay-bridge:yhonda-ohishi");
  });

  it("GET mcp-staging.* /u/:user/connect also routes to relay-connect", async () => {
    const req = new Request("https://mcp-staging.ippoan.org/u/alice/connect");
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("relay-connect:alice");
  });

  // ADR-003 (ippoan/cc-relay#35): user-less endpoints. `.mcp.json` committed
  // to a consumer repo root points at these; the handler derives DO id from
  // the JWT's github_login claim. The mock tags this with `(jwt)`.
  it("POST mcp.* /mcp → relay-bridge:(jwt) [user-less, ADR-003]", async () => {
    const req = new Request("https://mcp.ippoan.org/mcp", { method: "POST" });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("relay-bridge:(jwt)");
  });

  it("GET mcp.* /connect → relay-connect:(jwt) [user-less, ADR-003]", async () => {
    const req = new Request("https://mcp.ippoan.org/connect");
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("relay-connect:(jwt)");
  });

  // ADR-004 Phase D: GET /mcp → SSE stream (Streamable HTTP transport)。
  // 旧バージョンでは 404 だったが、Phase D で routing が増えたので
  // relay-sse handler に振られる。
  it("GET mcp.* /mcp → relay-sse:(jwt) [user-less, ADR-004 Phase D]", async () => {
    const req = new Request("https://mcp.ippoan.org/mcp");
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("relay-sse:(jwt)");
  });

  it("POST mcp.* /connect → 404 (wrong method for user-less connect)", async () => {
    const req = new Request("https://mcp.ippoan.org/connect", { method: "POST" });
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(404);
  });

  // ADR-004 (multiplex): GitHub webhook route
  it("POST mcp.* /webhooks/github → github-webhook handler", async () => {
    const req = new Request("https://mcp.ippoan.org/webhooks/github", {
      method: "POST",
    });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("github-webhook");
  });

  it("GET mcp.* /webhooks/github → 404 (wrong method)", async () => {
    const req = new Request("https://mcp.ippoan.org/webhooks/github");
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(404);
  });

  // Phase 5 (#128): mcp-staging.* host で /register と /authorize も dispatch される
  it("POST mcp.* /register → mcp-register handler (DCR, Phase 5 #128)", async () => {
    const req = new Request("https://mcp-staging.ippoan.org/register", {
      method: "POST",
    });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("mcp-register");
  });

  it("GET mcp.* /authorize → mcp-authorize handler (Auth Code, Phase 5 #128)", async () => {
    const req = new Request("https://mcp-staging.ippoan.org/authorize");
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("mcp-authorize");
  });

  // issue #438: Google IdP surface — authorize は idpDefault: "google" 付きで、
  // AS metadata は surface="google" variant で呼ばれることを引数レベルで検証。
  it("GET /mcp/google/authorize passes { idpDefault: 'google' } to mcp-authorize", async () => {
    const { handleMcpAuthorize } = await import("../../src/handlers/mcp-authorize");
    const req = new Request("https://auth.test.example/mcp/google/authorize");
    await worker.fetch(req, env);
    expect(vi.mocked(handleMcpAuthorize)).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      { idpDefault: "google" },
    );
  });

  it("GET /mcp/authorize (default surface) passes no idpDefault to mcp-authorize", async () => {
    const { handleMcpAuthorize } = await import("../../src/handlers/mcp-authorize");
    const req = new Request("https://auth.test.example/mcp/authorize");
    await worker.fetch(req, env);
    expect(vi.mocked(handleMcpAuthorize)).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
    );
  });

  it("GET /.well-known/oauth-authorization-server/mcp/google passes surface 'google' to mcp-as-metadata", async () => {
    const { handleMcpAsMetadata } = await import("../../src/handlers/mcp-as-metadata");
    const req = new Request(
      "https://auth.test.example/.well-known/oauth-authorization-server/mcp/google",
    );
    await worker.fetch(req, env);
    expect(vi.mocked(handleMcpAsMetadata)).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      "google",
    );
  });

  it("auth-staging.* POST /mcp/register → mcp-register handler", async () => {
    const req = new Request("https://auth.test.example/mcp/register", {
      method: "POST",
    });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("mcp-register");
  });

  it("POST mcp.* /u/:user/connect → 404 (wrong method)", async () => {
    const req = new Request("https://mcp.ippoan.org/u/alice/connect", {
      method: "POST",
    });
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(404);
  });

  // ADR-004 Phase D: GET /u/:user/mcp も SSE stream に振る (legacy user-scoped)。
  it("GET mcp.* /u/:user/mcp → relay-sse:<user> [ADR-004 Phase D]", async () => {
    const req = new Request("https://mcp.ippoan.org/u/alice/mcp");
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("relay-sse:alice");
  });

  it("GET mcp.* unknown path → 404 (relay 404, doesn't fall through to auth routes)", async () => {
    const req = new Request("https://mcp.ippoan.org/login");
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(404);
  });

  // --- issue #144: 1-click pair routes ---
  it("POST mcp.* /mcp/pair/new → mcp-pair-new", async () => {
    const req = new Request("https://mcp.ippoan.org/mcp/pair/new", { method: "POST" });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("mcp-pair-new");
  });

  it("GET /health/secret-fingerprint → secret-fingerprint", async () => {
    const req = new Request("https://auth.ippoan.org/health/secret-fingerprint", { method: "GET" });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("secret-fingerprint");
  });
  it("POST /auth/introspect → auth-introspect", async () => {
    const req = new Request("https://auth.ippoan.org/auth/introspect", { method: "POST" });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("auth-introspect");
  });

  // --- Phase 2 (ohishi-exp/smb-watch#1): device-token endpoints ---
  it("POST /device/pair → device-pair", async () => {
    const req = new Request("https://auth.ippoan.org/device/pair", { method: "POST" });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("device-pair");
  });
  it("POST /device/token → device-token", async () => {
    const req = new Request("https://auth.ippoan.org/device/token", { method: "POST" });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("device-token");
  });
  it("POST /device/revoke → device-revoke", async () => {
    const req = new Request("https://auth.ippoan.org/device/revoke", { method: "POST" });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("device-revoke");
  });

  // --- Phase 2.5 (ohishi-exp/smb-watch#1): headless pairing endpoints ---
  it("POST /device/pair/start → device-pair-start", async () => {
    const req = new Request("https://auth.ippoan.org/device/pair/start", { method: "POST" });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("device-pair-start");
  });
  it("GET /device/pair/approve → device-pair-approve-page", async () => {
    const req = new Request("https://auth.ippoan.org/device/pair/approve", { method: "GET" });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("device-pair-approve-page");
  });
  it("POST /device/pair/approve → device-pair-approve", async () => {
    const req = new Request("https://auth.ippoan.org/device/pair/approve", { method: "POST" });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("device-pair-approve");
  });
  it("POST /device/pair/token → device-pair-token", async () => {
    const req = new Request("https://auth.ippoan.org/device/pair/token", { method: "POST" });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("device-pair-token");
  });

  // --- issue #157 Phase B: 30-day refresh_token grant ---
  it("POST mcp.* /mcp/pair/grant → mcp-pair-grant (relay host)", async () => {
    const req = new Request("https://mcp.ippoan.org/mcp/pair/grant", { method: "POST" });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("mcp-pair-grant");
  });

  it("POST auth.* /mcp/pair/grant → mcp-pair-grant (auth host for debug)", async () => {
    const req = new Request("https://auth.test.example/mcp/pair/grant", { method: "POST" });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("mcp-pair-grant");
  });

  it("POST mcp.* /mcp/pair/grant-via-github → mcp-pair-grant-via-github (relay host, issue mcp-relay-rs#15)", async () => {
    const req = new Request("https://mcp.ippoan.org/mcp/pair/grant-via-github", {
      method: "POST",
    });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("mcp-pair-grant-via-github");
  });

  it("POST auth.* /mcp/pair/grant-via-github → mcp-pair-grant-via-github (auth host for debug)", async () => {
    const req = new Request("https://auth.test.example/mcp/pair/grant-via-github", {
      method: "POST",
    });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("mcp-pair-grant-via-github");
  });

  it("POST mcp.* /mcp/pair/grant-via-oat → mcp-pair-grant-via-oat (relay host, issue auth-worker#174)", async () => {
    const req = new Request("https://mcp.ippoan.org/mcp/pair/grant-via-oat", {
      method: "POST",
    });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("mcp-pair-grant-via-oat");
  });

  it("POST auth.* /mcp/pair/grant-via-oat → mcp-pair-grant-via-oat (auth host for debug)", async () => {
    const req = new Request("https://auth.test.example/mcp/pair/grant-via-oat", {
      method: "POST",
    });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("mcp-pair-grant-via-oat");
  });

  it("POST mcp.* /mcp/pair/register-via-github-comment → mcp-pair-register-via-github-comment (relay host)", async () => {
    const req = new Request(
      "https://mcp.ippoan.org/mcp/pair/register-via-github-comment",
      { method: "POST" },
    );
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("mcp-pair-register-via-github-comment");
  });

  it("POST auth.* /mcp/pair/register-via-github-comment → mcp-pair-register-via-github-comment (auth host)", async () => {
    const req = new Request(
      "https://auth.test.example/mcp/pair/register-via-github-comment",
      { method: "POST" },
    );
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("mcp-pair-register-via-github-comment");
  });

  // --- issue #145: native MCP tools (also routed on the relay host) ---
  it("POST mcp.* /mcp/tools → mcp-tools (native mode via relay host)", async () => {
    const req = new Request("https://mcp.ippoan.org/mcp/tools", { method: "POST" });
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("mcp-tools");
  });

  it("GET auth.* /mcp/pair/<code> → mcp-pair-claim:<code>", async () => {
    const req = new Request("https://auth.test.example/mcp/pair/ABC123");
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("mcp-pair-claim:ABC123");
  });

  it("GET auth.* /mcp/pair/new → 405 (POST-only, do not route to claim handler)", async () => {
    const req = new Request("https://auth.test.example/mcp/pair/new");
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(405);
  });

  it("GET auth.* /mcp/pair/ (empty code) → 404", async () => {
    const req = new Request("https://auth.test.example/mcp/pair/");
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(404);
  });

  it("GET auth.* /mcp/pair/<code>/extra → 404 (only one segment after /mcp/pair/)", async () => {
    const req = new Request("https://auth.test.example/mcp/pair/abc/extra");
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(404);
  });

  it("GET auth.* /mcp/pair_callback → mcp-pair-callback", async () => {
    const req = new Request("https://auth.test.example/mcp/pair_callback?code=x&state=y");
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("mcp-pair-callback");
  });

  // --- 404 / 405 ---
  it("GET unknown path returns 404", async () => {
    const req = new Request("https://auth.test.example/unknown");
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(404);
  });

  it("POST unknown path returns 404", async () => {
    const req = new Request("https://auth.test.example/unknown", { method: "POST" });
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(404);
  });

  it("OPTIONS returns CORS preflight", async () => {
    const req = new Request("https://auth.test.example/auth/woff", { method: "OPTIONS" });
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  it("PUT returns 405", async () => {
    const req = new Request("https://auth.test.example/api/health", { method: "PUT" });
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(405);
  });

  // --- issue #159 Phase 1: dashboard dynamic routes ---
  it("POST /api/dashboard/repos/:owner/:repo/protection → api-dashboard-apply:<o>/<r>", async () => {
    const req = new Request(
      "https://auth.test.example/api/dashboard/repos/ippoan/r1/protection",
      { method: "POST" },
    );
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("api-dashboard-apply:ippoan/r1");
  });

  it("POST /api/dashboard/repos/:owner/:repo/fix-settings → api-dashboard-fix-settings:<o>/<r>", async () => {
    const req = new Request(
      "https://auth.test.example/api/dashboard/repos/ippoan/r1/fix-settings",
      { method: "POST" },
    );
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("api-dashboard-fix-settings:ippoan/r1");
  });

  it("DELETE /api/dashboard/repos/:owner/:repo/protection → api-dashboard-remove:<o>/<r>", async () => {
    const req = new Request(
      "https://auth.test.example/api/dashboard/repos/ippoan/r1/protection",
      { method: "DELETE" },
    );
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("api-dashboard-remove:ippoan/r1");
  });

  it("DELETE non-dashboard path returns 404", async () => {
    const req = new Request("https://auth.test.example/something/else", { method: "DELETE" });
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(404);
  });

  it("GET /api/dashboard/repos/:owner/:repo/protection returns 405 (POST/DELETE only)", async () => {
    const req = new Request(
      "https://auth.test.example/api/dashboard/repos/ippoan/r1/protection",
    );
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(405);
  });

  // --- Error handling ---
  it("catches handler errors and returns 500", async () => {
    const { handleHealthProxy } = await import("../../src/handlers/health");
    (handleHealthProxy as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error("boom"));

    const req = new Request("https://auth.test.example/api/health");
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(500);
    const data = await res.json() as { error: string };
    expect(data.error).toBe("boom");
  });

  it("catches non-Error throws and returns 500 with generic message", async () => {
    const { handleHealthProxy } = await import("../../src/handlers/health");
    (handleHealthProxy as ReturnType<typeof vi.fn>).mockRejectedValueOnce("string error");

    const req = new Request("https://auth.test.example/api/health");
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(500);
    const data = await res.json() as { error: string };
    expect(data.error).toBe("Internal server error");
  });
});
