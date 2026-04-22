import { describe, it, expect, vi, beforeEach } from "vitest";

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

import worker from "../../src/index";

const env = {
  GOOGLE_CLIENT_ID: "cid",
  GOOGLE_CLIENT_SECRET: "cs",
  OAUTH_STATE_SECRET: "os",
  AUTH_WORKER_ORIGIN: "https://auth.test.example",
  ALC_API_ORIGIN: "https://alc-api.test.example",
  VERSION: "test",
  WORKER_ENV: "prod",
  AUTH_CONFIG: {
    get: async (key: string) =>
      key === "origins:prod" ? "https://app.test.example" : null,
  } as unknown as KVNamespace,
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
  ];

  for (const [path, expected] of postRoutes) {
    it(`POST ${path} → ${expected}`, async () => {
      const req = new Request(`https://auth.test.example${path}`, { method: "POST" });
      const res = await worker.fetch(req, env);
      expect(await res.text()).toBe(expected);
    });
  }

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
