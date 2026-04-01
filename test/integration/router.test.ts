import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock ALL handler modules
vi.mock("../../src/handlers/login-page", () => ({ handleLoginPage: vi.fn(() => new Response("login-page")) }));
vi.mock("../../src/handlers/login-api", () => ({ handleAuthLogin: vi.fn(() => new Response("login-api")) }));
vi.mock("../../src/handlers/google-redirect", () => ({ handleGoogleRedirect: vi.fn(() => new Response("google-redirect")) }));
vi.mock("../../src/handlers/google-callback", () => ({ handleGoogleCallback: vi.fn(() => new Response("google-callback")) }));
vi.mock("../../src/handlers/lineworks-redirect", () => ({ handleLineworksRedirect: vi.fn(() => new Response("lw-redirect")) }));
vi.mock("../../src/handlers/lineworks-callback", () => ({ handleLineworksCallback: vi.fn(() => new Response("lw-callback")) }));
vi.mock("../../src/handlers/admin-sso", () => ({
  handleAdminSsoPage: vi.fn(() => new Response("admin-sso")),
  handleAdminSsoCallback: vi.fn(() => new Response("admin-sso-cb")),
}));
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
vi.mock("../../src/handlers/api-rich-menu", () => ({
  handleRichMenuList: vi.fn(() => new Response("rm-list")),
  handleRichMenuCreate: vi.fn(() => new Response("rm-create")),
  handleRichMenuDelete: vi.fn(() => new Response("rm-delete")),
  handleRichMenuImageUpload: vi.fn(() => new Response("rm-image")),
  handleRichMenuDefaultSet: vi.fn(() => new Response("rm-default-set")),
  handleRichMenuDefaultDelete: vi.fn(() => new Response("rm-default-del")),
}));
vi.mock("../../src/handlers/admin-rich-menu", () => ({
  handleAdminRichMenuPage: vi.fn(() => new Response("admin-rm")),
  handleAdminRichMenuCallback: vi.fn(() => new Response("admin-rm-cb")),
}));
vi.mock("../../src/handlers/woff-auth", () => ({
  handleWoffAuth: vi.fn(() => new Response("woff-auth")),
  handleWoffConfig: vi.fn(() => new Response("woff-config")),
}));
vi.mock("../../src/handlers/top-page", () => ({ handleTopPage: vi.fn(() => new Response("top-page")) }));
vi.mock("../../src/handlers/logout", () => ({ handleLogout: vi.fn(() => new Response("logout")) }));
vi.mock("../../src/handlers/join-page", () => ({ handleJoinPage: vi.fn(() => new Response("join-page")) }));
vi.mock("../../src/handlers/join-callback", () => ({ handleJoinDone: vi.fn(() => new Response("join-done")) }));
vi.mock("../../src/handlers/admin-requests", () => ({
  handleAdminRequestsPage: vi.fn(() => new Response("admin-req")),
  handleAdminRequestsCallback: vi.fn(() => new Response("admin-req-cb")),
}));
vi.mock("../../src/handlers/api-access-requests", () => ({
  handleAccessRequestCreate: vi.fn(() => new Response("ar-create")),
  handleAccessRequestList: vi.fn(() => new Response("ar-list")),
  handleAccessRequestApprove: vi.fn(() => new Response("ar-approve")),
  handleAccessRequestDecline: vi.fn(() => new Response("ar-decline")),
}));
vi.mock("../../src/handlers/api-switch-org", () => ({ handleSwitchOrg: vi.fn(() => new Response("switch-org")) }));
vi.mock("../../src/handlers/api-my-orgs", () => ({ handleMyOrgs: vi.fn(() => new Response("my-orgs")) }));
vi.mock("../../src/handlers/admin-users", () => ({
  handleAdminUsersPage: vi.fn(() => new Response("admin-users")),
  handleAdminUsersCallback: vi.fn(() => new Response("admin-users-cb")),
}));
vi.mock("../../src/handlers/api-users", () => ({
  handleUsersList: vi.fn(() => new Response("users-list")),
  handleInvitationsList: vi.fn(() => new Response("inv-list")),
  handleInviteUser: vi.fn(() => new Response("invite")),
  handleDeleteInvitation: vi.fn(() => new Response("del-inv")),
  handleDeleteUser: vi.fn(() => new Response("del-user")),
}));

import worker from "../../src/index";

const env = {
  GRPC_PROXY: {} as any,
  GOOGLE_CLIENT_ID: "cid",
  GOOGLE_CLIENT_SECRET: "cs",
  OAUTH_STATE_SECRET: "os",
  AUTH_WORKER_ORIGIN: "https://auth.test.example",
  ALLOWED_REDIRECT_ORIGINS: "https://app.test.example",
  ALC_API_ORIGIN: "https://alc-api.test.example",
};

describe("Router (index.ts)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // --- GET routes ---
  const getRoutes: [string, string][] = [
    ["/login", "login-page"],
    ["/oauth/google/redirect", "google-redirect"],
    ["/oauth/google/callback", "google-callback"],
    ["/oauth/lineworks/redirect", "lw-redirect"],
    ["/oauth/lineworks/callback", "lw-callback"],
    ["/top", "top-page"],
    ["/auth/woff-config", "woff-config"],
    ["/admin/sso", "admin-sso"],
    ["/admin/sso/callback", "admin-sso-cb"],
    ["/admin/rich-menu", "admin-rm"],
    ["/admin/rich-menu/callback", "admin-rm-cb"],
    ["/admin/requests", "admin-req"],
    ["/admin/requests/callback", "admin-req-cb"],
    ["/admin/users", "admin-users"],
    ["/admin/users/callback", "admin-users-cb"],
    ["/logout", "logout"],
  ];

  for (const [path, expected] of getRoutes) {
    it(`GET ${path} → ${expected}`, async () => {
      const req = new Request(`https://auth.test.example${path}`);
      const res = await worker.fetch(req, env);
      expect(await res.text()).toBe(expected);
    });
  }

  // --- POST routes ---
  const postRoutes: [string, string][] = [
    ["/auth/login", "login-api"],
    ["/api/sso/list", "sso-list"],
    ["/api/sso/upsert", "sso-upsert"],
    ["/api/sso/delete", "sso-delete"],
    ["/auth/woff", "woff-auth"],
    ["/api/bot-config/list", "bot-list"],
    ["/api/bot-config/upsert", "bot-upsert"],
    ["/api/bot-config/delete", "bot-delete"],
    ["/api/richmenu/list", "rm-list"],
    ["/api/richmenu/create", "rm-create"],
    ["/api/richmenu/delete", "rm-delete"],
    ["/api/richmenu/image", "rm-image"],
    ["/api/richmenu/default/set", "rm-default-set"],
    ["/api/richmenu/default/delete", "rm-default-del"],
    ["/api/access-requests/create", "ar-create"],
    ["/api/access-requests/list", "ar-list"],
    ["/api/access-requests/approve", "ar-approve"],
    ["/api/access-requests/decline", "ar-decline"],
    ["/api/users/list", "users-list"],
    ["/api/users/invitations", "inv-list"],
    ["/api/users/invite", "invite"],
    ["/api/users/invite/delete", "del-inv"],
    ["/api/users/delete", "del-user"],
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

  // --- Dynamic routes ---
  it("GET /join/:slug dispatches to handleJoinPage", async () => {
    const req = new Request("https://auth.test.example/join/my-org");
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("join-page");
  });

  it("GET /join/:slug/done dispatches to handleJoinDone", async () => {
    const req = new Request("https://auth.test.example/join/my-org/done");
    const res = await worker.fetch(req, env);
    expect(await res.text()).toBe("join-done");
  });

  it("GET /join/ with extra segments returns 404", async () => {
    const req = new Request("https://auth.test.example/join/my-org/extra/stuff");
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(404);
  });

  // --- CORS preflight ---
  const corsRoutes = ["/auth/woff", "/api/switch-org", "/api/my-orgs"];
  for (const path of corsRoutes) {
    it(`OPTIONS ${path} → CORS preflight`, async () => {
      const req = new Request(`https://auth.test.example${path}`, { method: "OPTIONS" });
      const res = await worker.fetch(req, env);
      expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
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

  it("PUT returns 405", async () => {
    const req = new Request("https://auth.test.example/login", { method: "PUT" });
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(405);
  });

  it("OPTIONS on non-CORS path returns 405", async () => {
    const req = new Request("https://auth.test.example/login", { method: "OPTIONS" });
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(405);
  });

  // --- Error handling ---
  it("catches handler errors and returns 500", async () => {
    const { handleLoginPage } = await import("../../src/handlers/login-page");
    (handleLoginPage as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error("boom"));

    const req = new Request("https://auth.test.example/login");
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(500);
    const data = await res.json() as { error: string };
    expect(data.error).toBe("boom");
  });

  it("catches non-Error throws and returns 500 with generic message", async () => {
    const { handleLoginPage } = await import("../../src/handlers/login-page");
    (handleLoginPage as ReturnType<typeof vi.fn>).mockRejectedValueOnce("string error");

    const req = new Request("https://auth.test.example/login");
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(500);
    const data = await res.json() as { error: string };
    expect(data.error).toBe("Internal server error");
  });
});
