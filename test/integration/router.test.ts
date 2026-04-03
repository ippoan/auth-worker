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

import worker from "../../src/index";

const env = {
  GOOGLE_CLIENT_ID: "cid",
  GOOGLE_CLIENT_SECRET: "cs",
  OAUTH_STATE_SECRET: "os",
  AUTH_WORKER_ORIGIN: "https://auth.test.example",
  ALLOWED_REDIRECT_ORIGINS: "https://app.test.example",
  ALC_API_ORIGIN: "https://alc-api.test.example",
  VERSION: "test",
};

describe("Router (index.ts)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // --- GET routes ---
  it("GET /api/health → health proxy", async () => {
    const req = new Request("https://auth.test.example/api/health");
    const res = await worker.fetch(req, env);
    const body = await res.json() as { status: string };
    expect(body.status).toBe("ok");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
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
