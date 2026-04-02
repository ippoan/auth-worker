import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";
import { createTestJwt } from "../helpers/test-jwt";

const mockSwitchOrganization = vi.fn();
vi.mock("@connectrpc/connect", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@connectrpc/connect")>();
  return {
    ...actual,
    createClient: vi.fn(() => ({ switchOrganization: mockSwitchOrganization })),
  };
});
vi.mock("../../src/lib/transport", () => ({
  createTransportWithAuth: vi.fn(),
}));
vi.mock("@yhonda-ohishi-pub-dev/logi-proto", () => ({
  AuthService: {},
}));

import { handleSwitchOrg } from "../../src/handlers/api-switch-org";

describe("handleSwitchOrg", () => {
  const env = createMockEnv();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns 401 without token", async () => {
    const req = new Request("https://auth.test.example/api/switch-org", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ organizationId: "org-1" }),
    });
    const res = await handleSwitchOrg(req, env);
    expect(res.status).toBe(401);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  it("returns 400 without organizationId", async () => {
    const req = new Request("https://auth.test.example/api/switch-org", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer token123",
      },
      body: JSON.stringify({}),
    });
    const res = await handleSwitchOrg(req, env);
    expect(res.status).toBe(400);
  });

  it("returns token on success", async () => {
    const jwt = createTestJwt({ org: "org-2", org_slug: "my-org" });
    mockSwitchOrganization.mockResolvedValueOnce({
      token: jwt,
      expiresAt: "9999",
      organizationId: "org-2",
    });

    const req = new Request("https://auth.test.example/api/switch-org", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer token123",
      },
      body: JSON.stringify({ organizationId: "org-2" }),
    });
    const res = await handleSwitchOrg(req, env);
    expect(res.status).toBe(200);
    const data = await res.json<{ token: string; orgSlug: string }>();
    expect(data.token).toBe(jwt);
    expect(data.orgSlug).toBe("my-org");
  });

  it("returns empty orgSlug when payload has no org_slug", async () => {
    const jwt = createTestJwt({ org: "org-2" });
    // Remove org_slug from payload
    const parts = jwt.split(".");
    const payload = JSON.parse(atob(parts[1]!));
    delete payload.org_slug;
    parts[1] = btoa(JSON.stringify(payload));
    const noSlugJwt = parts.join(".");

    mockSwitchOrganization.mockResolvedValueOnce({
      token: noSlugJwt,
      expiresAt: "9999",
      organizationId: "org-2",
    });

    const req = new Request("https://auth.test.example/api/switch-org", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer token123",
      },
      body: JSON.stringify({ organizationId: "org-2" }),
    });
    const res = await handleSwitchOrg(req, env);
    const data = await res.json<{ orgSlug: string }>();
    expect(data.orgSlug).toBe("");
  });

  it("returns empty orgSlug when token has no payload part", async () => {
    mockSwitchOrganization.mockResolvedValueOnce({
      token: "nodots",
      expiresAt: "9999",
      organizationId: "org-2",
    });

    const req = new Request("https://auth.test.example/api/switch-org", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer token123",
      },
      body: JSON.stringify({ organizationId: "org-2" }),
    });
    const res = await handleSwitchOrg(req, env);
    const data = await res.json<{ orgSlug: string }>();
    expect(data.orgSlug).toBe("");
  });

  it("returns empty orgSlug when JWT decode fails", async () => {
    mockSwitchOrganization.mockResolvedValueOnce({
      token: "bad.!!!.jwt",
      expiresAt: "9999",
      organizationId: "org-2",
    });

    const req = new Request("https://auth.test.example/api/switch-org", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer token123",
      },
      body: JSON.stringify({ organizationId: "org-2" }),
    });
    const res = await handleSwitchOrg(req, env);
    const data = await res.json<{ orgSlug: string }>();
    expect(data.orgSlug).toBe("");
  });

  it("returns 400 on ConnectError", async () => {
    const { ConnectError } = await import("@connectrpc/connect");
    mockSwitchOrganization.mockRejectedValueOnce(new ConnectError("denied", 7));

    const req = new Request("https://auth.test.example/api/switch-org", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer token123",
      },
      body: JSON.stringify({ organizationId: "org-2" }),
    });
    const res = await handleSwitchOrg(req, env);
    expect(res.status).toBe(400);
  });

  it("throws non-ConnectError", async () => {
    mockSwitchOrganization.mockRejectedValueOnce(new Error("boom"));

    const req = new Request("https://auth.test.example/api/switch-org", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer token123",
      },
      body: JSON.stringify({ organizationId: "org-2" }),
    });
    await expect(handleSwitchOrg(req, env)).rejects.toThrow("boom");
  });
});
