import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

const mockListMyOrganizations = vi.fn();
vi.mock("@connectrpc/connect", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@connectrpc/connect")>();
  return {
    ...actual,
    createClient: vi.fn(() => ({ listMyOrganizations: mockListMyOrganizations })),
  };
});
vi.mock("../../src/lib/transport", () => ({
  createTransportWithAuth: vi.fn(),
}));
vi.mock("@yhonda-ohishi-pub-dev/logi-proto", () => ({
  OrganizationService: {},
}));

import { handleMyOrgs } from "../../src/handlers/api-my-orgs";

describe("handleMyOrgs", () => {
  const env = createMockEnv();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns 401 without token", async () => {
    const req = new Request("https://auth.test.example/api/my-orgs", {
      method: "POST",
    });
    const res = await handleMyOrgs(req, env);
    expect(res.status).toBe(401);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  it("returns organizations on success", async () => {
    mockListMyOrganizations.mockResolvedValueOnce({
      organizations: [
        { id: "o1", name: "Org1", slug: "org1", role: "admin" },
        { id: "o2", name: "Org2", slug: "org2", role: "member" },
      ],
    });

    const req = new Request("https://auth.test.example/api/my-orgs", {
      method: "POST",
      headers: { Authorization: "Bearer token123" },
    });
    const res = await handleMyOrgs(req, env);
    expect(res.status).toBe(200);
    const data = (await res.json()) as { organizations: Array<{ slug: string }> };
    expect(data.organizations).toHaveLength(2);
    expect(data.organizations[0]!.slug).toBe("org1");
  });

  it("returns empty array when organizations is undefined", async () => {
    mockListMyOrganizations.mockResolvedValueOnce({});

    const req = new Request("https://auth.test.example/api/my-orgs", {
      method: "POST",
      headers: { Authorization: "Bearer token123" },
    });
    const res = await handleMyOrgs(req, env);
    const data = (await res.json()) as { organizations: unknown[] };
    expect(data.organizations).toEqual([]);
  });

  it("returns 400 on ConnectError", async () => {
    const { ConnectError } = await import("@connectrpc/connect");
    mockListMyOrganizations.mockRejectedValueOnce(new ConnectError("fail", 3));

    const req = new Request("https://auth.test.example/api/my-orgs", {
      method: "POST",
      headers: { Authorization: "Bearer token123" },
    });
    const res = await handleMyOrgs(req, env);
    expect(res.status).toBe(400);
  });

  it("throws non-ConnectError", async () => {
    mockListMyOrganizations.mockRejectedValueOnce(new Error("boom"));

    const req = new Request("https://auth.test.example/api/my-orgs", {
      method: "POST",
      headers: { Authorization: "Bearer token123" },
    });
    await expect(handleMyOrgs(req, env)).rejects.toThrow("boom");
  });
});
