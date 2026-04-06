import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import {
  stubOrReal,
  testEnv,
  authJsonRequest,
  noAuthJsonRequest,
  restoreFetch,
  waitIfLive,
  isLive,
} from "../helpers/stub-or-real";
import { handleSwitchOrg } from "../../src/handlers/api-switch-org";

afterAll(() => restoreFetch());
waitIfLive();

describe("handleSwitchOrg", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleSwitchOrg(
      noAuthJsonRequest("/api/switch-org", { organizationId: "org1" }),
      env,
    );
    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Unauthorized");
  });

  it("returns 401 with non-Bearer auth header", async () => {
    const req = new Request("https://auth.test.example/api/switch-org", {
      method: "POST",
      headers: {
        Authorization: "Basic abc",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ organizationId: "org1" }),
    });
    const res = await handleSwitchOrg(req, env);
    expect(res.status).toBe(401);
  });

  it("returns 400 when organizationId is missing", async () => {
    const res = await handleSwitchOrg(
      authJsonRequest("/api/switch-org", {}),
      env,
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("organizationId is required");
  });

  it("returns mapped response fields on success", async () => {
    stubOrReal(
      new Response(
        JSON.stringify({
          token: "new-jwt-token",
          expires_at: "2026-01-01T00:00:00Z",
          organization_id: "org-uuid-123",
        }),
        { status: 200 },
      ),
    );
    const res = await handleSwitchOrg(
      authJsonRequest("/api/switch-org", { organizationId: "org-uuid-123" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      token: string;
      expiresAt: string;
      organizationId: string;
    };
    expect(typeof data.token).toBe("string");
    expect(typeof data.expiresAt).toBe("string");
    expect(typeof data.organizationId).toBe("string");
    if (!isLive) {
      expect(data.token).toBe("new-jwt-token");
      expect(data.expiresAt).toBe("2026-01-01T00:00:00Z");
      expect(data.organizationId).toBe("org-uuid-123");
    }
  });

  it("passes through error status from backend", async () => {
    stubOrReal(new Response("not found", { status: 404 }));
    const req = isLive
      ? new Request("https://auth.test.example/api/switch-org", {
          method: "POST",
          headers: {
            Authorization: "Bearer invalid-token",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ organizationId: "org1" }),
        })
      : authJsonRequest("/api/switch-org", { organizationId: "org1" });
    const res = await handleSwitchOrg(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
    const data = (await res.json()) as { error: string };
    expect(typeof data.error).toBe("string");
  });
});
