import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import {
  stubOrReal,
  testEnv,
  authRequest,
  noAuthRequest,
  restoreFetch,
  waitIfLive,
  isLive,
} from "../helpers/stub-or-real";
import { handleMyOrgs } from "../../src/handlers/api-my-orgs";

afterAll(() => restoreFetch());
waitIfLive();

describe("handleMyOrgs", () => {
  const env = testEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 401 without token", async () => {
    const res = await handleMyOrgs(noAuthRequest("/api/my-orgs"), env);
    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Unauthorized");
  });

  it("returns 401 with non-Bearer auth header", async () => {
    const req = new Request("https://auth.test.example/api/my-orgs", {
      method: "POST",
      headers: { Authorization: "Basic abc" },
    });
    const res = await handleMyOrgs(req, env);
    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Unauthorized");
  });

  it("returns organizations on success", async () => {
    stubOrReal(
      new Response(
        JSON.stringify({
          organizations: [
            { id: "org1", name: "Test Org", slug: "test-org" },
          ],
        }),
        { status: 200 },
      ),
    );
    const res = await handleMyOrgs(
      authRequest("/api/my-orgs", { method: "POST" }),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      organizations: Array<Record<string, unknown>>;
    };
    expect(Array.isArray(data.organizations)).toBe(true);
    expect(data.organizations.length).toBeGreaterThanOrEqual(1);
  });

  it("passes through error status from backend", async () => {
    stubOrReal(new Response("forbidden", { status: 403 }));
    const req = isLive
      ? new Request("https://auth.test.example/api/my-orgs", {
          method: "POST",
          headers: { Authorization: "Bearer invalid-token-value" },
        })
      : authRequest("/api/my-orgs", { method: "POST" });
    const res = await handleMyOrgs(req, env);
    expect(res.status).toBeGreaterThanOrEqual(400);
    const data = (await res.json()) as { error: string };
    expect(typeof data.error).toBe("string");
  });
});
