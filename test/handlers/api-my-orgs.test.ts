import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import {
  stubOrReal,
  testEnv,
  authRequest,
  noAuthRequest,
  restoreFetch,
  waitIfLive,
  isLive,
  assertMock,
} from "../helpers/stub-or-real";
import { makeJwt, TEST_TENANT_ID, TEST_USER_ID } from "../helpers/live-env";
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

  // rust-alc-api#434: 署名不正な JWT は backend に投げず 401 (前段検証)。
  it("returns 401 when JWT signature is invalid", async () => {
    const forged = makeJwt("wrong-secret-not-matching-env");
    const req = new Request("https://auth.test.example/api/my-orgs", {
      method: "POST",
      headers: { Authorization: `Bearer ${forged}` },
    });
    const res = await handleMyOrgs(req, env);
    expect(res.status).toBe(401);
  });

  // rust-alc-api#434: raw Bearer ではなく検証済み X-Tenant-ID + X-User-* を注入する。
  it("injects verified identity headers (not raw Bearer) to backend", async () => {
    stubOrReal(
      new Response(JSON.stringify({ organizations: [] }), { status: 200 }),
    );
    await handleMyOrgs(authRequest("/api/my-orgs", { method: "POST" }), env);
    assertMock(() => {
      const call = vi.mocked(globalThis.fetch).mock.calls[0]!;
      const headers = (call[1] as RequestInit).headers as Record<string, string>;
      expect(headers["X-Tenant-ID"]).toBe(TEST_TENANT_ID);
      expect(headers["X-User-ID"]).toBe(TEST_USER_ID);
      expect(headers["X-User-Email"]).toBe("test@example.com");
      expect(headers["X-User-Role"]).toBe("admin");
      expect(headers["Authorization"]).toBeUndefined();
    });
  });
});
