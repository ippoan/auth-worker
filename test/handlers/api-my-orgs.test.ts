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
import { makeJwt, TEST_TENANT_ID } from "../helpers/live-env";
import { createMockEnv } from "../helpers/mock-env";
import { FAKE_ALC_AUTH_SECRET } from "../helpers/fake-alc-auth";
import type { Env } from "../../src/index";
import { handleMyOrgs } from "../../src/handlers/api-my-orgs";

afterAll(() => restoreFetch());
waitIfLive();

/** alc-auth-worker (ALC_AUTH) の fake + それを使う env (my-orgs は alc-auth-worker から組む)。 */
function alcAuthEnv(respond: () => Response): { env: Env; fetchMock: ReturnType<typeof vi.fn> } {
  const fetchMock = vi.fn(async (_req: Request) => respond());
  const env = createMockEnv({
    ALC_AUTH_SESSION: "1",
    ALC_AUTH: { fetch: fetchMock } as unknown as Fetcher,
    INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET,
  });
  return { env, fetchMock };
}

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

  // my-orgs は alc-auth-worker (ALC_AUTH) から組む。live (ALC_AUTH 無しの testEnv) では 404 になるので、成功の形は mock だけで確かめる
  it.skipIf(isLive)("returns organizations on success", async () => {
    const { env: e, fetchMock } = alcAuthEnv(
      () => new Response(JSON.stringify({ id: "org1", name: "Test Org", slug: "test-org", short_id: "ab01" }), { status: 200 }),
    );
    const res = await handleMyOrgs(authRequest("/api/my-orgs", { method: "POST" }), e);
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      organizations: Array<Record<string, unknown>>;
    };
    expect(data.organizations).toEqual([{ id: "org1", name: "Test Org", slug: "test-org", role: "admin" }]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.skipIf(isLive)("alc-auth-worker の binding が無ければ fetch せず 404", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const res = await handleMyOrgs(authRequest("/api/my-orgs", { method: "POST" }), env);
    expect(res.status).toBe(404);
    expect(((await res.json()) as { error: string }).error).toBe("not_found");
    expect(fetchMock).not.toHaveBeenCalled();
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

  // rust-alc-api#434: raw Bearer ではなく検証済み identity (JWT の tenant) で alc-auth-worker を引く。
  it.skipIf(isLive)("検証済みの tenant で alc-auth-worker を引き、raw Bearer は渡さない", async () => {
    const { env: e, fetchMock } = alcAuthEnv(
      () => new Response(JSON.stringify({ id: TEST_TENANT_ID, name: "T", slug: null, short_id: "ab01" }), { status: 200 }),
    );
    await handleMyOrgs(authRequest("/api/my-orgs", { method: "POST" }), e);
    const req = fetchMock.mock.calls[0]![0] as Request;
    expect(new URL(req.url).pathname).toBe(`/internal/tenants/${TEST_TENANT_ID}`);
    expect(req.headers.get("X-Internal-Shared-Secret")).toBe(FAKE_ALC_AUTH_SECRET);
    expect(req.headers.get("Authorization")).toBeNull();
  });
});
