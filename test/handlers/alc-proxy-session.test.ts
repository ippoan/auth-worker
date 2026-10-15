/**
 * alc-proxy と my-orgs の呼び手が `lib/alc-session.ts` の helper を通ること
 * (Refs ohishi-exp/rust-leave-worker#1)。helper の中身は test/lib/alc-session.test.ts。
 */
import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { makeJwt } from "../helpers/live-env";

vi.mock("../../src/lib/acl", () => ({
  checkOrgAccess: vi.fn(async () => true),
  checkAppTenant: vi.fn(() => true),
}));
vi.mock("../../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async () => "fake-oidc-token"),
}));

import { handleAlcProxy } from "../../src/handlers/alc-proxy";
import { handleMyOrgs } from "../../src/handlers/api-my-orgs";

const ORIGIN = "https://alc.ippoan.org";
const PROXY_SECRET = "test-internal-shared-secret-32!!";
const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function setup() {
  const alcCalls: string[] = [];
  const alcAuth = {
    fetch: async (r: Request) => {
      alcCalls.push(`${r.method} ${new URL(r.url).pathname}`);
      if (r.method === "DELETE") return new Response(null, { status: 204 });
      return json(200, { id: "t", name: "Acme", slug: null, short_id: "ac01" });
    },
  } as unknown as Fetcher;
  const cloudRun = vi.fn(async (..._a: unknown[]) => json(200, { organizations: [] }));
  globalThis.fetch = cloudRun as unknown as typeof fetch;
  const env = createMockEnv({
    ALC_API_PROXY_SA_KEY: "{}",
    INTERNAL_SHARED_SECRET: PROXY_SECRET,
    ALC_API_PREVIEW_HOST_SUFFIX: "rust-alc-api-747065218280.asia-northeast1.run.app",
    ALC_AUTH: alcAuth,
    ALC_AUTH_SESSION: "1",
  });
  return { alcCalls, cloudRun, env };
}

function req(path: string, method: string, headers: Record<string, string> = {}, token?: string) {
  return new Request(`https://auth.test.example${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token ?? makeJwt(TEST_JWT_SECRET)}`,
      "X-Alc-Proxy-Origin": ORIGIN,
      "X-Alc-Proxy-Secret": PROXY_SECRET,
      ...headers,
    },
  });
}

describe("alc-proxy → handleSessionPath", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("me は alc-auth-worker から答え、Cloud Run へ流さない", async () => {
    const { alcCalls, cloudRun, env } = setup();
    const res = await handleAlcProxy(req("/alc-proxy/api/auth/me", "GET"), env);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { tenant_short_id: string }).tenant_short_id).toBe("ac01");
    expect(alcCalls).toHaveLength(1);
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("logout は 204", async () => {
    const { alcCalls, env } = setup();
    const res = await handleAlcProxy(req("/alc-proxy/api/auth/logout", "POST"), env);
    expect(res.status).toBe(204);
    expect(alcCalls[0]).toMatch(/^DELETE \/internal\/tenants\/.+\/users\/.+\/refresh-token$/);
  });

  it("preview override 付きの me は helper に流れず従来の経路 (Cloud Run の preview 宛)", async () => {
    const { alcCalls, cloudRun, env } = setup();
    const previewBase = "https://v1-2-3---rust-alc-api-747065218280.asia-northeast1.run.app";
    const res = await handleAlcProxy(
      req("/alc-proxy/api/auth/me", "GET", { "X-Alc-Preview-Api-Base": previewBase }),
      env,
    );
    expect(res.status).toBe(200);
    expect(alcCalls).toHaveLength(0);
    expect(String(cloudRun.mock.calls[0]![0])).toBe(`${previewBase}/api/auth/me`);
  });

  it("JWT が無効なら helper に届く前に 401", async () => {
    const { alcCalls, env } = setup();
    const res = await handleAlcProxy(req("/alc-proxy/api/auth/me", "GET", {}, "bad.token.value"), env);
    expect(res.status).toBe(401);
    expect(alcCalls).toHaveLength(0);
  });

  it("対象外の path は従来どおり Cloud Run へ", async () => {
    const { alcCalls, cloudRun, env } = setup();
    await handleAlcProxy(req("/alc-proxy/api/employees", "GET"), env);
    expect(alcCalls).toHaveLength(0);
    expect(cloudRun).toHaveBeenCalledTimes(1);
  });
});

describe("handleMyOrgs → fetchMyOrgs", () => {
  it("有効なら alc-auth-worker から組み、失敗は 502", async () => {
    const { cloudRun, env } = setup();
    const ok = await handleMyOrgs(req("/api/my-orgs", "POST"), env);
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({
      organizations: [{ id: "t", name: "Acme", slug: "", role: "admin" }],
    });
    expect(cloudRun).not.toHaveBeenCalled();

    const down = createMockEnv({
      INTERNAL_SHARED_SECRET: PROXY_SECRET,
      ALC_AUTH_SESSION: "1",
      ALC_AUTH: { fetch: async () => json(500, {}) } as unknown as Fetcher,
    });
    const bad = await handleMyOrgs(req("/api/my-orgs", "POST"), down);
    expect(bad.status).toBe(502);
  });
});
