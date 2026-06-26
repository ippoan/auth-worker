import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { makeJwt } from "../helpers/live-env";

// ACL / OIDC mint は別ユニットでテスト済み。ここでは handler の flow
// (token 抽出 → 検証 → origin 必須 → identity 注入 → forward) を固定する。
vi.mock("../../src/lib/acl", () => ({
  checkOrgAccess: vi.fn(async () => true),
  checkAppTenant: vi.fn(() => true),
}));
vi.mock("../../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async () => "fake-oidc-token"),
}));

import { handleAlcProxy } from "../../src/handlers/alc-proxy";

const ORIGIN = "https://alc.ippoan.org";
const PROXY_SECRET = "test-internal-shared-secret-32!!";
const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

function env(overrides: Record<string, unknown> = {}) {
  return createMockEnv({
    ALC_API_PROXY_SA_KEY: "{}", // resolveSecret が非空を返せばよい (oidc は mock)
    INTERNAL_SHARED_SECRET: PROXY_SECRET, // consumer worker proof 用 (resolveAllSharedSecrets)
    ...overrides,
  });
}

function req(
  path: string,
  init: RequestInit & {
    token?: string | null;
    origin?: string | null;
    proxySecret?: string | null;
  } = {},
) {
  const headers: Record<string, string> = {};
  const token = init.token === undefined ? makeJwt(TEST_JWT_SECRET) : init.token;
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (init.origin !== null) headers["X-Alc-Proxy-Origin"] = init.origin ?? ORIGIN;
  if (init.proxySecret !== null) headers["X-Alc-Proxy-Secret"] = init.proxySecret ?? PROXY_SECRET;
  return new Request(`https://auth.test.example${path}`, {
    method: init.method ?? "GET",
    headers: { ...headers, ...(init.headers as Record<string, string>) },
    body: init.body,
  });
}

describe("handleAlcProxy (rust-alc-api#434 step 3, 方式 B)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("X-Alc-Proxy-Secret 欠落は 401 (consumer worker proof 不能 → 直叩き/origin 詐称を弾く)", async () => {
    const res = await handleAlcProxy(
      req("/alc-proxy/api/employees", { proxySecret: null }),
      env(),
    );
    expect(res.status).toBe(401);
  });

  it("X-Alc-Proxy-Secret 不一致は 401", async () => {
    const res = await handleAlcProxy(
      req("/alc-proxy/api/employees", { proxySecret: "wrong-secret" }),
      env(),
    );
    expect(res.status).toBe(401);
  });

  it("INTERNAL_SHARED_SECRET 未 bind は 503 (fail-closed で route 無効化)", async () => {
    const res = await handleAlcProxy(
      req("/alc-proxy/api/employees"),
      env({ INTERNAL_SHARED_SECRET: undefined }),
    );
    expect(res.status).toBe(503);
  });

  it("token 無しは 401", async () => {
    const res = await handleAlcProxy(req("/alc-proxy/api/employees", { token: null }), env());
    expect(res.status).toBe(401);
  });

  it("X-Alc-Proxy-Origin 欠落は 401 (ACL 強制不能なので fail-closed)", async () => {
    const res = await handleAlcProxy(req("/alc-proxy/api/employees", { origin: null }), env());
    expect(res.status).toBe(401);
  });

  it("ALC_API_PROXY_SA_KEY 未設定は 503", async () => {
    const res = await handleAlcProxy(
      req("/alc-proxy/api/employees"),
      env({ ALC_API_PROXY_SA_KEY: undefined }),
    );
    expect(res.status).toBe(503);
  });

  it("署名不正な token は 401", async () => {
    const res = await handleAlcProxy(
      req("/alc-proxy/api/employees", { token: makeJwt("wrong-secret") }),
      env(),
    );
    expect(res.status).toBe(401);
  });

  it("正常: OIDC Bearer + X-Tenant-ID/X-User-* を注入して ALC_API_ORIGIN に forward", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleAlcProxy(req("/alc-proxy/api/employees?x=1"), env());
    expect(res.status).toBe(200);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    // ALC_API_ORIGIN (mock env) + /alc-proxy 以降の path + query
    expect(String(url)).toBe("https://alc-api.test.example/api/employees?x=1");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
    expect(h["X-Tenant-ID"]).toBe("11111111-1111-1111-1111-111111111111");
    expect(h["X-User-ID"]).toBe("22222222-2222-2222-2222-222222222222");
    expect(h["X-User-Email"]).toBe("test@example.com");
    expect(h["X-User-Role"]).toBe("admin");
  });

  it("POST は body を forward する", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await handleAlcProxy(
      req("/alc-proxy/api/measurements", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ a: 1 }),
      }),
      env(),
    );
    const [, init] = fetchMock.mock.calls[0]!;
    expect((init as RequestInit).method).toBe("POST");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Content-Type"]).toBe("application/json");
    expect((init as RequestInit).body).toBeDefined();
  });
});
