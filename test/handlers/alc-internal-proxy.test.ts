import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

// OIDC mint は別ユニットでテスト済み。ここでは handler の flow
// (consumer proof → path allowlist → tenant 必須 → OIDC mint → forward) を固定する。
vi.mock("../../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async () => "fake-oidc-token"),
}));

import { handleAlcInternalProxy } from "../../src/handlers/alc-internal-proxy";

const PROXY_SECRET = "test-internal-shared-secret-32!!";
const TENANT = "11111111-1111-1111-1111-111111111111";
const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

function env(overrides: Record<string, unknown> = {}) {
  return createMockEnv({
    ALC_API_PROXY_SA_KEY: "{}", // resolveSecret が非空を返せばよい (oidc は mock)
    INTERNAL_SHARED_SECRET: PROXY_SECRET,
    ...overrides,
  });
}

function req(
  path: string,
  init: RequestInit & {
    proxySecret?: string | null;
    tenant?: string | null;
  } = {},
) {
  const headers: Record<string, string> = {};
  if (init.proxySecret !== null) headers["X-Alc-Proxy-Secret"] = init.proxySecret ?? PROXY_SECRET;
  if (init.tenant !== null) headers["X-Tenant-ID"] = init.tenant ?? TENANT;
  return new Request(`https://auth.test.example${path}`, {
    method: init.method ?? "GET",
    headers: { ...headers, ...(init.headers as Record<string, string>) },
    body: init.body,
  });
}

describe("handleAlcInternalProxy (rust-alc-api#434 step 3d, caller #4)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("X-Alc-Proxy-Secret 欠落は 401", async () => {
    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/dtako/tickets", { method: "POST", proxySecret: null }),
      env(),
    );
    expect(res.status).toBe(401);
  });

  it("X-Alc-Proxy-Secret 不一致は 401", async () => {
    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/dtako/tickets", { method: "POST", proxySecret: "wrong" }),
      env(),
    );
    expect(res.status).toBe(401);
  });

  it("INTERNAL_SHARED_SECRET 未 bind は 503 (fail-closed)", async () => {
    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/dtako/tickets", { method: "POST" }),
      env({ INTERNAL_SHARED_SECRET: undefined }),
    );
    expect(res.status).toBe(503);
  });

  it("ALC_API_PROXY_SA_KEY 未設定は 503", async () => {
    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/dtako/tickets", { method: "POST" }),
      env({ ALC_API_PROXY_SA_KEY: undefined }),
    );
    expect(res.status).toBe(503);
  });

  it("allowlist 外の path は 403 (data 経路への X-Tenant-ID 詐称を塞ぐ)", async () => {
    for (const p of [
      "/alc-internal-proxy/api/employees",
      "/alc-internal-proxy/api/dtako/vehicles",
      "/alc-internal-proxy/api/measurements",
      "/alc-internal-proxy/api/dtako/tickets/abc/other",
    ]) {
      const res = await handleAlcInternalProxy(req(p, { method: "POST" }), env());
      expect(res.status, p).toBe(403);
    }
  });

  it("X-Tenant-ID 欠落は 400", async () => {
    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/dtako/tickets", { method: "POST", tenant: null }),
      env(),
    );
    expect(res.status).toBe(400);
  });

  it("正常 (POST 起票): OIDC Bearer + X-Internal-Shared-Secret + X-Tenant-ID を付けて forward", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/dtako/tickets", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ a: 1 }),
      }),
      env(),
    );
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/dtako/tickets");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
    expect(h["X-Internal-Shared-Secret"]).toBe(PROXY_SECRET);
    expect(h["X-Tenant-ID"]).toBe(TENANT);
    expect(h["Content-Type"]).toBe("application/json");
    expect((init as RequestInit).method).toBe("POST");
    expect((init as RequestInit).body).toBeDefined();
  });

  it("正常 (PATCH scraped): allowlist を通り query も維持して forward", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/dtako/tickets/abc-123/scraped?x=1", {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ b: 2 }),
      }),
      env(),
    );
    expect(res.status).toBe(200);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/dtako/tickets/abc-123/scraped?x=1");
    expect((init as RequestInit).method).toBe("PATCH");
  });

  it("public-ingest (tenko-call/register): X-Tenant-ID なしでも 200、tenant/secret は forward しない", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/tenko-call/register", {
        method: "POST",
        tenant: null, // public-ingest は X-Tenant-ID 不要
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ call_number: "001", driver_name: "x" }),
      }),
      env(),
    );
    expect(res.status).toBe(200);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/tenko-call/register");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
    expect(h["X-Tenant-ID"]).toBeUndefined();
    expect(h["X-Internal-Shared-Secret"]).toBeUndefined();
  });

  it("public-ingest: 送られてきた X-Tenant-ID は strip して forward しない (詐称防止)", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/devices/register/claim", {
        method: "POST",
        tenant: "99999999-9999-9999-9999-999999999999", // 攻撃者が混入しても
        body: JSON.stringify({ registration_code: "abc" }),
      }),
      env(),
    );
    expect(res.status).toBe(200);
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBeUndefined(); // strip される
  });

  it("public-ingest も consumer proof は必須 (X-Alc-Proxy-Secret 欠落は 401)", async () => {
    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/tenko-call/tenko", { method: "POST", proxySecret: null }),
      env(),
    );
    expect(res.status).toBe(401);
  });

  it("OIDC mint 失敗は 502 (詳細は出さない)", async () => {
    const { mintGoogleIdToken } = await import("../../src/lib/oidc");
    (mintGoogleIdToken as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("boom"),
    );
    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/dtako/tickets", { method: "POST" }),
      env(),
    );
    expect(res.status).toBe(502);
  });
});
