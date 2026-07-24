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

import { handleAlcProxy, validatePreviewBase } from "../../src/handlers/alc-proxy";
import { mintGoogleIdToken } from "../../src/lib/oidc";

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

  it("preview override: 妥当な tagged revision URL は forward 先 + OIDC aud を差し替える (Refs ippoan/ci-dashboard#472)", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const previewBase = "https://v1-2-3---rust-alc-api-747065218280.asia-northeast1.run.app";
    const res = await handleAlcProxy(
      req("/alc-proxy/api/employees", {
        headers: { "X-Alc-Preview-Api-Base": previewBase },
      }),
      env({
        ALC_API_PREVIEW_HOST_SUFFIX: "rust-alc-api-747065218280.asia-northeast1.run.app",
      }),
    );
    expect(res.status).toBe(200);
    const [url] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe(`${previewBase}/api/employees`);
    // OIDC aud も preview origin に切り替わる
    expect(vi.mocked(mintGoogleIdToken)).toHaveBeenLastCalledWith("{}", previewBase);
  });

  it("preview override: suffix 不一致 / 非 https / tag 無しは 400 (prod への silent fallback をしない)", async () => {
    const suffixEnv = env({
      ALC_API_PREVIEW_HOST_SUFFIX: "rust-alc-api-747065218280.asia-northeast1.run.app",
    });
    for (const bad of [
      "https://evil.example/",
      "https://v1---other-service-123.asia-northeast1.run.app",
      "http://v1---rust-alc-api-747065218280.asia-northeast1.run.app",
      "https://rust-alc-api-747065218280.asia-northeast1.run.app", // tag 無し (= prod と同じ)
      "not a url",
    ]) {
      const res = await handleAlcProxy(
        req("/alc-proxy/api/employees", { headers: { "X-Alc-Preview-Api-Base": bad } }),
        suffixEnv,
      );
      expect(res.status, bad).toBe(400);
    }
  });

  it("preview override: ALC_API_PREVIEW_HOST_SUFFIX 未設定なら override 要求は 400 (fail-closed)", async () => {
    const res = await handleAlcProxy(
      req("/alc-proxy/api/employees", {
        headers: {
          "X-Alc-Preview-Api-Base":
            "https://v1---rust-alc-api-747065218280.asia-northeast1.run.app",
        },
      }),
      env(),
    );
    expect(res.status).toBe(400);
  });

  it("token_kind=dev + POST は 403 dev_token_write_forbidden (issue #433)", async () => {
    const res = await handleAlcProxy(
      req("/alc-proxy/api/employees", {
        method: "POST",
        token: makeJwt(TEST_JWT_SECRET, { token_kind: "dev" }),
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ a: 1 }),
      }),
      env(),
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("dev_token_write_forbidden");
  });

  it("token_kind=dev + DELETE/PUT/PATCH も 403", async () => {
    for (const method of ["DELETE", "PUT", "PATCH"]) {
      const res = await handleAlcProxy(
        req("/alc-proxy/api/employees", {
          method,
          token: makeJwt(TEST_JWT_SECRET, { token_kind: "dev" }),
        }),
        env(),
      );
      expect(res.status, method).toBe(403);
    }
  });

  it("token_kind=dev + GET/HEAD は通す (read-only は許可)", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    for (const method of ["GET", "HEAD"]) {
      const res = await handleAlcProxy(
        req("/alc-proxy/api/employees", {
          method,
          token: makeJwt(TEST_JWT_SECRET, { token_kind: "dev" }),
        }),
        env(),
      );
      expect(res.status, method).toBe(200);
    }
  });

  it("token_kind 無し (通常 login token) の POST は forbidden にならない (回帰確認)", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleAlcProxy(
      req("/alc-proxy/api/employees", { method: "POST" }),
      env(),
    );
    expect(res.status).toBe(200);
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

describe("validatePreviewBase (pure)", () => {
  const SUFFIX = "rust-alc-api-747065218280.asia-northeast1.run.app";

  it("`<tag>---<suffix>` の https URL だけ origin を返す", () => {
    expect(validatePreviewBase(`https://v1-42-0---${SUFFIX}/api/x`, SUFFIX)).toBe(
      `https://v1-42-0---${SUFFIX}`,
    );
  });

  it("suffix 空 (未設定) は常に null", () => {
    expect(validatePreviewBase(`https://v1---${SUFFIX}`, "")).toBeNull();
  });

  it("tag が空 / 不正文字なら null", () => {
    expect(validatePreviewBase(`https://---${SUFFIX}`, SUFFIX)).toBeNull();
    expect(validatePreviewBase(`https://V1.x---${SUFFIX}`, SUFFIX)).toBeNull();
  });

  it("suffix を欺く host (evil.example?---suffix 等) は null", () => {
    expect(
      validatePreviewBase(`https://evil.example/?x=---${SUFFIX}`, SUFFIX),
    ).toBeNull();
    expect(validatePreviewBase(`https://v1---${SUFFIX}.evil.example`, SUFFIX)).toBeNull();
  });
});
