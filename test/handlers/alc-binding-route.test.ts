import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { makeJwt } from "../helpers/live-env";
import { signTestJwt } from "../helpers/test-jwt";

vi.mock("../../src/lib/acl", () => ({
  checkOrgAccess: vi.fn(async () => true),
  checkAppTenant: vi.fn(() => true),
}));
vi.mock("../../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async () => "fake-oidc-token"),
}));

import { handleAlcProxy } from "../../src/handlers/alc-proxy";
import { handleDeviceDataProxy } from "../../src/handlers/device-data-proxy";
import { mintGoogleIdToken } from "../../src/lib/oidc";
import { resolveAlcBinding } from "../../src/lib/alc-backend-route";
import { DEVICE_ROLE_KIOSK } from "../../src/lib/device";

const ORIGIN = "https://alc.ippoan.org";
const PROXY_SECRET = "test-internal-shared-secret-32!!";
const TENANT = "11111111-1111-1111-1111-111111111111";
const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

function makeBinding() {
  return {
    fetch: vi.fn(async (_url: string, _init?: RequestInit) => new Response("from-binding", { status: 200 })),
  };
}

function setup(overrides: Record<string, unknown> = {}) {
  const binding = makeBinding();
  const cloudRun = vi.fn(async (_url: unknown, _init?: RequestInit) => new Response("from-cloud-run", { status: 200 }));
  globalThis.fetch = cloudRun as unknown as typeof fetch;
  const env = createMockEnv({
    ALC_API_PROXY_SA_KEY: "{}",
    INTERNAL_SHARED_SECRET: PROXY_SECRET,
    ALC_VEIN: binding as unknown as Fetcher,
    ...overrides,
  });
  return { binding, cloudRun, env };
}

function alcReq(path: string, init: RequestInit & { token?: string } = {}) {
  return new Request(`https://auth.test.example${path}`, {
    method: init.method ?? "POST",
    headers: {
      Authorization: `Bearer ${init.token ?? makeJwt(TEST_JWT_SECRET)}`,
      "X-Alc-Proxy-Origin": ORIGIN,
      "X-Alc-Proxy-Secret": PROXY_SECRET,
      ...(init.headers as Record<string, string>),
    },
    body: init.body,
  });
}

async function kioskReq(path: string, method: string, headers: Record<string, string> = {}) {
  const token = await signTestJwt(
    { sub: "device-kiosk-1", tenant_id: TENANT, role: DEVICE_ROLE_KIOSK },
    TEST_JWT_SECRET,
  );
  return new Request(`https://auth.test.example${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...headers },
    body: method === "GET" ? undefined : "{}",
  });
}

describe("resolveAlcBinding", () => {
  it("/api/vein 完全一致と /api/vein/ 始まりだけ一致、/api/vein-x は一致しない", () => {
    const { env } = setup();
    expect(resolveAlcBinding("/api/vein", env)).not.toBeNull();
    expect(resolveAlcBinding("/api/vein/identify", env)).not.toBeNull();
    expect(resolveAlcBinding("/api/vein-x/identify", env)).toBeNull();
    expect(resolveAlcBinding("/api/tenko/x", env)).toBeNull();
  });
});

describe("alc-proxy → ALC_VEIN binding", () => {
  beforeEach(() => {
    vi.mocked(mintGoogleIdToken).mockReset();
    vi.mocked(mintGoogleIdToken).mockResolvedValue("fake-oidc-token");
  });

  it("(a) /api/vein/identify は binding に届き Cloud Run / OIDC mint は呼ばれない", async () => {
    const { binding, cloudRun, env } = setup();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/vein/identify?x=1", { body: "{}" }), env);
    expect(await res.text()).toBe("from-binding");
    expect(binding.fetch).toHaveBeenCalledTimes(1);
    const [url, init] = binding.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-vein/api/vein/identify?x=1");
    expect(init!.redirect).toBe("manual");
    expect(cloudRun).not.toHaveBeenCalled();
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });

  it("(b) binding 未定義なら /api/vein/... も Cloud Run へ", async () => {
    const { binding, cloudRun, env } = setup({ ALC_VEIN: undefined });
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/vein/identify", { body: "{}" }), env);
    expect(await res.text()).toBe("from-cloud-run");
    expect(cloudRun).toHaveBeenCalledTimes(1);
    expect(binding.fetch).not.toHaveBeenCalled();
    const init = cloudRun.mock.calls[0]![1] as RequestInit;
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer fake-oidc-token");
  });

  it("Cloud Run 経路で OIDC mint が失敗したら 502 (binding 経路とは独立)", async () => {
    const { cloudRun, env } = setup();
    vi.mocked(mintGoogleIdToken).mockRejectedValueOnce(new Error("boom"));
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/tenko/x", { method: "GET" }), env);
    expect(res.status).toBe(502);
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("(c) 表に無い /api/tenko/... は binding があっても Cloud Run", async () => {
    const { binding, cloudRun, env } = setup();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/tenko/x", { method: "GET" }), env);
    expect(await res.text()).toBe("from-cloud-run");
    expect(cloudRun).toHaveBeenCalledTimes(1);
    expect(binding.fetch).not.toHaveBeenCalled();
  });

  it("(d) 未認証 / dev token の書き込み (#433) は binding に届かない", async () => {
    const { binding, env } = setup();
    const unauth = await handleAlcProxy(
      new Request("https://auth.test.example/alc-proxy/api/vein/identify", {
        method: "POST",
        headers: { "X-Alc-Proxy-Origin": ORIGIN, "X-Alc-Proxy-Secret": PROXY_SECRET },
      }),
      env,
    );
    expect(unauth.status).toBe(401);
    const ro = await handleAlcProxy(
      alcReq("/alc-proxy/api/vein/identify", {
        token: makeJwt(TEST_JWT_SECRET, { token_kind: "dev" }),
        body: "{}",
      }),
      env,
    );
    expect(ro.status).toBe(403);
    expect(binding.fetch).not.toHaveBeenCalled();
  });

  it("(e) client の X-Tenant-ID / X-User-ID は渡らず、付け直した値だけ。Authorization も渡らない", async () => {
    const { binding, env } = setup();
    await handleAlcProxy(
      alcReq("/alc-proxy/api/vein/identify", {
        body: "{}",
        headers: { "X-Tenant-ID": "evil-tenant", "X-User-ID": "evil-user", "X-User-Role": "root" },
      }),
      env,
    );
    const init = binding.fetch.mock.calls[0]![1]!;
    const h = init.headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).not.toBe("evil-tenant");
    expect(h["X-Tenant-ID"]).toBeTruthy();
    expect(h["X-User-ID"]).not.toBe("evil-user");
    expect(h["X-User-Role"]).toBe("admin");
    expect(Object.keys(h).map((k) => k.toLowerCase())).not.toContain("authorization");
  });

  // `%2e%2e` 単独は URL パーサが dot segment として正規化して消える。`%2e%2e%2f` (encoded slash 込み) は
  // 正規化されず pathname に残るので、こちらが handler の `%` ガードの対象。
  it("(f) %2e%2e%2f を含む path は 403 で binding に届かない", async () => {
    const { binding, env } = setup();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/vein/%2e%2e%2fadmin", { body: "{}" }), env);
    expect(res.status).toBe(403);
    expect(binding.fetch).not.toHaveBeenCalled();
  });

  it("OIDC mint が失敗しても binding 経路は 502 にならない", async () => {
    const { binding, env } = setup();
    vi.mocked(mintGoogleIdToken).mockRejectedValueOnce(new Error("boom"));
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/vein/identify", { body: "{}" }), env);
    expect(res.status).toBe(200);
    expect(binding.fetch).toHaveBeenCalledTimes(1);
  });
});

describe("device-data-proxy → ALC_VEIN binding", () => {
  beforeEach(() => {
    vi.mocked(mintGoogleIdToken).mockReset();
    vi.mocked(mintGoogleIdToken).mockResolvedValue("fake-oidc-token");
  });

  it("(a) kiosk の POST /api/vein/identify は binding へ (Authorization 無し・Cloud Run 不呼)", async () => {
    const { binding, cloudRun, env } = setup();
    const res = await handleDeviceDataProxy(
      await kioskReq("/device-data-proxy/api/vein/identify", "POST", {
        "X-Tenant-ID": "evil-tenant",
      }),
      env,
    );
    expect(await res.text()).toBe("from-binding");
    const [url, init] = binding.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-vein/api/vein/identify");
    const h = init!.headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBe(TENANT);
    expect(Object.keys(h).map((k) => k.toLowerCase())).not.toContain("authorization");
    expect(cloudRun).not.toHaveBeenCalled();
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });

  it("(b) binding 未定義なら Cloud Run", async () => {
    const { binding, cloudRun, env } = setup({ ALC_VEIN: undefined });
    const res = await handleDeviceDataProxy(
      await kioskReq("/device-data-proxy/api/vein/identify", "POST"),
      env,
    );
    expect(await res.text()).toBe("from-cloud-run");
    expect(cloudRun).toHaveBeenCalledTimes(1);
    expect(binding.fetch).not.toHaveBeenCalled();
  });

  it("(d) 許可表に無い vein の DELETE / 未認証は binding に届かない", async () => {
    const { binding, env } = setup();
    const del = await handleDeviceDataProxy(
      await kioskReq("/device-data-proxy/api/vein/templates/emp-1", "DELETE"),
      env,
    );
    expect(del.status).toBe(403);
    const unauth = await handleDeviceDataProxy(
      new Request("https://auth.test.example/device-data-proxy/api/vein/identify", {
        method: "POST",
      }),
      env,
    );
    expect(unauth.status).toBe(401);
    expect(binding.fetch).not.toHaveBeenCalled();
  });
});
