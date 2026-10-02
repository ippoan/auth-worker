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
vi.mock("../../src/lib/alc-internal", () => ({
  internalAuthToken: vi.fn(async () => "fake-internal-jwt"),
}));

import { handleAlcProxy } from "../../src/handlers/alc-proxy";
import { handleDeviceDataProxy } from "../../src/handlers/device-data-proxy";
import { handleAlcInternalProxy } from "../../src/handlers/alc-internal-proxy";
import { mintGoogleIdToken } from "../../src/lib/oidc";
import { resolveAlcBinding } from "../../src/lib/alc-backend-route";
import { DEVICE_ROLE_DTAKO_INGEST, DEVICE_ROLE_KIOSK } from "../../src/lib/device";

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
  const dtako = makeBinding();
  const cloudRun = vi.fn(async (_url: unknown, _init?: RequestInit) => new Response("from-cloud-run", { status: 200 }));
  globalThis.fetch = cloudRun as unknown as typeof fetch;
  const env = createMockEnv({
    ALC_API_PROXY_SA_KEY: "{}",
    INTERNAL_SHARED_SECRET: PROXY_SECRET,
    ALC_VEIN: binding as unknown as Fetcher,
    ALC_DTAKO: dtako as unknown as Fetcher,
    ...overrides,
  });
  return { binding, dtako, cloudRun, env };
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
    expect(resolveAlcBinding("/api/vein", env, "browser")).not.toBeNull();
    expect(resolveAlcBinding("/api/vein/identify", env, "browser")).not.toBeNull();
    expect(resolveAlcBinding("/api/vein-x/identify", env, "browser")).toBeNull();
    expect(resolveAlcBinding("/api/tenko/x", env, "browser")).toBeNull();
  });

  it("vein の行は画面用と端末用が引ける (内部用は引かない)。転送先は vein の binding と host", () => {
    const { binding, env } = setup();
    const target = { fetcher: binding, host: "alc-vein" };
    expect(resolveAlcBinding("/api/vein/identify", env, "browser")).toEqual(target);
    expect(resolveAlcBinding("/api/vein/identify", env, "device")).toEqual(target);
    expect(resolveAlcBinding("/api/vein/identify", env, "internal")).toBeNull();
  });

  it("/api/upload は完全一致だけ。下位の path・末尾 / 付きは一致しない", () => {
    const { dtako, env } = setup();
    expect(resolveAlcBinding("/api/upload", env, "browser")).toEqual({ fetcher: dtako, host: "alc-dtako" });
    expect(resolveAlcBinding("/api/upload/", env, "browser")).toBeNull();
    expect(resolveAlcBinding("/api/upload/face-photo", env, "browser")).toBeNull();
    expect(resolveAlcBinding("/api/uploads", env, "browser")).toBeNull();
  });

  it("/api/upload は画面用と内部用が引ける (端末用は引かない)", () => {
    const { env } = setup();
    expect(resolveAlcBinding("/api/upload", env, "browser")).not.toBeNull();
    expect(resolveAlcBinding("/api/upload", env, "internal")).not.toBeNull();
    expect(resolveAlcBinding("/api/upload", env, "device")).toBeNull();
  });

  it("/api/split-csv は末尾 / を外した完全一致と /api/split-csv/ 始まりが一致。/api/split-csv-all は完全一致だけ", () => {
    const { dtako, env } = setup();
    const target = { fetcher: dtako, host: "alc-dtako" };
    expect(resolveAlcBinding("/api/split-csv", env, "browser")).toEqual(target);
    expect(resolveAlcBinding("/api/split-csv/3f2b0c1e-0000-4000-8000-000000000001", env, "browser")).toEqual(target);
    expect(resolveAlcBinding("/api/split-csv-all", env, "browser")).toEqual(target);
    expect(resolveAlcBinding("/api/split-csv-allx", env, "browser")).toBeNull();
    expect(resolveAlcBinding("/api/split-csv-all/x", env, "browser")).toBeNull();
    // %2e%2e%2f を含む path も prefix には一致する (転送の手前で各 proxy が 403 にする)
    expect(resolveAlcBinding("/api/split-csv/%2e%2e%2fadmin", env, "browser")).toEqual(target);
  });

  it("分割の 2 口は画面用だけが引ける", () => {
    const { env } = setup();
    for (const path of ["/api/split-csv/x", "/api/split-csv-all"]) {
      expect(resolveAlcBinding(path, env, "internal")).toBeNull();
      expect(resolveAlcBinding(path, env, "device")).toBeNull();
    }
  });

  it("binding が未定義なら、どの行も null", () => {
    const { env } = setup({ ALC_VEIN: undefined, ALC_DTAKO: undefined });
    for (const proxy of ["browser", "internal", "device"] as const) {
      for (const path of ["/api/vein/identify", "/api/upload", "/api/split-csv/x", "/api/split-csv-all"]) {
        expect(resolveAlcBinding(path, env, proxy)).toBeNull();
      }
    }
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

describe("alc-proxy → ALC_DTAKO binding", () => {
  beforeEach(() => {
    vi.mocked(mintGoogleIdToken).mockReset();
    vi.mocked(mintGoogleIdToken).mockResolvedValue("fake-oidc-token");
  });

  it("(a) /api/upload は binding に届く (URL・付け直したヘッダ・body がそのまま)。Cloud Run / OIDC mint は呼ばれない", async () => {
    const { binding, dtako, cloudRun, env } = setup();
    const boundary = "----test";
    const multipart = `--${boundary}\r\ncontent\r\n--${boundary}--\r\n`;
    const res = await handleAlcProxy(
      alcReq("/alc-proxy/api/upload", {
        body: multipart,
        headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "X-Tenant-ID": "evil-tenant" },
      }),
      env,
    );
    expect(await res.text()).toBe("from-binding");
    expect(dtako.fetch).toHaveBeenCalledTimes(1);
    const [url, init] = dtako.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-dtako/api/upload");
    expect(init!.method).toBe("POST");
    expect(init!.redirect).toBe("manual");
    expect(new TextDecoder().decode(init!.body as ArrayBuffer)).toBe(multipart);
    const h = init!.headers as Record<string, string>;
    expect(Object.keys(h).sort()).toEqual(["Content-Type", "X-Tenant-ID", "X-User-Email", "X-User-ID", "X-User-Role"]);
    expect(h["Content-Type"]).toBe(`multipart/form-data; boundary=${boundary}`);
    expect(h["X-Tenant-ID"]).not.toBe("evil-tenant");
    expect(binding.fetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });

  it("(a) 分割の 2 口も binding に届く", async () => {
    const { dtako, cloudRun, env } = setup();
    const one = await handleAlcProxy(
      alcReq("/alc-proxy/api/split-csv/3f2b0c1e-0000-4000-8000-000000000001", {}),
      env,
    );
    expect(await one.text()).toBe("from-binding");
    const all = await handleAlcProxy(alcReq("/alc-proxy/api/split-csv-all", {}), env);
    expect(await all.text()).toBe("from-binding");
    expect(dtako.fetch.mock.calls.map((c) => c[0])).toEqual([
      "https://alc-dtako/api/split-csv/3f2b0c1e-0000-4000-8000-000000000001",
      "https://alc-dtako/api/split-csv-all",
    ]);
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("(b) binding 未定義なら /api/upload・分割の 2 口も Cloud Run へ", async () => {
    const { dtako, cloudRun, env } = setup({ ALC_DTAKO: undefined });
    for (const path of ["/api/upload", "/api/split-csv/x", "/api/split-csv-all"]) {
      const res = await handleAlcProxy(alcReq(`/alc-proxy${path}`, { body: "{}" }), env);
      expect(await res.text()).toBe("from-cloud-run");
    }
    expect(cloudRun.mock.calls.map((c) => String(c[0]))).toEqual([
      "https://alc-api.test.example/api/upload",
      "https://alc-api.test.example/api/split-csv/x",
      "https://alc-api.test.example/api/split-csv-all",
    ]);
    expect(dtako.fetch).not.toHaveBeenCalled();
  });

  it("(c) /api/upload の下位の path は binding があっても Cloud Run", async () => {
    const { dtako, cloudRun, env } = setup();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/upload/face-photo", { body: "{}" }), env);
    expect(await res.text()).toBe("from-cloud-run");
    expect(String(cloudRun.mock.calls[0]![0])).toBe("https://alc-api.test.example/api/upload/face-photo");
    expect(dtako.fetch).not.toHaveBeenCalled();
  });

  it("(d) 未認証 / dev token の書き込み (#433) は binding に届かない", async () => {
    const { dtako, env } = setup();
    const unauth = await handleAlcProxy(
      new Request("https://auth.test.example/alc-proxy/api/upload", {
        method: "POST",
        headers: { "X-Alc-Proxy-Origin": ORIGIN, "X-Alc-Proxy-Secret": PROXY_SECRET },
      }),
      env,
    );
    expect(unauth.status).toBe(401);
    for (const path of ["/api/upload", "/api/split-csv/x", "/api/split-csv-all"]) {
      const ro = await handleAlcProxy(
        alcReq(`/alc-proxy${path}`, { token: makeJwt(TEST_JWT_SECRET, { token_kind: "dev" }), body: "{}" }),
        env,
      );
      expect(ro.status).toBe(403);
    }
    expect(dtako.fetch).not.toHaveBeenCalled();
  });

  it("(f) %2e%2e%2f を含む path は 403 で binding に届かない", async () => {
    const { dtako, env } = setup();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/split-csv/%2e%2e%2fadmin", { body: "{}" }), env);
    expect(res.status).toBe(403);
    expect(dtako.fetch).not.toHaveBeenCalled();
  });
});

function internalReq(path: string, headers: Record<string, string> = {}, body = "zip-bytes") {
  return new Request(`https://auth.test.example${path}`, {
    method: "POST",
    headers: { "X-Alc-Proxy-Secret": PROXY_SECRET, "X-Tenant-ID": TENANT, ...headers },
    body,
  });
}

describe("alc-internal-proxy → ALC_DTAKO binding", () => {
  beforeEach(() => {
    vi.mocked(mintGoogleIdToken).mockReset();
    vi.mocked(mintGoogleIdToken).mockResolvedValue("fake-oidc-token");
  });

  it("(a) /api/upload は binding に届き、ヘッダは X-Tenant-ID と Content-Type の 2 つだけ。token は作らない", async () => {
    const { binding, dtako, cloudRun, env } = setup();
    // token を作る処理が失敗するようにしておく (binding 経路は呼ばないので 502 にならない)
    vi.mocked(mintGoogleIdToken).mockRejectedValue(new Error("boom"));
    const res = await handleAlcInternalProxy(
      internalReq("/alc-internal-proxy/api/upload?x=1", {
        "content-type": "multipart/form-data; boundary=x",
        Authorization: "Bearer caller-token",
        "X-Device-Dev": "1",
        "X-User-Role": "admin",
      }),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("from-binding");
    expect(dtako.fetch).toHaveBeenCalledTimes(1);
    const [url, init] = dtako.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-dtako/api/upload?x=1");
    expect(init!.method).toBe("POST");
    expect(init!.redirect).toBe("manual");
    expect(new TextDecoder().decode(init!.body as ArrayBuffer)).toBe("zip-bytes");
    expect(init!.headers).toEqual({
      "X-Tenant-ID": TENANT,
      "Content-Type": "multipart/form-data; boundary=x",
    });
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
    expect(binding.fetch).not.toHaveBeenCalled();
  });

  it("(a) Content-Type が無ければ X-Tenant-ID だけ。GET は body を付けない", async () => {
    const { dtako, env } = setup();
    await handleAlcInternalProxy(
      new Request("https://auth.test.example/alc-internal-proxy/api/upload", {
        method: "GET",
        headers: { "X-Alc-Proxy-Secret": PROXY_SECRET, "X-Tenant-ID": TENANT },
      }),
      env,
    );
    const init = dtako.fetch.mock.calls[0]![1]!;
    expect(init.headers).toEqual({ "X-Tenant-ID": TENANT });
    expect(init.method).toBe("GET");
    expect(init.body).toBeUndefined();
  });

  it("(b) binding 未定義なら今までどおり Cloud Run (token と共有の secret 付き)", async () => {
    const { dtako, cloudRun, env } = setup({ ALC_DTAKO: undefined });
    const res = await handleAlcInternalProxy(internalReq("/alc-internal-proxy/api/upload"), env);
    expect(await res.text()).toBe("from-cloud-run");
    const [url, init] = cloudRun.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/upload");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h.Authorization).toBe("Bearer fake-oidc-token");
    expect(h["X-Internal-Shared-Secret"]).toBe(PROXY_SECRET);
    expect(h["X-Tenant-ID"]).toBe(TENANT);
    expect(dtako.fetch).not.toHaveBeenCalled();
  });

  it("(c) 許可リストのほかの path は binding があっても今までどおり Cloud Run", async () => {
    const { binding, dtako, cloudRun, env } = setup();
    const res = await handleAlcInternalProxy(internalReq("/alc-internal-proxy/api/dtako/tickets"), env);
    expect(await res.text()).toBe("from-cloud-run");
    expect(String(cloudRun.mock.calls[0]![0])).toBe("https://alc-api.test.example/api/dtako/tickets");
    expect(dtako.fetch).not.toHaveBeenCalled();
    expect(binding.fetch).not.toHaveBeenCalled();
  });

  it("(d) secret の不一致・テナント無し・許可リストに無い path は binding に届かない", async () => {
    const { binding, dtako, cloudRun, env } = setup();
    const badSecret = await handleAlcInternalProxy(
      internalReq("/alc-internal-proxy/api/upload", { "X-Alc-Proxy-Secret": "wrong" }),
      env,
    );
    expect(badSecret.status).toBe(401);
    const noTenant = await handleAlcInternalProxy(
      new Request("https://auth.test.example/alc-internal-proxy/api/upload", {
        method: "POST",
        headers: { "X-Alc-Proxy-Secret": PROXY_SECRET },
        body: "zip-bytes",
      }),
      env,
    );
    expect(noTenant.status).toBe(400);
    for (const path of ["/api/upload/face-photo", "/api/split-csv/x", "/api/split-csv-all", "/api/vein/identify"]) {
      const res = await handleAlcInternalProxy(internalReq(`/alc-internal-proxy${path}`), env);
      expect(res.status).toBe(403);
    }
    expect(dtako.fetch).not.toHaveBeenCalled();
    expect(binding.fetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("device-data-proxy と ALC_DTAKO binding", () => {
  beforeEach(() => {
    vi.mocked(mintGoogleIdToken).mockReset();
    vi.mocked(mintGoogleIdToken).mockResolvedValue("fake-oidc-token");
  });

  it("端末用の /api/upload は binding があっても Cloud Run へ", async () => {
    const { binding, dtako, cloudRun, env } = setup();
    const token = await signTestJwt(
      { sub: "device-ingest-1", tenant_id: TENANT, role: DEVICE_ROLE_DTAKO_INGEST },
      TEST_JWT_SECRET,
    );
    const res = await handleDeviceDataProxy(
      new Request("https://auth.test.example/device-data-proxy/api/upload", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "content-type": "multipart/form-data; boundary=x" },
        body: "zip-bytes",
      }),
      env,
    );
    expect(await res.text()).toBe("from-cloud-run");
    const [url, init] = cloudRun.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/upload");
    expect(((init as RequestInit).headers as Record<string, string>).Authorization).toBe("Bearer fake-oidc-token");
    expect(dtako.fetch).not.toHaveBeenCalled();
    expect(binding.fetch).not.toHaveBeenCalled();
  });
});
