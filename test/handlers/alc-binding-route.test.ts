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
import {
  DEVICE_ROLE_BP_STATION,
  DEVICE_ROLE_DTAKO_INGEST,
  DEVICE_ROLE_DTAKO_RELAY,
  DEVICE_ROLE_KIOSK,
} from "../../src/lib/device";
import { internalAuthToken } from "../../src/lib/alc-internal";
import { sendDeviceNotify } from "../../src/lib/device-notify-send";
import { handleAdminNotifyApi } from "../../src/handlers/admin-notify-api";
import { handleLineUserDelete, handleLineUsersList } from "../../src/handlers/api-line-users";

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
  const leave = makeBinding();
  const lineworks = makeBinding();
  const notify = makeBinding();
  const cloudRun = vi.fn(async (_url: unknown, _init?: RequestInit) => new Response("from-cloud-run", { status: 200 }));
  globalThis.fetch = cloudRun as unknown as typeof fetch;
  const env = createMockEnv({
    ALC_API_PROXY_SA_KEY: "{}",
    INTERNAL_SHARED_SECRET: PROXY_SECRET,
    ALC_VEIN: binding as unknown as Fetcher,
    ALC_DTAKO: dtako as unknown as Fetcher,
    ALC_LEAVE: leave as unknown as Fetcher,
    ALC_LINEWORKS: lineworks as unknown as Fetcher,
    ALC_NOTIFY: notify as unknown as Fetcher,
    ...overrides,
  });
  return { binding, dtako, leave, lineworks, notify, cloudRun, env };
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

  it("/api/leave/ は画面用だけ ALC_LEAVE へ解決され、端末用・内部用は null (Cloud Run のまま)", () => {
    const { leave, env } = setup();
    expect(resolveAlcBinding("/api/leave/settings", env, "browser")).toEqual({ fetcher: leave, host: "rust-leave" });
    expect(resolveAlcBinding("/api/leave/settings", env, "device")).toBeNull();
    expect(resolveAlcBinding("/api/leave/settings", env, "internal")).toBeNull();
    expect(resolveAlcBinding("/api/leave-x/settings", env, "browser")).toBeNull();
  });

  it("/api/leave/ は binding 未定義なら null (従来どおり Cloud Run)", () => {
    const { env } = setup({ ALC_LEAVE: undefined });
    expect(resolveAlcBinding("/api/leave/settings", env, "browser")).toBeNull();
  });

  it("/api/fuel/ は画面用だけ FUEL_WORKER へ解決され、端末用・内部用は null (Refs yhonda-ohishi/nginx#814)", () => {
    const fuel = makeBinding();
    const { env } = setup({ FUEL_WORKER: fuel as unknown as Fetcher });
    expect(resolveAlcBinding("/api/fuel/intank", env, "browser")).toEqual({ fetcher: fuel, host: "rust-fuel-worker" });
    expect(resolveAlcBinding("/api/fuel/intank", env, "device")).toBeNull();
    expect(resolveAlcBinding("/api/fuel/intank", env, "internal")).toBeNull();
    expect(resolveAlcBinding("/api/fuel-x/intank", env, "browser")).toBeNull();
  });

  it("/api/fuel/ は binding 未定義なら null (staging は bind しないので Cloud Run のまま)", () => {
    const { env } = setup();
    expect(resolveAlcBinding("/api/fuel/intank", env, "browser")).toBeNull();
  });

  it("/api/upload は完全一致だけ。下位の path・末尾 / 付きは一致しない", () => {
    const { dtako, env } = setup();
    expect(resolveAlcBinding("/api/upload", env, "browser")).toEqual({ fetcher: dtako, host: "alc-dtako" });
    expect(resolveAlcBinding("/api/upload/", env, "browser")).toBeNull();
    expect(resolveAlcBinding("/api/upload/face-photo", env, "browser")).toBeNull();
    expect(resolveAlcBinding("/api/uploadsx", env, "browser")).toBeNull();
  });

  const READ_RERUN_PATHS = [
    "/api/uploads",
    "/api/internal/pending",
    "/api/internal/download/upload-1",
    "/api/internal/download",
    "/api/internal/rerun/upload-1",
    "/api/internal/rerun",
  ];

  it("履歴の読み取りとやり直しの口は画面用が引ける (一覧の 2 つは完全一致、id 付きの 2 つは prefix)", () => {
    const { dtako, env } = setup();
    const target = { fetcher: dtako, host: "alc-dtako" };
    for (const path of READ_RERUN_PATHS) {
      expect(resolveAlcBinding(path, env, "browser"), path).toEqual(target);
    }
  });

  it("履歴の読み取りとやり直しの口は、内部用と端末用からは引かない", () => {
    const { env } = setup();
    for (const path of READ_RERUN_PATHS) {
      expect(resolveAlcBinding(path, env, "internal"), path).toBeNull();
      expect(resolveAlcBinding(path, env, "device"), path).toBeNull();
    }
  });

  it("近い名前の別の path は一致しない", () => {
    const { env } = setup();
    for (const path of [
      "/api/internal/operations",
      "/api/internal/rls-check",
      "/api/internal/downloads",
      "/api/internal/reruns",
      "/api/internal",
      "/api/uploads/x",
      "/api/uploads/",
      "/api/upload/",
      "/api/internal/pending/x",
      "/api/internal/pending/",
    ]) {
      expect(resolveAlcBinding(path, env, "browser"), path).toBeNull();
    }
  });

  const RECALC_PATHS = ["/api/recalculate", "/api/recalculate-driver", "/api/recalculate-drivers"];

  it("再計算の 3 口は画面用が引ける (完全一致)", () => {
    const { dtako, env } = setup();
    for (const path of RECALC_PATHS) {
      expect(resolveAlcBinding(path, env, "browser"), path).toEqual({ fetcher: dtako, host: "alc-dtako" });
    }
  });

  it("再計算の 3 口は、内部用と端末用からは引かない", () => {
    const { env } = setup();
    for (const path of RECALC_PATHS) {
      expect(resolveAlcBinding(path, env, "internal"), path).toBeNull();
      expect(resolveAlcBinding(path, env, "device"), path).toBeNull();
    }
  });

  it("再計算の口に近い名前の別の path は一致しない", () => {
    const { env } = setup();
    for (const path of [
      "/api/recalculatex",
      "/api/recalculate/x",
      "/api/recalculate/",
      "/api/recalculate-driverx",
      "/api/recalculate-driver/",
      "/api/recalculate-driversx",
      "/api/recalculate-drivers/x",
    ]) {
      expect(resolveAlcBinding(path, env, "browser"), path).toBeNull();
    }
  });

  it("/api/recalculate-pending は画面用・内部用が引ける (完全一致)。端末用は引かない", () => {
    const { dtako, env } = setup();
    const target = { fetcher: dtako, host: "alc-dtako" };
    expect(resolveAlcBinding("/api/recalculate-pending", env, "browser")).toEqual(target);
    expect(resolveAlcBinding("/api/recalculate-pending", env, "internal")).toEqual(target);
    expect(resolveAlcBinding("/api/recalculate-pending", env, "device")).toBeNull();
    for (const path of ["/api/recalculate-pending/", "/api/recalculate-pending/x", "/api/recalculate-pendingx"]) {
      expect(resolveAlcBinding(path, env, "browser"), path).toBeNull();
      expect(resolveAlcBinding(path, env, "internal"), path).toBeNull();
    }
  });

  it("/api/upload は画面用・内部用・端末用のどれも引ける", () => {
    const { env } = setup();
    expect(resolveAlcBinding("/api/upload", env, "browser")).not.toBeNull();
    expect(resolveAlcBinding("/api/upload", env, "internal")).not.toBeNull();
    expect(resolveAlcBinding("/api/upload", env, "device")).not.toBeNull();
  });

  it("/api/split-csv は末尾 / を外した完全一致と /api/split-csv/ 始まりが一致。/api/split-csv-all は完全一致だけ", () => {
    const { dtako, env } = setup();
    const target = { fetcher: dtako, host: "alc-dtako" };
    expect(resolveAlcBinding("/api/split-csv", env, "browser")).toEqual(target);
    expect(resolveAlcBinding("/api/split-csv/upload-1", env, "browser")).toEqual(target);
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
      for (const path of [...READ_RERUN_PATHS, ...RECALC_PATHS, "/api/recalculate-pending"]) {
        expect(resolveAlcBinding(path, env, proxy), path).toBeNull();
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

  it("Range は binding へ渡し、206 と Content-Range はそのまま返す (動画のシーク)", async () => {
    const clips = {
      fetch: vi.fn(
        async (_url: string, _init?: RequestInit) =>
          new Response("part", { status: 206, headers: { "Content-Range": "bytes 0-3/100", "Accept-Ranges": "bytes" } }),
      ),
    };
    const { env } = setup({ ALC_CAM_CLIPS: clips as unknown as Fetcher });
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/cam-clips/clips/c/x.mp4", { method: "GET", headers: { Range: "bytes=0-3" } }), env);
    expect(res.status).toBe(206);
    expect(res.headers.get("content-range")).toBe("bytes 0-3/100");
    const init = clips.fetch.mock.calls[0]![1] as RequestInit;
    expect((init.headers as Record<string, string>).Range).toBe("bytes=0-3");
  });

  it("Range は Cloud Run 経路にも渡す。無ければ付けない", async () => {
    const { cloudRun, env } = setup();
    await handleAlcProxy(alcReq("/alc-proxy/api/tenko/x", { method: "GET", headers: { Range: "bytes=5-" } }), env);
    expect((cloudRun.mock.calls[0]![1]!.headers as Record<string, string>).Range).toBe("bytes=5-");
    await handleAlcProxy(alcReq("/alc-proxy/api/tenko/x", { method: "GET" }), env);
    expect((cloudRun.mock.calls[1]![1]!.headers as Record<string, string>).Range).toBeUndefined();
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
      alcReq("/alc-proxy/api/split-csv/upload-1", {}),
      env,
    );
    expect(await one.text()).toBe("from-binding");
    const all = await handleAlcProxy(alcReq("/alc-proxy/api/split-csv-all", {}), env);
    expect(await all.text()).toBe("from-binding");
    expect(dtako.fetch.mock.calls.map((c) => c[0])).toEqual([
      "https://alc-dtako/api/split-csv/upload-1",
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

  it("(a) 履歴の読み取りの GET は binding に届く (付くヘッダは既存の dtako の行と同じ。body は付かない)", async () => {
    const { binding, dtako, cloudRun, env } = setup();
    const paths = ["/api/uploads", "/api/internal/pending", "/api/internal/download/upload-1"];
    for (const path of paths) {
      const res = await handleAlcProxy(
        alcReq(`/alc-proxy${path}`, { method: "GET", headers: { "X-Tenant-ID": "evil-tenant" } }),
        env,
      );
      expect(await res.text()).toBe("from-binding");
    }
    expect(dtako.fetch.mock.calls.map((c) => c[0])).toEqual(paths.map((p) => `https://alc-dtako${p}`));
    for (const [, init] of dtako.fetch.mock.calls) {
      expect(init!.method).toBe("GET");
      expect(init!.redirect).toBe("manual");
      expect(init!.body).toBeUndefined();
      const h = init!.headers as Record<string, string>;
      expect(Object.keys(h).sort()).toEqual(["X-Tenant-ID", "X-User-Email", "X-User-ID", "X-User-Role"]);
      expect(h["X-Tenant-ID"]).not.toBe("evil-tenant");
    }
    expect(binding.fetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });

  it("(a) やり直しの POST は binding に届く", async () => {
    const { dtako, cloudRun, env } = setup();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/internal/rerun/upload-1", {}), env);
    expect(await res.text()).toBe("from-binding");
    const [url, init] = dtako.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-dtako/api/internal/rerun/upload-1");
    expect(init!.method).toBe("POST");
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("(b) binding 未定義なら履歴の読み取りとやり直しの口も Cloud Run へ", async () => {
    const { dtako, cloudRun, env } = setup({ ALC_DTAKO: undefined });
    const paths = ["/api/uploads", "/api/internal/pending", "/api/internal/download/upload-1"];
    for (const path of paths) {
      const res = await handleAlcProxy(alcReq(`/alc-proxy${path}`, { method: "GET" }), env);
      expect(await res.text()).toBe("from-cloud-run");
    }
    const rerun = await handleAlcProxy(alcReq("/alc-proxy/api/internal/rerun/upload-1", {}), env);
    expect(await rerun.text()).toBe("from-cloud-run");
    expect(cloudRun.mock.calls.map((c) => String(c[0]))).toEqual(
      [...paths, "/api/internal/rerun/upload-1"].map((p) => `https://alc-api.test.example${p}`),
    );
    expect(dtako.fetch).not.toHaveBeenCalled();
  });

  it("(d) 未認証 / dev token のやり直しの POST (#433) は binding に届かない", async () => {
    const { dtako, cloudRun, env } = setup();
    const unauth = await handleAlcProxy(
      new Request("https://auth.test.example/alc-proxy/api/uploads", {
        method: "GET",
        headers: { "X-Alc-Proxy-Origin": ORIGIN, "X-Alc-Proxy-Secret": PROXY_SECRET },
      }),
      env,
    );
    expect(unauth.status).toBe(401);
    const ro = await handleAlcProxy(
      alcReq("/alc-proxy/api/internal/rerun/upload-1", {
        token: makeJwt(TEST_JWT_SECRET, { token_kind: "dev" }),
      }),
      env,
    );
    expect(ro.status).toBe(403);
    expect(dtako.fetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("(f) %2e%2e%2f を含むダウンロード・やり直しの path は 403 で binding に届かない", async () => {
    const { dtako, env } = setup();
    for (const path of ["/api/internal/download/%2e%2e%2fadmin", "/api/internal/rerun/%2e%2e%2fadmin"]) {
      const res = await handleAlcProxy(alcReq(`/alc-proxy${path}`, { method: "GET" }), env);
      expect(res.status, path).toBe(403);
    }
    expect(dtako.fetch).not.toHaveBeenCalled();
  });

  it("(a) 再計算の 3 つの POST は binding に届く (URL・method・body がそのまま。付くヘッダは既存の dtako の行と同じ)", async () => {
    const { binding, dtako, cloudRun, env } = setup();
    const bodies: Record<string, string> = {
      "/api/recalculate": "",
      "/api/recalculate-driver": "",
      "/api/recalculate-drivers": JSON.stringify({ driver_ids: ["driver-1", "driver-2"] }),
    };
    const search: Record<string, string> = {
      "/api/recalculate": "?year=2026&month=9",
      "/api/recalculate-driver": "?year=2026&month=9&driver_id=driver-1",
      "/api/recalculate-drivers": "?year=2026&month=9",
    };
    for (const [path, body] of Object.entries(bodies)) {
      const res = await handleAlcProxy(
        alcReq(`/alc-proxy${path}${search[path]}`, {
          body: body || undefined,
          headers: { "content-type": "application/json", "X-Tenant-ID": "evil-tenant" },
        }),
        env,
      );
      expect(await res.text(), path).toBe("from-binding");
    }
    expect(dtako.fetch.mock.calls.map((c) => c[0])).toEqual(
      Object.keys(bodies).map((p) => `https://alc-dtako${p}${search[p]}`),
    );
    for (const [i, [, init]] of dtako.fetch.mock.calls.entries()) {
      expect(init!.method).toBe("POST");
      expect(init!.redirect).toBe("manual");
      const h = init!.headers as Record<string, string>;
      expect(Object.keys(h).sort()).toEqual(["Content-Type", "X-Tenant-ID", "X-User-Email", "X-User-ID", "X-User-Role"]);
      expect(h["Content-Type"]).toBe("application/json");
      expect(h["X-Tenant-ID"]).not.toBe("evil-tenant");
      const sent = init!.body ? new TextDecoder().decode(init!.body as ArrayBuffer) : "";
      expect(sent).toBe(Object.values(bodies)[i]);
    }
    expect(binding.fetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });

  it("(a) /api/recalculate-pending の POST は binding に届く (画面の JWT。X-Tenant-ID は JWT 由来に付け直す)", async () => {
    const { binding, dtako, cloudRun, env } = setup();
    const res = await handleAlcProxy(
      alcReq("/alc-proxy/api/recalculate-pending", { headers: { "X-Tenant-ID": "evil-tenant" } }),
      env,
    );
    expect(await res.text()).toBe("from-binding");
    expect(dtako.fetch).toHaveBeenCalledTimes(1);
    const [url, init] = dtako.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-dtako/api/recalculate-pending");
    expect(init!.method).toBe("POST");
    expect((init!.headers as Record<string, string>)["X-Tenant-ID"]).not.toBe("evil-tenant");
    expect(binding.fetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("(b) binding 未定義なら再計算の 3 口も Cloud Run へ", async () => {
    const { dtako, cloudRun, env } = setup({ ALC_DTAKO: undefined });
    const paths = ["/api/recalculate", "/api/recalculate-driver", "/api/recalculate-drivers"];
    for (const path of paths) {
      const res = await handleAlcProxy(alcReq(`/alc-proxy${path}`, { body: "{}" }), env);
      expect(await res.text()).toBe("from-cloud-run");
    }
    expect(cloudRun.mock.calls.map((c) => String(c[0]))).toEqual(
      paths.map((p) => `https://alc-api.test.example${p}`),
    );
    expect(dtako.fetch).not.toHaveBeenCalled();
  });

  it("(c) 再計算の口の下位の path は binding があっても Cloud Run", async () => {
    const { dtako, cloudRun, env } = setup();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/recalculate/x", { body: "{}" }), env);
    expect(await res.text()).toBe("from-cloud-run");
    expect(String(cloudRun.mock.calls[0]![0])).toBe("https://alc-api.test.example/api/recalculate/x");
    expect(dtako.fetch).not.toHaveBeenCalled();
  });

  it("(d) 閲覧専用の token (dev) の再計算の POST (#433) は 403 で binding に届かない", async () => {
    const { dtako, cloudRun, env } = setup();
    for (const path of ["/api/recalculate", "/api/recalculate-driver", "/api/recalculate-drivers"]) {
      const ro = await handleAlcProxy(
        alcReq(`/alc-proxy${path}`, { token: makeJwt(TEST_JWT_SECRET, { token_kind: "dev" }), body: "{}" }),
        env,
      );
      expect(ro.status, path).toBe(403);
    }
    expect(dtako.fetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
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

  it("(a) /api/upload は binding に届き、ヘッダは X-Tenant-ID と Content-Type (と dev端末の印) だけ。token は作らない", async () => {
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
      "X-Device-Dev": "1",
    });
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
    expect(binding.fetch).not.toHaveBeenCalled();
  });

  it("(a) dev端末の印は値がちょうど 1 のときだけ binding に渡す", async () => {
    for (const value of ["true", "0", ""]) {
      const { dtako, env } = setup();
      await handleAlcInternalProxy(internalReq("/alc-internal-proxy/api/upload", { "X-Device-Dev": value }), env);
      expect((dtako.fetch.mock.calls[0]![1]!.headers as Record<string, string>)["X-Device-Dev"], value).toBeUndefined();
    }
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
    const res = await handleAlcInternalProxy(internalReq("/alc-internal-proxy/api/hub/measurements"), env);
    expect(await res.text()).toBe("from-cloud-run");
    expect(String(cloudRun.mock.calls[0]![0])).toBe("https://alc-api.test.example/api/hub/measurements");
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
    for (const path of [
      "/api/upload/face-photo",
      "/api/split-csv/x",
      "/api/split-csv-all",
      "/api/vein/identify",
      "/api/uploads",
      "/api/internal/pending",
      "/api/internal/download/upload-1",
      "/api/internal/rerun/upload-1",
      "/api/recalculate",
      "/api/recalculate-driver",
      "/api/recalculate-drivers",
    ]) {
      const res = await handleAlcInternalProxy(internalReq(`/alc-internal-proxy${path}`), env);
      expect(res.status, path).toBe(403);
    }
    expect(dtako.fetch).not.toHaveBeenCalled();
    expect(binding.fetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("(e) /api/recalculate-pending は shared-secret + X-Tenant-ID で binding に届く。token は作らない", async () => {
    const { binding, dtako, cloudRun, env } = setup();
    vi.mocked(mintGoogleIdToken).mockRejectedValue(new Error("boom"));
    const res = await handleAlcInternalProxy(
      internalReq("/alc-internal-proxy/api/recalculate-pending", { "content-type": "application/json" }, "{}"),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("from-binding");
    const [url, init] = dtako.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-dtako/api/recalculate-pending");
    expect(init!.method).toBe("POST");
    expect(init!.headers).toEqual({ "X-Tenant-ID": TENANT, "Content-Type": "application/json" });
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
    expect(binding.fetch).not.toHaveBeenCalled();
  });

  it("(f) /api/recalculate-pending も secret 無し・不一致は 401、X-Tenant-ID 無しは 400、近い path は 403 で binding に届かない", async () => {
    const { binding, dtako, cloudRun, env } = setup();
    const path = "/alc-internal-proxy/api/recalculate-pending";
    const noSecret = await handleAlcInternalProxy(
      new Request(`https://auth.test.example${path}`, { method: "POST", headers: { "X-Tenant-ID": TENANT }, body: "{}" }),
      env,
    );
    expect(noSecret.status).toBe(401);
    const badSecret = await handleAlcInternalProxy(internalReq(path, { "X-Alc-Proxy-Secret": "wrong" }), env);
    expect(badSecret.status).toBe(401);
    const noTenant = await handleAlcInternalProxy(
      new Request(`https://auth.test.example${path}`, {
        method: "POST",
        headers: { "X-Alc-Proxy-Secret": PROXY_SECRET },
        body: "{}",
      }),
      env,
    );
    expect(noTenant.status).toBe(400);
    for (const p of ["/api/recalculate-pending/", "/api/recalculate-pending/x", "/api/recalculate-pendingx"]) {
      const res = await handleAlcInternalProxy(internalReq(`/alc-internal-proxy${p}`), env);
      expect(res.status, p).toBe(403);
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

  it("端末用の /api/upload は ALC_DTAKO の binding へ (Cloud Run には行かない)", async () => {
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
    expect(await res.text()).toBe("from-binding");
    expect(dtako.fetch).toHaveBeenCalledTimes(1);
    const [url, init] = dtako.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-dtako/api/upload");
    expect(init!.method).toBe("POST");
    expect((init!.headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
    expect(binding.fetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });
});

describe("LINE WORKS の送信の口 → ALC_LINEWORKS binding (Refs ohishi-exp/rust-leave-worker#1)", () => {
  const SEND = "/api/internal/lineworks/send";
  const FIRE = "/api/internal/trouble/schedules/11111111-2222-3333-4444-555555555555/fire";

  beforeEach(() => {
    vi.mocked(mintGoogleIdToken).mockReset();
    vi.mocked(mintGoogleIdToken).mockResolvedValue("fake-oidc-token");
    vi.mocked(internalAuthToken).mockReset();
    vi.mocked(internalAuthToken).mockResolvedValue("fake-internal-jwt");
  });

  it("表の行は内部用だけ ALC_LINEWORKS へ (完全一致)。画面用・端末用・近い path は null", () => {
    const { lineworks, env } = setup();
    expect(resolveAlcBinding(SEND, env, "internal")).toEqual({ fetcher: lineworks, host: "alc-lineworks" });
    expect(resolveAlcBinding(SEND, env, "browser")).toBeNull();
    expect(resolveAlcBinding(SEND, env, "device")).toBeNull();
    expect(resolveAlcBinding(`${SEND}/`, env, "internal")).toBeNull();
    expect(resolveAlcBinding("/api/internal/lineworks/token", env, "internal")).toBeNull();
    expect(resolveAlcBinding(SEND, setup({ ALC_LINEWORKS: undefined }).env, "internal")).toBeNull();
  });

  it("(a) alc-internal-proxy の internal-jwt の口は binding に届く。ヘッダは Content-Type だけ (X-Tenant-ID も渡さない)。token は作らない", async () => {
    const { lineworks, dtako, cloudRun, env } = setup();
    vi.mocked(internalAuthToken).mockRejectedValue(new Error("boom"));
    const body = JSON.stringify({ channel_id: "c1", text: "hi" });
    const res = await handleAlcInternalProxy(
      internalReq(
        `/alc-internal-proxy${SEND}`,
        { "content-type": "application/json", Authorization: "Bearer caller-token", "X-User-Role": "admin" },
        body,
      ),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("from-binding");
    expect(lineworks.fetch).toHaveBeenCalledTimes(1);
    const [url, init] = lineworks.fetch.mock.calls[0]!;
    expect(url).toBe(`https://alc-lineworks${SEND}`);
    expect(init!.method).toBe("POST");
    expect(init!.redirect).toBe("manual");
    expect(new TextDecoder().decode(init!.body as ArrayBuffer)).toBe(body);
    expect(init!.headers).toEqual({ "Content-Type": "application/json" });
    expect(internalAuthToken).not.toHaveBeenCalled();
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
    expect(dtako.fetch).not.toHaveBeenCalled();
  });

  it("(b) binding 未定義なら今までどおり Cloud Run (internal JWT 付き・X-Tenant-ID なし)", async () => {
    const { lineworks, cloudRun, env } = setup({ ALC_LINEWORKS: undefined });
    const res = await handleAlcInternalProxy(
      internalReq(`/alc-internal-proxy${SEND}`, { "content-type": "application/json" }, "{}"),
      env,
    );
    expect(await res.text()).toBe("from-cloud-run");
    const [url, init] = cloudRun.mock.calls[0]!;
    expect(String(url)).toBe(`https://alc-api.test.example${SEND}`);
    expect((init as RequestInit).headers).toEqual({
      Authorization: "Bearer fake-internal-jwt",
      "Content-Type": "application/json",
    });
    expect(lineworks.fetch).not.toHaveBeenCalled();
  });

  it("(c) GET・secret 不一致は binding に届かない。internal-jwt の別の口 (fire) は ALC_LINEWORKS へ行かない (ALC_TROUBLE 未定義なら Cloud Run)", async () => {
    const { lineworks, cloudRun, env } = setup();
    const get = await handleAlcInternalProxy(
      new Request(`https://auth.test.example/alc-internal-proxy${SEND}`, {
        method: "GET",
        headers: { "X-Alc-Proxy-Secret": PROXY_SECRET },
      }),
      env,
    );
    expect(get.status).toBe(403);
    const bad = await handleAlcInternalProxy(
      internalReq(`/alc-internal-proxy${SEND}`, { "X-Alc-Proxy-Secret": "wrong" }, "{}"),
      env,
    );
    expect(bad.status).toBe(401);
    expect(lineworks.fetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();

    const fire = await handleAlcInternalProxy(internalReq(`/alc-internal-proxy${FIRE}`, {}, "{}"), env);
    expect(await fire.text()).toBe("from-cloud-run");
    expect(String(cloudRun.mock.calls[0]![0])).toBe(`https://alc-api.test.example${FIRE}`);
    expect(lineworks.fetch).not.toHaveBeenCalled();
  });

  const DEPLOY_CHECK = "/api/lineworks/deploy-check";

  it("デプロイ確認の口 (exact) は画面用だけ ALC_LINEWORKS へ。内部用・端末用・管理画面用は null", () => {
    const { lineworks, env } = setup();
    expect(resolveAlcBinding(DEPLOY_CHECK, env, "browser")).toEqual({ fetcher: lineworks, host: "alc-lineworks" });
    expect(resolveAlcBinding(DEPLOY_CHECK, env, "internal")).toBeNull();
    expect(resolveAlcBinding(DEPLOY_CHECK, env, "device")).toBeNull();
    expect(resolveAlcBinding(DEPLOY_CHECK, env, "admin")).toBeNull();
  });

  it("デプロイ確認の口は、末尾の余り・頭の余り・.. ・前方一致を拾わない", () => {
    const { env } = setup();
    for (const path of [
      `${DEPLOY_CHECK}/`,
      `${DEPLOY_CHECK}x`,
      `${DEPLOY_CHECK}/x`,
      `${DEPLOY_CHECK}/..`,
      `/x${DEPLOY_CHECK}`,
      "/api/lineworks/x/../deploy-check",
      "/api/lineworks/deploy",
      "/api/lineworks",
      "/api/lineworks/",
    ]) {
      for (const proxy of ["browser", "internal", "device", "admin"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
  });

  it("デプロイ確認の口は binding が未定義なら null (= Cloud Run)", () => {
    const { env } = setup({ ALC_LINEWORKS: undefined });
    expect(resolveAlcBinding(DEPLOY_CHECK, env, "browser")).toBeNull();
  });

  it("(g) alc-proxy の GET /api/lineworks/deploy-check は binding に届く (付け直したヘッダだけ。Cloud Run / OIDC mint は呼ばれない)", async () => {
    const { lineworks, binding, cloudRun, env } = setup();
    const res = await handleAlcProxy(
      alcReq(`/alc-proxy${DEPLOY_CHECK}`, { method: "GET", headers: { "X-Tenant-ID": "evil-tenant" } }),
      env,
    );
    expect(await res.text()).toBe("from-binding");
    expect(lineworks.fetch).toHaveBeenCalledTimes(1);
    const [url, init] = lineworks.fetch.mock.calls[0]!;
    expect(url).toBe(`https://alc-lineworks${DEPLOY_CHECK}`);
    expect(init!.method).toBe("GET");
    expect(init!.redirect).toBe("manual");
    expect(init!.body).toBeUndefined();
    const h = init!.headers as Record<string, string>;
    expect(h.Authorization).toBeUndefined();
    expect(h["X-Tenant-ID"]).not.toBe("evil-tenant");
    expect(binding.fetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });

  it("(h) alc-proxy のデプロイ確認は binding 未定義なら Cloud Run。%2f%2e%2e を含む path は exact に一致せず binding に届かない", async () => {
    const off = setup({ ALC_LINEWORKS: undefined });
    const res = await handleAlcProxy(alcReq(`/alc-proxy${DEPLOY_CHECK}`, { method: "GET" }), off.env);
    expect(await res.text()).toBe("from-cloud-run");
    expect(String(off.cloudRun.mock.calls[0]![0])).toBe(`https://alc-api.test.example${DEPLOY_CHECK}`);

    const { lineworks, env } = setup();
    const unsafe = await handleAlcProxy(
      alcReq("/alc-proxy/api/lineworks/x%2f%2e%2e%2fdeploy-check", { method: "GET" }),
      env,
    );
    expect(await unsafe.text()).not.toBe("from-binding");
    expect(lineworks.fetch).not.toHaveBeenCalled();
  });

  it("(d) 端末通知 (sendDeviceNotify) も binding へ。{recipient_id, text} を Content-Type だけで送り、token は作らない", async () => {
    const { lineworks, cloudRun, env } = setup();
    vi.mocked(internalAuthToken).mockRejectedValue(new Error("boom"));
    const res = await sendDeviceNotify(env, "https://alc-api.test.example", "r1", "hello", { event: "t" });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("from-binding");
    const [url, init] = lineworks.fetch.mock.calls[0]!;
    expect(url).toBe(`https://alc-lineworks${SEND}`);
    expect(init!.method).toBe("POST");
    expect(init!.headers).toEqual({ "Content-Type": "application/json" });
    expect(JSON.parse(String(init!.body))).toEqual({ recipient_id: "r1", text: "hello" });
    expect(internalAuthToken).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("(e) 端末通知は binding 未定義なら今までどおり rust へ (internal JWT 付き)", async () => {
    const { cloudRun, env } = setup({ ALC_LINEWORKS: undefined });
    const res = await sendDeviceNotify(env, "https://alc-api.test.example/", "r1", "hello", { event: "t" });
    expect(await res.text()).toBe("from-cloud-run");
    const [url, init] = cloudRun.mock.calls[0]!;
    expect(String(url)).toBe(`https://alc-api.test.example${SEND}`);
    expect((init as RequestInit).headers).toEqual({
      Authorization: "Bearer fake-internal-jwt",
      "Content-Type": "application/json",
    });
  });

  it("(f) 端末通知の binding の失敗は今までどおり 502 (本文は返さない)", async () => {
    const { lineworks, env } = setup();
    lineworks.fetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: "recipient_not_found" }), { status: 404 }),
    );
    const res = await sendDeviceNotify(env, "https://alc-api.test.example", "r1", "hello", { event: "t" });
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ error: "upstream error" });
  });
});

describe("notify の口 → ALC_NOTIFY binding (Refs ippoan/rust-alc-api#747)", () => {
  /** UUID の形 (8-4-4-4-12) を 1 文字の繰り返しで組み立てる。 */
  const uuidOf = (c: string) => [8, 4, 4, 4, 12].map((n) => c.repeat(n)).join("-");
  const DOC = uuidOf("a");
  const DISTRIBUTE = `/api/notify/documents/${DOC}/distribute`;
  const RID = uuidOf("2");
  /** worker (ippoan/alc-notify-worker の crates/notify) に在る口のうち、画面用と管理画面用の両方が引くもの。 */
  const SHARED_PATHS = [
    "/api/notify/recipients",
    "/api/notify/recipients/bulk",
    `/api/notify/recipients/${RID}`,
    "/api/notify/groups",
    `/api/notify/groups/${RID}`,
    `/api/notify/groups/${RID}/members`,
    `/api/notify/groups/${RID}/members/${RID}`,
    "/api/notify/lineworks/channels",
    `/api/notify/lineworks/channels/${RID}`,
    `/api/notify/lineworks/channels/${RID}/test-send`,
    "/api/notify/line-config",
    "/api/notify/lineworks/users",
    "/api/notify/lineworks/login-activity",
    "/api/notify/test-distribute",
    "/api/notify/employees",
    "/api/notify/recipients/link-employees-by-name",
  ];
  /** Cloud Run に残る notify の口と、近い名前の path (表が拾ってはいけない)。 */
  const CLOUD_RUN_PATHS = [
    "/api/notify/documents",
    "/api/notify/documents/search",
    "/api/notify/documents/upload",
    `/api/notify/documents/${DOC}`,
    `/api/notify/documents/${DOC}/preview`,
    `/api/notify/documents/${DOC}/download`,
    `/api/notify/documents/${DOC}/redact-recompute`,
    `/api/notify/documents/${DOC}/extract-recompute`,
    "/api/notify/ingest",
    "/api/notify/emails",
    "/api/notify/line/webhook",
    "/api/notify/read/tok",
    "/api/notify/v/tok",
    "/api/notify/v/tok/file",
    "/api/notify/register-view",
    "/api/notify/test/redact-pdf",
    "/api/notify/lineworks",
    "/api/notify/lineworks/",
    "/api/notify/lineworks/users/x",
    "/api/notify/lineworks/login-activity/x",
    "/api/notify/line-config/x",
    "/api/notify/test-distribute/x",
    "/api/notify/recipientsx",
    "/api/notify/groupsx",
    "/api/notify/lineworks/channelsx",
    "/api/internal/lineworks/bot-secret",
    "/api/internal/lineworks/event",
  ];

  beforeEach(() => {
    vi.mocked(mintGoogleIdToken).mockReset();
    vi.mocked(mintGoogleIdToken).mockResolvedValue("fake-oidc-token");
  });

  it("worker に在る口は、画面用と管理画面用が ALC_NOTIFY へ解決される。内部用・端末用は null", () => {
    const { notify, env } = setup();
    const target = { fetcher: notify, host: "alc-notify" };
    for (const path of SHARED_PATHS) {
      expect(resolveAlcBinding(path, env, "browser"), path).toEqual(target);
      expect(resolveAlcBinding(path, env, "admin"), path).toEqual(target);
      expect(resolveAlcBinding(path, env, "internal"), path).toBeNull();
      expect(resolveAlcBinding(path, env, "device"), path).toBeNull();
    }
  });

  it("文書の配信 (pattern) は画面用だけ。管理画面用・内部用・端末用は null", () => {
    const { notify, env } = setup();
    expect(resolveAlcBinding(DISTRIBUTE, env, "browser")).toEqual({ fetcher: notify, host: "alc-notify" });
    expect(resolveAlcBinding(DISTRIBUTE, env, "admin")).toBeNull();
    expect(resolveAlcBinding(DISTRIBUTE, env, "internal")).toBeNull();
    expect(resolveAlcBinding(DISTRIBUTE, env, "device")).toBeNull();
  });

  it("文書の配信の pattern は、UUID でない id・末尾の余り・頭の余り・.. を拾わない", () => {
    const { env } = setup();
    for (const path of [
      "/api/notify/documents/not-a-uuid/distribute",
      `/api/notify/documents/${DOC}x/distribute`,
      `/api/notify/documents/${DOC.toUpperCase()}/distribute`,
      `/api/notify/documents/${DOC}/distribute/`,
      `/api/notify/documents/${DOC}/distributex`,
      `/api/notify/documents/${DOC}/distribute/x`,
      `/x/api/notify/documents/${DOC}/distribute`,
      `/api/notify/documents/../${DOC.slice(3)}/distribute`,
      `/api/notify/documents/${DOC}/../distribute`,
      "/api/notify/documents//distribute",
    ]) {
      expect(resolveAlcBinding(path, env, "browser"), path).toBeNull();
    }
  });

  it("Cloud Run に残る notify の口 (文書の他の口・ingest・viewer・webhook・既読・内部の LINE WORKS) は回らない", () => {
    const { env } = setup();
    for (const path of CLOUD_RUN_PATHS) {
      for (const proxy of ["browser", "admin", "internal", "device"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
  });

  it("binding が未定義なら、どの行も null (= Cloud Run)", () => {
    const { env } = setup({ ALC_NOTIFY: undefined });
    for (const path of [...SHARED_PATHS, DISTRIBUTE]) {
      expect(resolveAlcBinding(path, env, "browser"), path).toBeNull();
      expect(resolveAlcBinding(path, env, "admin"), path).toBeNull();
    }
  });

  it("(a) alc-proxy の文書の配信は binding に届く (付け直したヘッダだけ。Authorization は渡さない)", async () => {
    const { notify, cloudRun, env } = setup();
    const res = await handleAlcProxy(alcReq(`/alc-proxy${DISTRIBUTE}`, { body: "{}" }), env);
    expect(await res.text()).toBe("from-binding");
    const [url, init] = notify.fetch.mock.calls[0]!;
    expect(url).toBe(`https://alc-notify${DISTRIBUTE}`);
    const h = init!.headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBeTruthy();
    expect(Object.keys(h).map((k) => k.toLowerCase())).not.toContain("authorization");
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("(b) alc-proxy の Cloud Run に残る口 (文書の一覧) は binding があっても Cloud Run", async () => {
    const { notify, cloudRun, env } = setup();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/notify/documents", { method: "GET" }), env);
    expect(await res.text()).toBe("from-cloud-run");
    expect(cloudRun).toHaveBeenCalledTimes(1);
    expect(notify.fetch).not.toHaveBeenCalled();
  });

  it("(c) alc-proxy の %2e%2e%2f を含む notify の path は 403 で binding に届かない", async () => {
    const { notify, env } = setup();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/notify/recipients/%2e%2e%2fx", { method: "GET" }), env);
    expect(res.status).toBe(403);
    expect(notify.fetch).not.toHaveBeenCalled();
  });

  function adminReq(path: string, init: RequestInit = {}) {
    return new Request(`https://auth.test.example${path}`, {
      method: init.method ?? "GET",
      headers: { Authorization: `Bearer ${makeJwt(TEST_JWT_SECRET)}`, ...(init.headers as Record<string, string>) },
      body: init.body,
    });
  }

  it("(d) admin-notify-api は binding へ。X-Tenant-ID / X-User-* を付け、Cloud Run 用の Authorization は付けない", async () => {
    const { notify, cloudRun, env } = setup();
    const body = JSON.stringify({ name: "g" });
    const res = await handleAdminNotifyApi(
      adminReq("/admin/notify/api/notify/groups?x=1", {
        method: "POST",
        body,
        headers: { "Content-Type": "application/json" },
      }),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("from-binding");
    const [url, init] = notify.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-notify/api/notify/groups?x=1");
    expect(init!.method).toBe("POST");
    expect(init!.redirect).toBe("manual");
    expect(init!.body).toBe(body);
    const h = init!.headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBe(TENANT);
    expect(h["X-User-Role"]).toBe("admin");
    expect(h["X-User-ID"]).toBeTruthy();
    expect(h["Content-Type"]).toBe("application/json");
    expect(Object.keys(h).map((k) => k.toLowerCase())).not.toContain("authorization");
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("(e) admin-notify-api の表に無い口・文書の配信 (画面用だけの行) は binding があっても Cloud Run (OIDC 付き)", async () => {
    const { notify, cloudRun, env } = setup();
    for (const path of ["/api/notify/documents", DISTRIBUTE]) {
      await handleAdminNotifyApi(adminReq(`/admin/notify${path}`, { method: "POST", body: "{}" }), env);
    }
    expect(notify.fetch).not.toHaveBeenCalled();
    expect(cloudRun).toHaveBeenCalledTimes(2);
    expect(String(cloudRun.mock.calls[0]![0])).toBe("https://alc-api.test.example/api/notify/documents");
    expect(String(cloudRun.mock.calls[1]![0])).toBe(`https://alc-api.test.example${DISTRIBUTE}`);
    const h = (cloudRun.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h.Authorization).toBe("Bearer fake-oidc-token");
    expect(h["X-Tenant-ID"]).toBe(TENANT);
  });

  it("(f) admin-notify-api は binding 未定義なら今までどおり Cloud Run", async () => {
    const { notify, cloudRun, env } = setup({ ALC_NOTIFY: undefined });
    const res = await handleAdminNotifyApi(adminReq("/admin/notify/api/notify/lineworks/users"), env);
    expect(await res.text()).toBe("from-cloud-run");
    expect(String(cloudRun.mock.calls[0]![0])).toBe("https://alc-api.test.example/api/notify/lineworks/users");
    expect(notify.fetch).not.toHaveBeenCalled();
  });

  it("(g) admin-notify-api の %2e%2e%2f を含む path は 403 で binding に届かない", async () => {
    const { notify, cloudRun, env } = setup();
    const res = await handleAdminNotifyApi(adminReq("/admin/notify/api/notify/recipients/%2e%2e%2fx"), env);
    expect(res.status).toBe(403);
    expect(notify.fetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("(h) api-line-users の一覧と削除は binding へ (X-Tenant-ID 付き・Authorization なし)", async () => {
    const { notify, cloudRun, env } = setup();
    notify.fetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify([
          { id: "r1", name: "a", line_user_id: "U1", enabled: true },
          { id: "r2", name: "b", line_user_id: null, enabled: true },
        ]),
        { status: 200 },
      ),
    );
    const list = await handleLineUsersList(adminReq("/api/line-users/list", { method: "POST" }), env);
    expect(await list.json()).toEqual({ recipients: [{ id: "r1", name: "a", lineUserId: "U1", enabled: true }] });
    const del = await handleLineUserDelete(
      adminReq("/api/line-users/delete", { method: "POST", body: JSON.stringify({ id: RID }) }),
      env,
    );
    expect(await del.json()).toEqual({ success: true });

    expect(notify.fetch).toHaveBeenCalledTimes(2);
    const [listUrl, listInit] = notify.fetch.mock.calls[0]!;
    expect(listUrl).toBe("https://alc-notify/api/notify/recipients");
    expect(listInit!.method).toBe("GET");
    const [delUrl, delInit] = notify.fetch.mock.calls[1]!;
    expect(delUrl).toBe(`https://alc-notify/api/notify/recipients/${RID}`);
    expect(delInit!.method).toBe("DELETE");
    for (const init of [listInit, delInit]) {
      const h = init!.headers as Record<string, string>;
      expect(h["X-Tenant-ID"]).toBe(TENANT);
      expect(Object.keys(h).map((k) => k.toLowerCase())).not.toContain("authorization");
    }
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("(i) api-line-users は binding 未定義なら今までどおり Cloud Run (OIDC 付き)", async () => {
    const { cloudRun, env } = setup({ ALC_NOTIFY: undefined });
    cloudRun.mockResolvedValueOnce(new Response("[]", { status: 200 }));
    await handleLineUsersList(adminReq("/api/line-users/list", { method: "POST" }), env);
    await handleLineUserDelete(
      adminReq("/api/line-users/delete", { method: "POST", body: JSON.stringify({ id: RID }) }),
      env,
    );
    expect(String(cloudRun.mock.calls[0]![0])).toBe("https://alc-api.test.example/api/notify/recipients");
    expect(String(cloudRun.mock.calls[1]![0])).toBe(`https://alc-api.test.example/api/notify/recipients/${RID}`);
    expect((cloudRun.mock.calls[1]![1] as RequestInit).method).toBe("DELETE");
    const h = (cloudRun.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h.Authorization).toBe("Bearer fake-oidc-token");
  });

  it("(j) api-line-users の削除で id が encode されて % を含む path は 403 で binding に届かない", async () => {
    const { notify, env } = setup();
    const res = await handleLineUserDelete(
      adminReq("/api/line-users/delete", { method: "POST", body: JSON.stringify({ id: "../x" }) }),
      env,
    );
    expect(res.status).toBe(403);
    expect(notify.fetch).not.toHaveBeenCalled();
  });
});

describe("trouble の口 → ALC_TROUBLE binding (Refs ippoan/rust-alc-api#747)", () => {
  /** UUID の形 (8-4-4-4-12) を 1 文字の繰り返しで組み立てる。 */
  const uuidOf = (c: string) => [8, 4, 4, 4, 12].map((n) => c.repeat(n)).join("-");
  const ID = uuidOf("b");
  const FIRE = `/api/internal/trouble/schedules/${ID}/fire`;
  /** worker (ippoan/alc-trouble-worker の crates/trouble) の router に在る口 (rust の trouble の口と同じ集合)。 */
  const TROUBLE_PATHS = [
    "/api/trouble",
    "/api/trouble/categories",
    `/api/trouble/categories/${ID}`,
    "/api/trouble/offices",
    `/api/trouble/offices/${ID}`,
    "/api/trouble/progress-statuses",
    `/api/trouble/progress-statuses/${ID}`,
    "/api/trouble/task-types",
    `/api/trouble/task-types/${ID}`,
    "/api/trouble/task-statuses",
    `/api/trouble/task-statuses/${ID}`,
    "/api/trouble/field-layout",
    "/api/trouble/notification-prefs",
    `/api/trouble/notification-prefs/${ID}`,
    "/api/trouble/tickets",
    "/api/trouble/tickets/csv",
    `/api/trouble/tickets/${ID}`,
    `/api/trouble/tickets/${ID}/transition`,
    `/api/trouble/tickets/${ID}/history`,
    `/api/trouble/tickets/${ID}/tasks`,
    `/api/trouble/tickets/${ID}/tasks/reorder`,
    `/api/trouble/tickets/${ID}/files`,
    `/api/trouble/tickets/${ID}/files/trash`,
    `/api/trouble/tickets/${ID}/schedules`,
    "/api/trouble/workflow/setup",
    "/api/trouble/workflow/states",
    `/api/trouble/workflow/states/${ID}`,
    "/api/trouble/workflow/transitions",
    `/api/trouble/workflow/transitions/${ID}`,
    "/api/trouble/tasks",
    `/api/trouble/tasks/${ID}`,
    `/api/trouble/tasks/${ID}/files`,
    `/api/trouble/files/${ID}`,
    `/api/trouble/files/${ID}/download`,
    `/api/trouble/files/${ID}/restore`,
    `/api/trouble/task-files/${ID}`,
    `/api/trouble/task-files/${ID}/download`,
    "/api/trouble/schedules",
    `/api/trouble/schedules/${ID}`,
    "/api/trouble/lineworks/members",
  ];

  beforeEach(() => {
    vi.mocked(mintGoogleIdToken).mockReset();
    vi.mocked(mintGoogleIdToken).mockResolvedValue("fake-oidc-token");
    vi.mocked(internalAuthToken).mockReset();
    vi.mocked(internalAuthToken).mockResolvedValue("fake-internal-jwt");
  });

  function setupTrouble(overrides: Record<string, unknown> = {}) {
    const trouble = makeBinding();
    return { trouble, ...setup({ ALC_TROUBLE: trouble as unknown as Fetcher, ...overrides }) };
  }

  it("/api/trouble/ の口は画面用だけ ALC_TROUBLE へ。内部用・端末用・管理画面用は null", () => {
    const { trouble, env } = setupTrouble();
    const target = { fetcher: trouble, host: "alc-trouble" };
    for (const path of TROUBLE_PATHS) {
      expect(resolveAlcBinding(path, env, "browser"), path).toEqual(target);
      expect(resolveAlcBinding(path, env, "internal"), path).toBeNull();
      expect(resolveAlcBinding(path, env, "device"), path).toBeNull();
      expect(resolveAlcBinding(path, env, "admin"), path).toBeNull();
    }
  });

  it("/api/trouble の近い名前 (/api/troublex・/api/trouble-x) は回らない", () => {
    const { env } = setupTrouble();
    for (const path of ["/api/troublex", "/api/trouble-x", "/api/troubles/tickets"]) {
      expect(resolveAlcBinding(path, env, "browser"), path).toBeNull();
    }
  });

  it("予約の発火 (pattern) は内部用だけ ALC_TROUBLE へ。大文字の UUID も内部用の分類と同じく拾う。画面用・端末用・管理画面用は null", () => {
    const { trouble, env } = setupTrouble();
    const target = { fetcher: trouble, host: "alc-trouble" };
    expect(resolveAlcBinding(FIRE, env, "internal")).toEqual(target);
    expect(resolveAlcBinding(FIRE.replace(ID, ID.toUpperCase()), env, "internal")).toEqual(target);
    expect(resolveAlcBinding(FIRE, env, "browser")).toBeNull();
    expect(resolveAlcBinding(FIRE, env, "device")).toBeNull();
    expect(resolveAlcBinding(FIRE, env, "admin")).toBeNull();
  });

  it("発火の pattern は、UUID でない id・末尾の余り・頭の余り・.. を拾わない", () => {
    const { env } = setupTrouble();
    for (const path of [
      "/api/internal/trouble/schedules/not-a-uuid/fire",
      `/api/internal/trouble/schedules/${ID}x/fire`,
      `/api/internal/trouble/schedules/${ID}/fire/`,
      `/api/internal/trouble/schedules/${ID}/firex`,
      `/api/internal/trouble/schedules/${ID}/fire/x`,
      `/x/api/internal/trouble/schedules/${ID}/fire`,
      `/api/internal/trouble/schedules/../${ID.slice(3)}/fire`,
      `/api/internal/trouble/schedules/${ID}/../fire`,
      "/api/internal/trouble/schedules//fire",
      `/api/internal/trouble/schedules/${ID}`,
      "/api/internal/trouble/schedules",
    ]) {
      for (const proxy of ["browser", "internal", "device", "admin"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
  });

  it("binding が未定義なら、どの行も null (= Cloud Run)", () => {
    const { env } = setup();
    for (const path of TROUBLE_PATHS) {
      expect(resolveAlcBinding(path, env, "browser"), path).toBeNull();
    }
    expect(resolveAlcBinding(FIRE, env, "internal")).toBeNull();
  });

  it("(a) alc-proxy の trouble の口は binding に届く (付け直したヘッダだけ。Authorization は渡さない)", async () => {
    const { trouble, cloudRun, env } = setupTrouble();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/trouble/tickets?status=open", { method: "GET" }), env);
    expect(await res.text()).toBe("from-binding");
    const [url, init] = trouble.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-trouble/api/trouble/tickets?status=open");
    const h = init!.headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBeTruthy();
    expect(Object.keys(h).map((k) => k.toLowerCase())).not.toContain("authorization");
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("(b) alc-proxy の %2e%2e%2f を含む trouble の path は 403 で binding に届かない", async () => {
    const { trouble, env } = setupTrouble();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/trouble/tickets/%2e%2e%2fx", { method: "GET" }), env);
    expect(res.status).toBe(403);
    expect(trouble.fetch).not.toHaveBeenCalled();
  });

  it("(c) alc-internal-proxy の発火は binding に届く。ALC_LINEWORKS へは行かず、token は作らない", async () => {
    const { trouble, lineworks, cloudRun, env } = setupTrouble();
    vi.mocked(internalAuthToken).mockRejectedValue(new Error("boom"));
    const res = await handleAlcInternalProxy(
      internalReq(`/alc-internal-proxy${FIRE}`, { "content-type": "application/json" }, "{}"),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("from-binding");
    const [url, init] = trouble.fetch.mock.calls[0]!;
    expect(url).toBe(`https://alc-trouble${FIRE}`);
    expect(init!.method).toBe("POST");
    expect(init!.redirect).toBe("manual");
    expect(init!.headers).toEqual({ "Content-Type": "application/json" });
    expect(internalAuthToken).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
    expect(lineworks.fetch).not.toHaveBeenCalled();
  });

  it("(d) alc-internal-proxy の発火は binding 未定義なら今までどおり Cloud Run (internal JWT 付き)", async () => {
    const { cloudRun, env } = setup();
    const res = await handleAlcInternalProxy(internalReq(`/alc-internal-proxy${FIRE}`, {}, "{}"), env);
    expect(await res.text()).toBe("from-cloud-run");
    expect(String(cloudRun.mock.calls[0]![0])).toBe(`https://alc-api.test.example${FIRE}`);
  });
});

describe("拠点カメラの切り出し → ALC_CAM_CLIPS binding (ippoan/alc-cam)", () => {
  it("/api/cam-clips/ は画面用と端末用が ALC_CAM_CLIPS へ。内部用・管理画面用と近い名前は null", () => {
    const clips = makeBinding();
    const { env } = setup({ ALC_CAM_CLIPS: clips as unknown as Fetcher });
    const target = { fetcher: clips, host: "alc-cam-sd-ingest" };
    // 端末用で通せる口は device-data-proxy の許可表 (運行管理者席の GET /cameras だけ) が絞る
    for (const path of [
      "/api/cam-clips/cameras",
      "/api/cam-clips/clips",
      "/api/cam-clips/clips/TS-NS320W-55/20261023T125800_20261023T125930.mp4",
    ]) {
      expect(resolveAlcBinding(path, env, "browser"), path).toEqual(target);
      expect(resolveAlcBinding(path, env, "device"), path).toEqual(target);
      expect(resolveAlcBinding(path, env, "internal"), path).toBeNull();
      expect(resolveAlcBinding(path, env, "admin"), path).toBeNull();
    }
    expect(resolveAlcBinding("/api/cam-clipsx", env, "browser")).toBeNull();
    expect(resolveAlcBinding("/api/cam-clipsx", env, "device")).toBeNull();
  });

  it("binding が無ければ null (= Cloud Run)", () => {
    const { env } = setup({});
    expect(resolveAlcBinding("/api/cam-clips/clips", env, "browser")).toBeNull();
  });
});

describe("測定の口 → ALC_MEASUREMENTS binding (Refs ippoan/alc-app#436)", () => {
  /** UUID の形 (8-4-4-4-12) を 1 文字の繰り返しで組み立てる。 */
  const uuidOf = (c: string) => [8, 4, 4, 4, 12].map((n) => c.repeat(n)).join("-");
  const ID = uuidOf("c");
  /** worker (ippoan/alc-measurements-worker) に在る 8 口: [method, path]。 */
  const MEASUREMENT_ROUTES: ReadonlyArray<readonly [string, string]> = [
    ["POST", "/api/measurements"],
    ["GET", "/api/measurements"],
    ["POST", "/api/measurements/start"],
    ["GET", `/api/measurements/${ID}`],
    ["PUT", `/api/measurements/${ID}`],
    ["GET", `/api/measurements/${ID}/face-photo`],
    ["GET", `/api/measurements/${ID}/video`],
    ["POST", `/api/measurements/${ID}/tenko`],
  ];

  function setupMeasurements() {
    const measurements = makeBinding();
    return { measurements, ...setup({ ALC_MEASUREMENTS: measurements as unknown as Fetcher }) };
  }

  it("8 口は画面用と端末用が ALC_MEASUREMENTS へ。内部用・管理画面用は null", () => {
    const { measurements, env } = setupMeasurements();
    const target = { fetcher: measurements, host: "alc-measurements" };
    for (const [method, path] of MEASUREMENT_ROUTES) {
      expect(resolveAlcBinding(path, env, "browser"), `${method} ${path}`).toEqual(target);
      expect(resolveAlcBinding(path, env, "device"), `${method} ${path}`).toEqual(target);
      expect(resolveAlcBinding(path, env, "internal"), `${method} ${path}`).toBeNull();
      expect(resolveAlcBinding(path, env, "admin"), `${method} ${path}`).toBeNull();
    }
  });

  it("alert-test (受信者管理のテスト送信) は画面用と管理画面用が ALC_MEASUREMENTS へ。端末用・内部用は null", () => {
    const { measurements, env } = setupMeasurements();
    const target = { fetcher: measurements, host: "alc-measurements" };
    const path = "/api/measurements/alert-test";
    expect(resolveAlcBinding(path, env, "browser")).toEqual(target);
    expect(resolveAlcBinding(path, env, "admin")).toEqual(target);
    expect(resolveAlcBinding(path, env, "device")).toBeNull();
    expect(resolveAlcBinding(path, env, "internal")).toBeNull();
    for (const near of ["/api/measurements/alert-test/x", "/api/measurements/alert-testx"]) {
      expect(resolveAlcBinding(near, env, "browser"), near).toBeNull();
      expect(resolveAlcBinding(near, env, "admin"), near).toBeNull();
    }
  });

  it("bp-report-test (血圧の日報のテスト送信) は画面用と管理画面用が ALC_MEASUREMENTS へ。端末用・内部用は null", () => {
    const { measurements, env } = setupMeasurements();
    const target = { fetcher: measurements, host: "alc-measurements" };
    const path = "/api/measurements/bp-report-test";
    expect(resolveAlcBinding(path, env, "browser")).toEqual(target);
    expect(resolveAlcBinding(path, env, "admin")).toEqual(target);
    expect(resolveAlcBinding(path, env, "device")).toBeNull();
    expect(resolveAlcBinding(path, env, "internal")).toBeNull();
    for (const near of ["/api/measurements/bp-report-test/x", "/api/measurements/bp-report-testx"]) {
      expect(resolveAlcBinding(near, env, "browser"), near).toBeNull();
      expect(resolveAlcBinding(near, env, "admin"), near).toBeNull();
    }
  });

  it("血圧の通知の設定 (/api/bp-notify/) は画面用だけが ALC_MEASUREMENTS へ。端末用・内部用・管理画面用は null", () => {
    const { measurements, env } = setupMeasurements();
    const target = { fetcher: measurements, host: "alc-measurements" };
    for (const path of [
      "/api/bp-notify/settings",
      `/api/bp-notify/settings/${ID}`,
      "/api/bp-notify/lineworks-users",
      "/api/bp-notify/link-by-name",
    ]) {
      expect(resolveAlcBinding(path, env, "browser"), path).toEqual(target);
      expect(resolveAlcBinding(path, env, "device"), path).toBeNull();
      expect(resolveAlcBinding(path, env, "internal"), path).toBeNull();
      expect(resolveAlcBinding(path, env, "admin"), path).toBeNull();
    }
    expect(resolveAlcBinding("/api/bp-notifyx", env, "browser")).toBeNull();
  });

  it("大文字の UUID でも ALC_MEASUREMENTS へ行く", () => {
    const { measurements, env } = setupMeasurements();
    const target = { fetcher: measurements, host: "alc-measurements" };
    const upper = ID.toUpperCase();
    for (const path of [`/api/measurements/${upper}`, `/api/measurements/${upper}/face-photo`, `/api/measurements/${upper}/video`, `/api/measurements/${upper}/tenko`]) {
      expect(resolveAlcBinding(path, env, "browser"), path).toEqual(target);
      expect(resolveAlcBinding(path, env, "device"), path).toEqual(target);
    }
  });

  it("UUID でない path・下位の余り・近い名前は null (= Cloud Run)", () => {
    const { env } = setupMeasurements();
    for (const path of [
      "/api/measurements/m-1",
      `/api/measurements/${ID}/other`,
      `/api/measurements/${ID}/face-photo/x`,
      `/api/measurements/${ID}/video/x`,
      `/api/measurements/${ID}/tenko/x`,
      `/api/measurements/${ID}/tenkox`,
      "/api/measurements/m-1/tenko",
      `/api/measurements/${ID}/`,
      `/api/measurements/${ID}x`,
      "/api/measurements/start/x",
      "/api/measurements/",
      "/api/measurementsx",
      `/x/api/measurements/${ID}`,
    ]) {
      for (const proxy of ["browser", "device"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
  });

  describe("端末の POST /api/measurements/{uuid}/tenko (点呼の確定)", () => {
    async function deviceReq(path: string, method: string, role: string = DEVICE_ROLE_KIOSK, claims: Record<string, unknown> = {}) {
      const token = await signTestJwt({ sub: "device-1", tenant_id: TENANT, role, ...claims }, TEST_JWT_SECRET);
      return new Request(`https://auth.test.example/device-data-proxy${path}`, {
        method,
        headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
        ...(method === "GET" ? {} : { body: JSON.stringify({ tenko_method: "IT点呼" }) }),
      });
    }

    it("kiosk の要求は ALC_MEASUREMENTS の binding へ。tenant は JWT から、Cloud Run には行かない", async () => {
      const { measurements, cloudRun, env } = setupMeasurements();
      const res = await handleDeviceDataProxy(
        await deviceReq(`/api/measurements/${ID}/tenko`, "POST"),
        env,
      );
      expect(await res.text()).toBe("from-binding");
      const [url, init] = measurements.fetch.mock.calls[0]!;
      expect(url).toBe(`https://alc-measurements/api/measurements/${ID}/tenko`);
      expect(init!.method).toBe("POST");
      expect((init!.headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
      expect(cloudRun).not.toHaveBeenCalled();
    });

    it("dev の鍵なら PUT /api/measurements/{uuid} と同じ X-Device-Dev の印が付く", async () => {
      const { measurements, env } = setupMeasurements();
      for (const [method, path] of [["PUT", `/api/measurements/${ID}`], ["POST", `/api/measurements/${ID}/tenko`]] as const) {
        measurements.fetch.mockClear();
        const res = await handleDeviceDataProxy(await deviceReq(path, method, DEVICE_ROLE_KIOSK, { dev_device: true }), env);
        expect(res.status, path).toBe(200);
        const h = measurements.fetch.mock.calls[0]![1]!.headers as Record<string, string>;
        expect(h["X-Device-Dev"], path).toBe("1");
        expect(h["X-Device-Role"], path).toBe(DEVICE_ROLE_KIOSK);
      }
    });

    it("GET・別 method・別の下位 path・uuid でない path は 403 で、binding にも Cloud Run にも届かない", async () => {
      const { measurements, cloudRun, env } = setupMeasurements();
      for (const [method, path] of [
        ["GET", `/api/measurements/${ID}/tenko`],
        ["PUT", `/api/measurements/${ID}/tenko`],
        ["DELETE", `/api/measurements/${ID}/tenko`],
        ["POST", `/api/measurements/${ID}/tenko/x`],
        ["POST", `/api/measurements/${ID}/tenkox`],
        ["POST", `/api/measurements/${ID}/other`],
        ["POST", "/api/measurements/tenko"],
        ["POST", "/api/measurements//tenko"],
      ] as const) {
        const res = await handleDeviceDataProxy(await deviceReq(path, method), env);
        expect(res.status, `${method} ${path}`).toBe(403);
      }
      expect(measurements.fetch).not.toHaveBeenCalled();
      expect(cloudRun).not.toHaveBeenCalled();
    });

    it("uuid でない path (m-1・%2e%2e%2fadmin) は許可表は通る (既存の PUT と同じ) が binding へは行かず Cloud Run へ", async () => {
      for (const path of ["/api/measurements/m-1/tenko", "/api/measurements/%2e%2e%2fadmin/tenko"]) {
        const { measurements, cloudRun, env } = setupMeasurements();
        const res = await handleDeviceDataProxy(await deviceReq(path, "POST"), env);
        expect(await res.text(), path).toBe("from-cloud-run");
        expect(measurements.fetch, path).not.toHaveBeenCalled();
        expect(cloudRun, path).toHaveBeenCalledTimes(1);
      }
    });

    it("血圧測定台 (device-bp-station) の role でも通り、ALC_MEASUREMENTS へ回る (Cloud Run には行かない)", async () => {
      const { measurements, cloudRun, env } = setupMeasurements();
      const res = await handleDeviceDataProxy(
        await deviceReq(`/api/measurements/${ID}/tenko`, "POST", DEVICE_ROLE_BP_STATION),
        env,
      );
      expect(await res.text()).toBe("from-binding");
      const [url, init] = measurements.fetch.mock.calls[0]!;
      expect(url).toBe(`https://alc-measurements/api/measurements/${ID}/tenko`);
      expect((init!.headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
      expect(cloudRun).not.toHaveBeenCalled();
    });

    it("血圧測定台でも GET・PUT・下位 path の余りは 403", async () => {
      const { measurements, cloudRun, env } = setupMeasurements();
      for (const [method, path] of [
        ["GET", `/api/measurements/${ID}/tenko`],
        ["PUT", `/api/measurements/${ID}/tenko`],
        ["POST", `/api/measurements/${ID}/tenko/x`],
      ] as const) {
        const res = await handleDeviceDataProxy(await deviceReq(path, method, DEVICE_ROLE_BP_STATION), env);
        expect(res.status, `${method} ${path}`).toBe(403);
      }
      expect(measurements.fetch).not.toHaveBeenCalled();
      expect(cloudRun).not.toHaveBeenCalled();
    });
  });

  it("binding が未定義なら、どの口も null (= Cloud Run)", () => {
    const { env } = setup();
    for (const [, path] of MEASUREMENT_ROUTES) {
      expect(resolveAlcBinding(path, env, "browser"), path).toBeNull();
      expect(resolveAlcBinding(path, env, "device"), path).toBeNull();
    }
  });
});

describe("Bot 設定の口 → ALC_LINEWORKS binding (Refs ippoan/rust-alc-api#680)", () => {
  const BOT = "/api/admin/bot/configs";
  const ID = "0f0e0d0c-0b0a-4908-8706-050403020100";

  it("一覧・保存・削除の口 (exact) は画面用と管理画面用が ALC_LINEWORKS へ。内部用・端末用は null", () => {
    const { lineworks, env } = setup();
    expect(resolveAlcBinding(BOT, env, "browser")).toEqual({ fetcher: lineworks, host: "alc-lineworks" });
    expect(resolveAlcBinding(BOT, env, "admin")).toEqual({ fetcher: lineworks, host: "alc-lineworks" });
    expect(resolveAlcBinding(BOT, env, "internal")).toBeNull();
    expect(resolveAlcBinding(BOT, env, "device")).toBeNull();
  });

  it("id 付きの削除 (UUID) は画面用だけ。export・UUID でない・余りは拾わない (export は Cloud Run)", () => {
    const { lineworks, env } = setup();
    expect(resolveAlcBinding(`${BOT}/${ID}`, env, "browser")).toEqual({ fetcher: lineworks, host: "alc-lineworks" });
    expect(resolveAlcBinding(`${BOT}/${ID.toUpperCase()}`, env, "browser")).not.toBeNull();
    expect(resolveAlcBinding(`${BOT}/${ID}`, env, "admin")).toBeNull();
    for (const path of [
      `${BOT}/export`,
      `${BOT}/x`,
      `${BOT}/${ID}/secrets`,
      `${BOT}/${ID}x`,
      `${BOT}/`,
      `${BOT}x`,
      `/x${BOT}`,
    ]) {
      for (const proxy of ["browser", "internal", "device", "admin"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
  });

  it("binding が未定義なら null (= Cloud Run)", () => {
    const { env } = setup({ ALC_LINEWORKS: undefined });
    expect(resolveAlcBinding(BOT, env, "browser")).toBeNull();
    expect(resolveAlcBinding(BOT, env, "admin")).toBeNull();
  });

  it("alc-proxy の DELETE /api/admin/bot/configs/{id} は binding に届く (Cloud Run は呼ばれない)", async () => {
    const { lineworks, cloudRun, env } = setup();
    const res = await handleAlcProxy(alcReq(`/alc-proxy${BOT}/${ID}`, { method: "DELETE" }), env);
    expect(await res.text()).toBe("from-binding");
    const [url, init] = lineworks.fetch.mock.calls[0]!;
    expect(url).toBe(`https://alc-lineworks${BOT}/${ID}`);
    expect(init!.method).toBe("DELETE");
    expect((init!.headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("車検証・車両整備の口 → ALC_CARINS binding (Refs ippoan/rust-alc-api#680)", () => {
  const uuidOf = (c: string) => [8, 4, 4, 4, 12].map((n) => c.repeat(n)).join("-");
  const ID = uuidOf("c");
  /** worker (ippoan/alc-carins-worker の crates/carins) の router に在る口のうち、画面用だけが使うもの */
  const BROWSER_ONLY = [
    "/api/files/recent",
    "/api/files/verify",
    `/api/files/${ID}/download`,
    `/api/files/${ID.toUpperCase()}/download`,
    "/api/nfc-tags",
    "/api/nfc-tags/search",
    "/api/nfc-tags/04a1b2",
    "/api/maintenance/vehicles",
    `/api/maintenance/vehicles/${ID}/carins`,
    "/api/maintenance/vehicles/carins-import",
    "/api/maintenance/categories",
    `/api/maintenance/records/${ID}/files`,
    `/api/maintenance/files/${ID}/download`,
  ];
  /** 画面用と端末用 (端末で通せる口は device-data-proxy の role の表で絞る) */
  const BROWSER_AND_DEVICE = [
    "/api/car-inspections/current",
    "/api/car-inspections/expired",
    "/api/car-inspections/vehicle-categories",
    "/api/car-inspections/by-car/CARID000000001/history",
    "/api/car-inspections/lookup",
  ];
  /** worker に無い (rust にだけ在る) 下位の口と、近い名前は Cloud Run に残る */
  const STAYS_ON_CLOUD_RUN = [
    "/api/files/not-attached",
    `/api/files/${ID}`,
    `/api/files/${ID}/delete`,
    `/api/files/${ID}/restore`,
    "/api/files/x/download",
    `/api/files/${ID}/download/x`,
    "/api/car-inspection-files/current",
    "/api/filesx",
    "/api/maintenancex",
  ];

  function setupCarins() {
    const carins = makeBinding();
    return { carins, ...setup({ ALC_CARINS: carins as unknown as Fetcher }) };
  }

  it("表の行と proxy の組み合わせ (/api/files は画面用・端末用・RPC、照合などは画面用・端末用、ほかは画面用だけ)", () => {
    const { carins, env } = setupCarins();
    const target = { fetcher: carins, host: "alc-carins" };
    expect(resolveAlcBinding("/api/files", env, "browser")).toEqual(target);
    expect(resolveAlcBinding("/api/files", env, "device")).toEqual(target);
    expect(resolveAlcBinding("/api/files", env, "rpc")).toEqual(target);
    expect(resolveAlcBinding("/api/files", env, "internal")).toBeNull();
    expect(resolveAlcBinding("/api/files", env, "admin")).toBeNull();
    for (const path of BROWSER_AND_DEVICE) {
      expect(resolveAlcBinding(path, env, "browser"), path).toEqual(target);
      expect(resolveAlcBinding(path, env, "device"), path).toEqual(target);
      for (const proxy of ["internal", "admin", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
    for (const path of BROWSER_ONLY) {
      expect(resolveAlcBinding(path, env, "browser"), path).toEqual(target);
      for (const proxy of ["internal", "device", "admin", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
    for (const path of STAYS_ON_CLOUD_RUN) {
      for (const proxy of ["browser", "internal", "device", "admin", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
  });

  it("binding が未定義なら null (= Cloud Run)", () => {
    const { env } = setup();
    expect(resolveAlcBinding("/api/files", env, "rpc")).toBeNull();
    expect(resolveAlcBinding("/api/maintenance/vehicles", env, "browser")).toBeNull();
  });

  it("alc-proxy の整備の口は binding に届く (付け直したヘッダだけ。Authorization は渡さない)", async () => {
    const { carins, cloudRun, env } = setupCarins();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/maintenance/records?page=2", { method: "GET" }), env);
    expect(await res.text()).toBe("from-binding");
    const [url, init] = carins.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-carins/api/maintenance/records?page=2");
    const h = init!.headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBeTruthy();
    expect(Object.keys(h).map((k) => k.toLowerCase())).not.toContain("authorization");
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("device-data-proxy のキオスクの車検期限の照合は binding に届く", async () => {
    const { carins, cloudRun, env } = setupCarins();
    const res = await handleDeviceDataProxy(await kioskReq("/device-data-proxy/api/car-inspections/lookup", "POST"), env);
    expect(await res.text()).toBe("from-binding");
    const [url, init] = carins.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-carins/api/car-inspections/lookup");
    expect((init!.headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("upload の 3 口 → ALC_MEASUREMENTS binding (Refs ippoan/rust-alc-api#680)", () => {
  const UPLOADS = ["/api/upload/face-photo", "/api/upload/blow-video", "/api/upload/report-audio"];

  function setupMeasurements() {
    const measurements = makeBinding();
    return { measurements, ...setup({ ALC_MEASUREMENTS: measurements as unknown as Fetcher }) };
  }

  it("3 口は画面用と端末用だけ ALC_MEASUREMENTS へ。/api/upload (dtako の取り込み) と近い名前は回らない", () => {
    const { measurements, dtako, env } = setupMeasurements();
    const target = { fetcher: measurements, host: "alc-measurements" };
    for (const path of UPLOADS) {
      expect(resolveAlcBinding(path, env, "browser"), path).toEqual(target);
      expect(resolveAlcBinding(path, env, "device"), path).toEqual(target);
      for (const proxy of ["internal", "admin", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
    expect(resolveAlcBinding("/api/upload", env, "browser")).toEqual({ fetcher: dtako, host: "alc-dtako" });
    for (const path of ["/api/upload/face-photo/x", "/api/upload/other", "/api/upload/"]) {
      expect(resolveAlcBinding(path, env, "browser"), path).toBeNull();
    }
  });

  it("device-data-proxy のキオスクの吹きかけ動画の upload は binding に届く (Cloud Run を呼ばない)", async () => {
    const { measurements, cloudRun, env } = setupMeasurements();
    const res = await handleDeviceDataProxy(await kioskReq("/device-data-proxy/api/upload/blow-video", "POST"), env);
    expect(await res.text()).toBe("from-binding");
    const [url, init] = measurements.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-measurements/api/upload/blow-video");
    expect((init!.headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("alc-proxy の顔写真の upload は binding に届く", async () => {
    const { measurements, cloudRun, env } = setupMeasurements();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/upload/face-photo"), env);
    expect(await res.text()).toBe("from-binding");
    expect(measurements.fetch.mock.calls[0]![0]).toBe("https://alc-measurements/api/upload/face-photo");
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("物品・携行品・伝達事項・指導記録の口 → ALC_RECORDS binding (Refs ippoan/rust-alc-api#680)", () => {
  const uuidOf = (c: string) => [8, 4, 4, 4, 12].map((n) => c.repeat(n)).join("-");
  const ID = uuidOf("d");
  /** worker (ippoan/alc-records-worker の crates/records) の router に在る口 (rust の口と同じ集合) */
  const BROWSER_ONLY = [
    "/api/items",
    "/api/items/search",
    `/api/items/${ID}`,
    `/api/items/${ID}/move`,
    `/api/items/${ID}/ownership`,
    `/api/items/${ID}/convert`,
    "/api/item-files",
    `/api/item-files/${ID}`,
    "/api/communication-items",
    "/api/communication-items/active",
    `/api/communication-items/${ID}`,
    "/api/guidance-records",
    `/api/guidance-records/${ID}`,
    `/api/guidance-records/${ID}/attachments`,
    `/api/guidance-records/${ID}/attachments/${ID}`,
  ];
  const BROWSER_AND_DEVICE = ["/api/carrying-items", `/api/carrying-items/${ID}`];

  function setupRecords() {
    const records = makeBinding();
    return { records, ...setup({ ALC_RECORDS: records as unknown as Fetcher }) };
  }

  it("表の行と proxy の組み合わせ (携行品だけ端末用も)。近い名前は回らない", () => {
    const { records, env } = setupRecords();
    const target = { fetcher: records, host: "alc-records" };
    for (const path of BROWSER_ONLY) {
      expect(resolveAlcBinding(path, env, "browser"), path).toEqual(target);
      for (const proxy of ["internal", "device", "admin", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
    for (const path of BROWSER_AND_DEVICE) {
      expect(resolveAlcBinding(path, env, "browser"), path).toEqual(target);
      expect(resolveAlcBinding(path, env, "device"), path).toEqual(target);
      for (const proxy of ["internal", "admin", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
    for (const path of ["/api/itemsx", "/api/item-filesx", "/api/carrying-itemsx", "/api/guidance-recordsx"]) {
      expect(resolveAlcBinding(path, env, "browser"), path).toBeNull();
    }
  });

  it("binding が未定義なら null (= Cloud Run)", () => {
    const { env } = setup();
    expect(resolveAlcBinding("/api/items", env, "browser")).toBeNull();
    expect(resolveAlcBinding("/api/carrying-items", env, "device")).toBeNull();
  });

  it("device-data-proxy のキオスクの携行品の一覧は binding に届く", async () => {
    const { records, cloudRun, env } = setupRecords();
    const res = await handleDeviceDataProxy(await kioskReq("/device-data-proxy/api/carrying-items", "GET"), env);
    expect(await res.text()).toBe("from-binding");
    const [url, init] = records.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-records/api/carrying-items");
    expect((init!.headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("alc-proxy の物品の一覧は binding に届く", async () => {
    const { records, cloudRun, env } = setupRecords();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/items?owner_type=org", { method: "GET" }), env);
    expect(await res.text()).toBe("from-binding");
    expect(records.fetch.mock.calls[0]![0]).toBe("https://alc-records/api/items?owner_type=org");
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("タイムカードの口 → ALC_PEOPLE binding (W4d-a、Refs ippoan/rust-alc-api#680)", () => {
  const ID = [8, 4, 4, 4, 12].map((n) => "e".repeat(n)).join("-");
  /** worker (ippoan/alc-people-worker の crates/people) の router に在る口 (rust の口と同じ集合) */
  const PATHS = [
    "/api/timecard/cards",
    `/api/timecard/cards/${ID}`,
    "/api/timecard/cards/bulk-by-code",
    "/api/timecard/cards/delete-by-card",
    "/api/timecard/cards/lookup",
    "/api/timecard/punches",
    "/api/timecard/punches/csv",
  ];

  function setupPeople() {
    const people = makeBinding();
    return { people, ...setup({ ALC_PEOPLE: people as unknown as Fetcher }) };
  }

  it("画面用・端末用・RPC は回り、内部用・管理画面用は回らない。近い名前は回らない", () => {
    const { people, env } = setupPeople();
    const target = { fetcher: people, host: "alc-people" };
    for (const path of PATHS) {
      for (const proxy of ["browser", "device", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toEqual(target);
      }
      for (const proxy of ["internal", "admin"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
    for (const path of ["/api/timecardx"]) {
      for (const proxy of ["browser", "device", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
  });

  it("binding が未定義なら null (= Cloud Run)", () => {
    const { env } = setup();
    expect(resolveAlcBinding("/api/timecard/cards", env, "browser")).toBeNull();
    expect(resolveAlcBinding("/api/timecard/cards/bulk-by-code", env, "rpc")).toBeNull();
  });

  it("device-data-proxy のキオスクのカード一覧は binding に届く", async () => {
    const { people, cloudRun, env } = setupPeople();
    const res = await handleDeviceDataProxy(await kioskReq("/device-data-proxy/api/timecard/cards", "GET"), env);
    expect(await res.text()).toBe("from-binding");
    const [url, init] = people.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-people/api/timecard/cards");
    expect((init!.headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("alc-proxy の打刻の一覧は binding に届く", async () => {
    const { people, cloudRun, env } = setupPeople();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/timecard/punches?page=2", { method: "GET" }), env);
    expect(await res.text()).toBe("from-binding");
    expect(people.fetch.mock.calls[0]![0]).toBe("https://alc-people/api/timecard/punches?page=2");
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("社員の口 → ALC_PEOPLE binding (W4d-b、Refs ippoan/rust-alc-api#680)", () => {
  const ID = [8, 4, 4, 4, 12].map((n) => "e".repeat(n)).join("-");
  /** worker (ippoan/alc-people-worker の crates/people/src/employees.rs) の router に在る口 (rust の口と同じ集合) */
  const PATHS = [
    "/api/employees",
    `/api/employees/${ID}`,
    `/api/employees/${ID}/face`,
    `/api/employees/${ID}/nfc`,
    `/api/employees/${ID}/license`,
    `/api/employees/${ID}/face/approve`,
    `/api/employees/${ID}/face/reject`,
    "/api/employees/face-data",
    "/api/employees/lookup",
    "/api/employees/by-code/E001",
    "/api/employees/bulk-by-code",
  ];

  function setupPeople() {
    const people = makeBinding();
    return { people, ...setup({ ALC_PEOPLE: people as unknown as Fetcher }) };
  }

  it("画面用・端末用・RPC は回り、内部用・管理画面用は回らない。近い名前と通知の社員の選択肢は回らない", () => {
    const { people, env } = setupPeople();
    const target = { fetcher: people, host: "alc-people" };
    for (const path of PATHS) {
      for (const proxy of ["browser", "device", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toEqual(target);
      }
      for (const proxy of ["internal", "admin"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
    for (const path of ["/api/employeesx", "/api/notify/employees"]) {
      for (const proxy of ["browser", "device", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy)?.host, `${proxy} ${path}`).not.toBe("alc-people");
      }
    }
  });

  it("binding が未定義なら null (= Cloud Run)", () => {
    const { env } = setup();
    expect(resolveAlcBinding("/api/employees", env, "browser")).toBeNull();
    expect(resolveAlcBinding("/api/employees/bulk-by-code", env, "rpc")).toBeNull();
  });

  it("device-data-proxy のキオスクの NFC 照会は binding に届く", async () => {
    const { people, cloudRun, env } = setupPeople();
    const res = await handleDeviceDataProxy(await kioskReq("/device-data-proxy/api/employees/lookup", "POST"), env);
    expect(await res.text()).toBe("from-binding");
    const [url, init] = people.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-people/api/employees/lookup");
    expect((init!.headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("alc-proxy の社員の一覧は binding に届く", async () => {
    const { people, cloudRun, env } = setupPeople();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/employees", { method: "GET" }), env);
    expect(await res.text()).toBe("from-binding");
    expect(people.fetch.mock.calls[0]![0]).toBe("https://alc-people/api/employees");
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("端末の測定・打刻 → ALC_PEOPLE binding (W6a、Refs ippoan/rust-alc-api#680)", () => {
  const PATH = "/api/hub/measurements";

  function setupPeople() {
    const people = makeBinding();
    return { people, ...setup({ ALC_PEOPLE: people as unknown as Fetcher }) };
  }

  it("取り込みは内部用の POST、一覧は画面用・RPC の GET だけ", () => {
    const { people, env } = setupPeople();
    const target = { fetcher: people, host: "alc-people" };
    expect(resolveAlcBinding(PATH, env, "internal", "POST")).toEqual(target);
    expect(resolveAlcBinding(PATH, env, "browser", "GET")).toEqual(target);
    expect(resolveAlcBinding(PATH, env, "rpc", "GET")).toEqual(target);
    expect(resolveAlcBinding(PATH, env, "internal", "GET")).toBeNull();
    for (const proxy of ["browser", "rpc"] as const) {
      expect(resolveAlcBinding(PATH, env, proxy, "POST"), proxy).toBeNull();
    }
    for (const proxy of ["device", "admin"] as const) {
      expect(resolveAlcBinding(PATH, env, proxy, "GET"), proxy).toBeNull();
    }
    for (const path of ["/api/hub/measurementsx", "/api/hub/measurements/x", "/api/hub/"]) {
      expect(resolveAlcBinding(path, env, "internal", "POST"), path).toBeNull();
    }
  });

  it("binding が未定義なら null (= Cloud Run)", () => {
    const { env } = setup();
    expect(resolveAlcBinding(PATH, env, "internal", "POST")).toBeNull();
  });

  it("alc-internal-proxy の取り込みは binding に届き、dev端末の印も渡す", async () => {
    vi.mocked(mintGoogleIdToken).mockReset();
    const { people, cloudRun, env } = setupPeople();
    const res = await handleAlcInternalProxy(
      internalReq(`/alc-internal-proxy${PATH}`, { "content-type": "application/json", "X-Device-Dev": "1" }, "[]"),
      env,
    );
    expect(await res.text()).toBe("from-binding");
    const [url, init] = people.fetch.mock.calls[0]!;
    expect(url).toBe(`https://alc-people${PATH}`);
    expect(init!.method).toBe("POST");
    expect(init!.headers).toEqual({ "X-Tenant-ID": TENANT, "Content-Type": "application/json", "X-Device-Dev": "1" });
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("alc-proxy の一覧は binding に届き、取り込みの POST は届かない", async () => {
    vi.mocked(mintGoogleIdToken).mockReset();
    vi.mocked(mintGoogleIdToken).mockResolvedValue("fake-oidc-token");
    const { people, cloudRun, env } = setupPeople();
    const res = await handleAlcProxy(alcReq(`/alc-proxy${PATH}?kind=alcohol`, { method: "GET" }), env);
    expect(await res.text()).toBe("from-binding");
    expect(people.fetch.mock.calls[0]![0]).toBe(`https://alc-people${PATH}?kind=alcohol`);
    const post = await handleAlcProxy(alcReq(`/alc-proxy${PATH}`, { method: "POST", body: "[]" }), env);
    expect(await post.text()).toBe("from-cloud-run");
    expect(people.fetch).toHaveBeenCalledTimes(1);
    expect(cloudRun).toHaveBeenCalledTimes(1);
  });
});

describe("機械の取り込み → ALC_DTAKO binding (W5a、Refs ippoan/rust-alc-api#680)", () => {
  const ID = "0f0e0d0c-0b0a-4908-8706-050403020100";
  beforeEach(() => {
    vi.mocked(mintGoogleIdToken).mockReset();
    vi.mocked(mintGoogleIdToken).mockResolvedValue("fake-oidc-token");
  });

  it("dtako-logs/bulk は端末用・RPC だけ、dvr の 2 口は内部用だけ。近い名前と同じ prefix の読み取りは回らない", () => {
    const { dtako, env } = setup();
    const target = { fetcher: dtako, host: "alc-dtako" };
    const rows: Array<[string, ReadonlyArray<"browser" | "internal" | "device" | "admin" | "rpc">]> = [
      ["/api/dtako-logs/bulk", ["device", "rpc"]],
      ["/api/dvr/notifications", ["internal"]],
      [`/api/dvr/files/${ID}`, ["internal"]],
    ];
    for (const [path, allowed] of rows) {
      for (const proxy of ["browser", "internal", "device", "admin", "rpc"] as const) {
        const want = allowed.includes(proxy) ? target : null;
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toEqual(want);
      }
    }
    for (const path of [
      "/api/dtako-logs/bulk/x",
      "/api/dvr/files/not-a-uuid",
      `/api/dvr/files/${ID}/x`,
      "/api/dvr/notificationsx",
    ]) {
      for (const proxy of ["browser", "internal", "device", "admin", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
  });

  it("binding が未定義なら null (= Cloud Run)", () => {
    const { env } = setup({ ALC_DTAKO: undefined });
    expect(resolveAlcBinding("/api/dtako-logs/bulk", env, "rpc")).toBeNull();
    expect(resolveAlcBinding("/api/dvr/notifications", env, "internal")).toBeNull();
  });

  it("alc-internal-proxy の dvr の 2 口は binding に届き、token は作らない", async () => {
    const { dtako, cloudRun, env } = setup();
    vi.mocked(mintGoogleIdToken).mockRejectedValue(new Error("boom"));
    for (const path of ["/api/dvr/notifications", `/api/dvr/files/${ID}`]) {
      const res = await handleAlcInternalProxy(
        internalReq(`/alc-internal-proxy${path}`, { "content-type": "application/octet-stream" }, "vdf-bytes"),
        env,
      );
      expect(await res.text(), path).toBe("from-binding");
    }
    expect(dtako.fetch.mock.calls.map((c) => c[0])).toEqual([
      "https://alc-dtako/api/dvr/notifications",
      `https://alc-dtako/api/dvr/files/${ID}`,
    ]);
    const init = dtako.fetch.mock.calls[1]![1]!;
    expect(new TextDecoder().decode(init.body as ArrayBuffer)).toBe("vdf-bytes");
    expect((init.headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("端末用 (dtako 取り込みの端末 role) の dtako-logs/bulk は binding に届く", async () => {
    const { dtako, cloudRun, env } = setup();
    const token = await signTestJwt(
      { sub: "device-ingest-1", tenant_id: TENANT, role: DEVICE_ROLE_DTAKO_INGEST },
      TEST_JWT_SECRET,
    );
    const res = await handleDeviceDataProxy(
      new Request("https://auth.test.example/device-data-proxy/api/dtako-logs/bulk", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: "[]",
      }),
      env,
    );
    expect(await res.text()).toBe("from-binding");
    const [url, init] = dtako.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-dtako/api/dtako-logs/bulk");
    expect((init!.headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("勤怠向けの読み取り → ALC_DTAKO binding (W5b、Refs ippoan/rust-alc-api#680)", () => {
  it("dtako/events は RPC だけ、dtako/events/etags は RPC・画面用・端末用。近い名前と dtako の他の口は回らない", () => {
    const { dtako, env } = setup();
    const target = { fetcher: dtako, host: "alc-dtako" };
    const rows: Array<[string, ReadonlyArray<"browser" | "internal" | "device" | "admin" | "rpc">]> = [
      ["/api/dtako/events", ["rpc"]],
      ["/api/dtako/events/etags", ["rpc", "browser", "device"]],
    ];
    for (const [path, allowed] of rows) {
      for (const proxy of ["browser", "internal", "device", "admin", "rpc"] as const) {
        const want = allowed.includes(proxy) ? target : null;
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toEqual(want);
      }
    }
    for (const path of ["/api/dtako/events/", "/api/dtako/events/etags/x", "/api/dtako/eventsx", "/api/dtako/ticketsx"]) {
      for (const proxy of ["browser", "internal", "device", "admin", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
  });

  it("binding が未定義なら null (= Cloud Run)", () => {
    const { env } = setup({ ALC_DTAKO: undefined });
    expect(resolveAlcBinding("/api/dtako/events", env, "rpc")).toBeNull();
    expect(resolveAlcBinding("/api/dtako/events/etags", env, "browser")).toBeNull();
  });

  it("alc-proxy の etags は binding に届く (query もそのまま)", async () => {
    const { dtako, cloudRun, env } = setup();
    const res = await handleAlcProxy(
      alcReq("/alc-proxy/api/dtako/events/etags?date_from=2026-10-01&date_to=2026-10-31", { method: "GET" }),
      env,
    );
    expect(await res.text()).toBe("from-binding");
    expect(dtako.fetch.mock.calls[0]![0]).toBe(
      "https://alc-dtako/api/dtako/events/etags?date_from=2026-10-01&date_to=2026-10-31",
    );
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("端末用 (dtako relay の端末 role) の etags は binding に届く", async () => {
    const { dtako, cloudRun, env } = setup();
    const token = await signTestJwt(
      { sub: "device-relay-1", tenant_id: TENANT, role: DEVICE_ROLE_DTAKO_RELAY },
      TEST_JWT_SECRET,
    );
    const res = await handleDeviceDataProxy(
      new Request("https://auth.test.example/device-data-proxy/api/dtako/events/etags?date_from=2026-10-01&date_to=2026-10-31", {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
      }),
      env,
    );
    expect(await res.text()).toBe("from-binding");
    const [url, init] = dtako.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-dtako/api/dtako/events/etags?date_from=2026-10-01&date_to=2026-10-31");
    expect((init!.headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("画面向けの読み取りと分類の更新 → ALC_DTAKO binding (W5c-1、Refs ippoan/rust-alc-api#680)", () => {
  const ID = "0b9f5a52-6a1e-4c1b-9d2a-3f4e5d6c7b8a";
  const SCREEN_PATHS = [
    "/api/drivers",
    "/api/vehicles",
    "/api/work-times",
    "/api/daily-hours",
    `/api/daily-hours/${ID}/2026-10-01/segments`,
    "/api/operations",
    "/api/operations/calendar",
    "/api/operations/2610010800000000001",
    "/api/operations/2610010800000000001/csv/kudgivt",
    "/api/dtako/operation-changes",
    "/api/event-classifications",
    `/api/event-classifications/${ID}`,
    "/api/dtako-logs/current",
    "/api/dtako-logs/current/select",
    "/api/dtako-logs/by-date",
    "/api/dtako-logs/by-date-range",
  ];

  it("画面の口は画面用だけ、internal/operations は内部用だけ、scraper/history は画面用・RPC・端末用", () => {
    const { dtako, env } = setup();
    const target = { fetcher: dtako, host: "alc-dtako" };
    const rows: Array<[string, ReadonlyArray<"browser" | "internal" | "device" | "admin" | "rpc">]> = [
      ...SCREEN_PATHS.map((p): [string, ReadonlyArray<"browser">] => [p, ["browser"]]),
      ["/api/internal/operations", ["internal"]],
      ["/api/scraper/history", ["browser", "rpc", "device"]],
    ];
    for (const [path, allowed] of rows) {
      for (const proxy of ["browser", "internal", "device", "admin", "rpc"] as const) {
        const want = allowed.includes(proxy) ? target : null;
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toEqual(want);
      }
    }
  });

  it("近い名前と完全一致の口の下位は回らない", () => {
    const { env } = setup();
    for (const path of [
      "/api/driversx",
      "/api/drivers/x",
      "/api/vehicles/x",
      "/api/vehicle-settings",
      "/api/work-times/x",
      "/api/daily-hoursx",
      "/api/operationsx",
      "/api/dtako/operation-changes/x",
      "/api/event-classificationsx",
      "/api/dtako-logs/current/x",
      "/api/dtako-logs/by-date/x",
      "/api/dtako-logs/latest",
      "/api/internal/operations/x",
      "/api/scraper/history/x",
      "/api/scraper",
    ]) {
      for (const proxy of ["browser", "internal", "device", "admin", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
  });

  it("binding が未定義なら null (= Cloud Run)", () => {
    const { env } = setup({ ALC_DTAKO: undefined });
    expect(resolveAlcBinding("/api/operations", env, "browser")).toBeNull();
    expect(resolveAlcBinding("/api/internal/operations", env, "internal")).toBeNull();
    expect(resolveAlcBinding("/api/scraper/history", env, "rpc")).toBeNull();
  });

  it("alc-proxy の画面の口は binding に届く (method・query もそのまま)", async () => {
    const { dtako, cloudRun, env } = setup();
    for (const [path, method] of [
      ["/api/operations?date_from=2026-10-01&page=2", "GET"],
      ["/api/operations/2610010800000000001", "DELETE"],
      ["/api/dtako-logs/by-date-range?start_date_time=2026-10-01&end_date_time=2026-10-02", "GET"],
    ] as const) {
      const res = await handleAlcProxy(alcReq(`/alc-proxy${path}`, { method }), env);
      expect(await res.text(), path).toBe("from-binding");
    }
    expect(dtako.fetch.mock.calls.map((c) => [c[0], c[1]!.method])).toEqual([
      ["https://alc-dtako/api/operations?date_from=2026-10-01&page=2", "GET"],
      ["https://alc-dtako/api/operations/2610010800000000001", "DELETE"],
      ["https://alc-dtako/api/dtako-logs/by-date-range?start_date_time=2026-10-01&end_date_time=2026-10-02", "GET"],
    ]);
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("alc-internal-proxy の internal/operations は binding に届き、token は作らない", async () => {
    const { dtako, cloudRun, env } = setup();
    vi.mocked(mintGoogleIdToken).mockReset();
    vi.mocked(mintGoogleIdToken).mockRejectedValue(new Error("boom"));
    const req = new Request("https://auth.test.example/alc-internal-proxy/api/internal/operations?date_from=2026-10-01", {
      method: "GET",
      headers: { "X-Alc-Proxy-Secret": PROXY_SECRET, "X-Tenant-ID": TENANT },
    });
    const res = await handleAlcInternalProxy(req, env);
    expect(await res.text()).toBe("from-binding");
    const [url, init] = dtako.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-dtako/api/internal/operations?date_from=2026-10-01");
    expect((init!.headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("端末用 (dtako relay の端末 role) の scraper/history は binding に届く", async () => {
    const { dtako, cloudRun, env } = setup();
    const token = await signTestJwt(
      { sub: "device-relay-1", tenant_id: TENANT, role: DEVICE_ROLE_DTAKO_RELAY },
      TEST_JWT_SECRET,
    );
    const res = await handleDeviceDataProxy(
      new Request("https://auth.test.example/device-data-proxy/api/scraper/history?limit=5", {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
      }),
      env,
    );
    expect(await res.text()).toBe("from-binding");
    const [url, init] = dtako.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-dtako/api/scraper/history?limit=5");
    expect((init!.headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("Y時間 export → ALC_DTAKO binding (W5c-2、Refs ippoan/rust-alc-api#680)", () => {
  const PATHS = ["/api/dtako/y-time-export", "/api/dtako/y-time-rows"];

  it("2 口は画面用だけ", () => {
    const { dtako, env } = setup();
    const target = { fetcher: dtako, host: "alc-dtako" };
    for (const path of PATHS) {
      for (const proxy of ["browser", "internal", "device", "admin", "rpc"] as const) {
        const want = proxy === "browser" ? target : null;
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toEqual(want);
      }
    }
  });

  it("近い名前と完全一致の口の下位は回らない", () => {
    const { env } = setup();
    for (const path of [
      "/api/dtako/y-time-exportx",
      "/api/dtako/y-time-export/x",
      "/api/dtako/y-time-rowsx",
      "/api/dtako/y-time-rows/x",
      "/api/dtako/y-time",
      "/api/dtako/ticketsx",
    ]) {
      for (const proxy of ["browser", "internal", "device", "admin", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
  });

  it("binding が未定義なら null (= Cloud Run)", () => {
    const { env } = setup({ ALC_DTAKO: undefined });
    for (const path of PATHS) {
      expect(resolveAlcBinding(path, env, "browser"), path).toBeNull();
    }
  });

  it("alc-proxy の 2 口は binding に届く (method・query もそのまま)", async () => {
    const { dtako, cloudRun, env } = setup();
    for (const [path, method] of [
      ["/api/dtako/y-time-export?driver_cd=1001&from=2026-09-01&to=2026-09-30", "GET"],
      ["/api/dtako/y-time-rows", "POST"],
    ] as const) {
      const res = await handleAlcProxy(alcReq(`/alc-proxy${path}`, { method }), env);
      expect(await res.text(), path).toBe("from-binding");
    }
    expect(dtako.fetch.mock.calls.map((c) => [c[0], c[1]!.method])).toEqual([
      ["https://alc-dtako/api/dtako/y-time-export?driver_cd=1001&from=2026-09-01&to=2026-09-30", "GET"],
      ["https://alc-dtako/api/dtako/y-time-rows", "POST"],
    ]);
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("拘束時間の帳票と PDF → ALC_DTAKO binding (W5c-3・W5c-4、Refs ippoan/rust-alc-api#680)", () => {
  const PATHS = [
    "/api/restraint-report",
    "/api/restraint-report/compare-csv",
    "/api/restraint-report/pdf",
    "/api/restraint-report/pdf-stream",
  ];

  it("4 口は画面用だけ", () => {
    const { dtako, env } = setup();
    const target = { fetcher: dtako, host: "alc-dtako" };
    for (const path of PATHS) {
      for (const proxy of ["browser", "internal", "device", "admin", "rpc"] as const) {
        const want = proxy === "browser" ? target : null;
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toEqual(want);
      }
    }
  });

  it("近い名前・完全一致の口の下位は回らない", () => {
    const { env } = setup();
    for (const path of [
      "/api/restraint-report/pdfx",
      "/api/restraint-report/pdf/x",
      "/api/restraint-report/pdf-streamx",
      "/api/restraint-reportx",
      "/api/restraint-report/compare-csvx",
      "/api/restraint-report/compare-csv/x",
    ]) {
      for (const proxy of ["browser", "internal", "device", "admin", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
  });

  it("binding が未定義なら null (= Cloud Run)", () => {
    const { env } = setup({ ALC_DTAKO: undefined });
    for (const path of PATHS) {
      expect(resolveAlcBinding(path, env, "browser"), path).toBeNull();
    }
  });

  it("alc-proxy の 4 口は binding に届く (method・query もそのまま)", async () => {
    const { dtako, cloudRun, env } = setup();
    for (const [path, method] of [
      ["/api/restraint-report?driver_id=0b9f5a52-6a1e-4c1b-9d2a-3f4e5d6c7b8a&year=2026&month=2", "GET"],
      ["/api/restraint-report/compare-csv?driver_cd=1001", "POST"],
      ["/api/restraint-report/pdf?year=2026&month=2&driver_id=0b9f5a52-6a1e-4c1b-9d2a-3f4e5d6c7b8a", "GET"],
      ["/api/restraint-report/pdf-stream?year=2026&month=2", "GET"],
    ] as const) {
      const res = await handleAlcProxy(alcReq(`/alc-proxy${path}`, { method }), env);
      expect(await res.text(), path).toBe("from-binding");
    }
    expect(dtako.fetch.mock.calls.map((c) => [c[0], c[1]!.method])).toEqual([
      ["https://alc-dtako/api/restraint-report?driver_id=0b9f5a52-6a1e-4c1b-9d2a-3f4e5d6c7b8a&year=2026&month=2", "GET"],
      ["https://alc-dtako/api/restraint-report/compare-csv?driver_cd=1001", "POST"],
      ["https://alc-dtako/api/restraint-report/pdf?year=2026&month=2&driver_id=0b9f5a52-6a1e-4c1b-9d2a-3f4e5d6c7b8a", "GET"],
      ["https://alc-dtako/api/restraint-report/pdf-stream?year=2026&month=2", "GET"],
    ]);
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("車両のエラーの起票 → ALC_DTAKO binding (W5c-5、Refs ippoan/rust-alc-api#680)", () => {
  const ID = "0b9f5a52-6a1e-4c1b-9d2a-3f4e5d6c7b8a";

  it("一覧は画面用の GET、起票は内部用の POST だけ。ほかの method は Cloud Run", () => {
    const { dtako, env } = setup();
    const target = { fetcher: dtako, host: "alc-dtako" };
    const path = "/api/dtako/tickets";
    expect(resolveAlcBinding(path, env, "browser", "GET")).toEqual(target);
    expect(resolveAlcBinding(path, env, "browser", "get")).toEqual(target);
    expect(resolveAlcBinding(path, env, "internal", "POST")).toEqual(target);
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      expect(resolveAlcBinding(path, env, "browser", method), `browser ${method}`).toBeNull();
    }
    for (const method of ["GET", "PUT", "PATCH", "DELETE"]) {
      expect(resolveAlcBinding(path, env, "internal", method), `internal ${method}`).toBeNull();
    }
    // method を渡さない呼び手は、method を絞った行を引けない
    expect(resolveAlcBinding(path, env, "browser")).toBeNull();
    for (const proxy of ["device", "admin", "rpc"] as const) {
      expect(resolveAlcBinding(path, env, proxy, "GET"), proxy).toBeNull();
    }
  });

  it("alc-proxy からの起票の POST は binding に届かず Cloud Run へ", async () => {
    vi.mocked(mintGoogleIdToken).mockReset();
    vi.mocked(mintGoogleIdToken).mockResolvedValue("fake-oidc-token");
    const { dtako, cloudRun, env } = setup();
    const res = await handleAlcProxy(alcReq("/alc-proxy/api/dtako/tickets", { method: "POST", body: "{}" }), env);
    expect(await res.text()).toBe("from-cloud-run");
    expect(dtako.fetch).not.toHaveBeenCalled();
    expect(cloudRun).toHaveBeenCalledTimes(1);
  });

  it("1 件と close は画面用、結果の反映は内部用", () => {
    const { dtako, env } = setup();
    const target = { fetcher: dtako, host: "alc-dtako" };
    const rows: Array<[string, ReadonlyArray<"browser" | "internal" | "device" | "admin" | "rpc">]> = [
      ["/api/dtako/tickets/close", ["browser"]],
      [`/api/dtako/tickets/${ID}`, ["browser"]],
      [`/api/dtako/tickets/${ID.toUpperCase()}`, ["browser"]],
      [`/api/dtako/tickets/${ID}/scraped`, ["internal"]],
    ];
    for (const [path, allowed] of rows) {
      for (const proxy of ["browser", "internal", "device", "admin", "rpc"] as const) {
        const want = allowed.includes(proxy) ? target : null;
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toEqual(want);
      }
    }
  });

  it("近い名前・UUID でない id・下位の口は回らない", () => {
    const { env } = setup();
    for (const path of [
      "/api/dtako/tickets/",
      "/api/dtako/ticketsx",
      "/api/dtako/tickets/closex",
      "/api/dtako/tickets/close/x",
      "/api/dtako/tickets/ticket-1",
      "/api/dtako/tickets/ticket-1/scraped",
      `/api/dtako/tickets/${ID}x`,
      `/api/dtako/tickets/${ID}/scrapedx`,
      `/api/dtako/tickets/${ID}/scraped/x`,
    ]) {
      for (const proxy of ["browser", "internal", "device", "admin", "rpc"] as const) {
        expect(resolveAlcBinding(path, env, proxy), `${proxy} ${path}`).toBeNull();
      }
    }
  });

  it("binding が未定義なら null (= Cloud Run)", () => {
    const { env } = setup({ ALC_DTAKO: undefined });
    expect(resolveAlcBinding("/api/dtako/tickets", env, "browser", "GET")).toBeNull();
    expect(resolveAlcBinding(`/api/dtako/tickets/${ID}/scraped`, env, "internal")).toBeNull();
  });

  it("alc-proxy の一覧・1 件・close は binding に届く (method・query もそのまま)", async () => {
    const { dtako, cloudRun, env } = setup();
    for (const [path, method] of [
      ["/api/dtako/tickets?status=open", "GET"],
      [`/api/dtako/tickets/${ID}`, "GET"],
      ["/api/dtako/tickets/close", "POST"],
    ] as const) {
      const res = await handleAlcProxy(alcReq(`/alc-proxy${path}`, { method }), env);
      expect(await res.text(), path).toBe("from-binding");
    }
    expect(dtako.fetch.mock.calls.map((c) => [c[0], c[1]!.method])).toEqual([
      ["https://alc-dtako/api/dtako/tickets?status=open", "GET"],
      [`https://alc-dtako/api/dtako/tickets/${ID}`, "GET"],
      ["https://alc-dtako/api/dtako/tickets/close", "POST"],
    ]);
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("alc-internal-proxy の起票・結果の反映は binding に届き、ヘッダは X-Tenant-ID と Content-Type だけ", async () => {
    vi.mocked(mintGoogleIdToken).mockReset();
    const { dtako, cloudRun, env } = setup();
    for (const [path, method] of [
      ["/api/dtako/tickets", "POST"],
      [`/api/dtako/tickets/${ID}/scraped`, "PATCH"],
    ] as const) {
      const req = new Request(`https://auth.test.example/alc-internal-proxy${path}`, {
        method,
        headers: { "X-Alc-Proxy-Secret": PROXY_SECRET, "X-Tenant-ID": TENANT, "content-type": "application/json" },
        body: "{}",
      });
      const res = await handleAlcInternalProxy(req, env);
      expect(await res.text(), path).toBe("from-binding");
    }
    expect(dtako.fetch.mock.calls.map((c) => [c[0], c[1]!.method, c[1]!.headers])).toEqual([
      ["https://alc-dtako/api/dtako/tickets", "POST", { "X-Tenant-ID": TENANT, "Content-Type": "application/json" }],
      [
        `https://alc-dtako/api/dtako/tickets/${ID}/scraped`,
        "PATCH",
        { "X-Tenant-ID": TENANT, "Content-Type": "application/json" },
      ],
    ]);
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
  });
});
