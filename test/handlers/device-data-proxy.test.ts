import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";
import {
  DEVICE_ROLE,
  DEVICE_ROLE_DTAKO_INGEST,
  DEVICE_ROLE_DTAKO_RELAY,
  DEVICE_ROLE_KIOSK,
  DEVICE_ROLE_TENKO_MANAGER,
  DEVICE_ROLE_BP_STATION,
} from "../../src/lib/device";

// OIDC mint は別ユニットでテスト済み。ここでは handler の flow
// (device JWT 検証 → role/path allowlist → OIDC mint → forward) を固定する。
vi.mock("../../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async () => "fake-oidc-token"),
}));

import { handleDeviceDataProxy } from "../../src/handlers/device-data-proxy";

const TENANT = "11111111-1111-1111-1111-111111111111";
const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

function env(overrides: Record<string, unknown> = {}) {
  return createMockEnv({
    ALC_API_PROXY_SA_KEY: "{}", // resolveSecret が非空を返せばよい (oidc は mock)
    ...overrides,
  });
}

async function deviceToken(claims: Record<string, unknown> = {}): Promise<string> {
  return signTestJwt(
    { sub: "device-1", tenant_id: TENANT, role: DEVICE_ROLE_DTAKO_INGEST, ...claims },
    TEST_JWT_SECRET,
  );
}

function req(path: string, init: RequestInit & { token?: string | null } = {}): Request {
  const headers: Record<string, string> = { ...(init.headers as Record<string, string>) };
  if (init.token !== null && init.token !== undefined) headers["Authorization"] = `Bearer ${init.token}`;
  return new Request(`https://auth.ippoan.org${path}`, {
    method: init.method ?? "POST",
    headers,
    body: init.body,
  });
}

describe("handleDeviceDataProxy (rust-alc-api#434 followup, browser-render-rust dtako ingest)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("Authorization ヘッダー欠落は 401", async () => {
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/dtako-logs/bulk"),
      env(),
    );
    expect(res.status).toBe(401);
  });

  it("不正な device JWT は 401", async () => {
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/dtako-logs/bulk", { token: "garbage" }),
      env(),
    );
    expect(res.status).toBe(401);
  });

  it("JWT_SECRET 未 bind は 503", async () => {
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/dtako-logs/bulk", { token: await deviceToken() }),
      env({ JWT_SECRET: undefined }),
    );
    expect(res.status).toBe(503);
  });

  it("ALC_API_PROXY_SA_KEY 未設定は 503", async () => {
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/dtako-logs/bulk", { token: await deviceToken() }),
      env({ ALC_API_PROXY_SA_KEY: undefined }),
    );
    expect(res.status).toBe(503);
  });

  it("ALC_API_ORIGIN 未設定は 503", async () => {
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/dtako-logs/bulk", { token: await deviceToken() }),
      env({ ALC_API_ORIGIN: undefined }),
    );
    expect(res.status).toBe(503);
  });

  it("tenant_id クレーム欠落は 401", async () => {
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/dtako-logs/bulk", {
        token: await deviceToken({ tenant_id: undefined }),
      }),
      env(),
    );
    expect(res.status).toBe(401);
  });

  it("role クレーム欠落は 401", async () => {
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/dtako-logs/bulk", { token: await deviceToken({ role: undefined }) }),
      env(),
    );
    expect(res.status).toBe(401);
  });

  it("allowlist に無い role は 403", async () => {
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/dtako-logs/bulk", {
        token: await deviceToken({ role: "unknown-role" }),
      }),
      env(),
    );
    expect(res.status).toBe(403);
  });

  it("role は許可されているが path が allowlist に無い場合は 403 (盗難時の blast radius 限定)", async () => {
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/employees", { token: await deviceToken() }),
      env(),
    );
    expect(res.status).toBe(403);
  });

  it("path 部分が空 (= プレフィックスのみ) は \"/\" として判定される", async () => {
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy", { token: await deviceToken() }),
      env(),
    );
    expect(res.status).toBe(403);
  });

  it("正常: OIDC Bearer + device JWT 由来の X-Tenant-ID を付けて forward し、client からの X-Tenant-ID 詐称は無視する", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/dtako-logs/bulk", {
        token: await deviceToken(),
        headers: {
          "content-type": "application/json",
          // 攻撃者/バグで混入しても、tenant は device JWT 由来のものだけを使う。
          "X-Tenant-ID": "99999999-9999-9999-9999-999999999999",
        },
        body: JSON.stringify([{ vehicle_cd: 1 }]),
      }),
      env(),
    );
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/dtako-logs/bulk");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
    expect(h["X-Tenant-ID"]).toBe(TENANT);
    expect(h["Content-Type"]).toBe("application/json");
    expect((init as RequestInit).method).toBe("POST");
    expect((init as RequestInit).body).toBeDefined();
  });

  it("device-dtako-ingest role で /api/upload も forward できる (dtako-scraper 共用、Refs dtako-scraper#14)", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/upload", {
        token: await deviceToken(),
        headers: { "content-type": "multipart/form-data; boundary=x" },
        body: "dummy-multipart-body",
      }),
      env(),
    );
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/upload");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
    expect(h["X-Tenant-ID"]).toBe(TENANT);
  });

  it("OIDC mint 失敗は 502 (詳細は出さない)", async () => {
    const { mintGoogleIdToken } = await import("../../src/lib/oidc");
    (mintGoogleIdToken as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("boom"),
    );
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/dtako-logs/bulk", { token: await deviceToken() }),
      env(),
    );
    expect(res.status).toBe(502);
  });
});

describe("device-dtako-relay role (ohishi-exp/nuxt-dtako-admin#931 / #933)", () => {
  beforeEach(() => vi.restoreAllMocks());

  async function relayToken(): Promise<string> {
    return signTestJwt(
      { sub: "device-relay-1", tenant_id: TENANT, role: DEVICE_ROLE_DTAKO_RELAY },
      TEST_JWT_SECRET,
    );
  }

  function okFetch() {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    return fetchMock;
  }

  // ★ #931 (書き) と #933 (読み) が同じ 1 行の allowlist で通ることを固定する。
  //   allowlist は method を見ないので、GET と POST の両方が同じ path で通る。
  for (const method of ["GET", "POST"]) {
    it(`${method} /api/scraper/history を forward する (tenant は device record 由来)`, async () => {
      const fetchMock = okFetch();
      const res = await handleDeviceDataProxy(
        req("/device-data-proxy/api/scraper/history?limit=20", {
          method,
          token: await relayToken(),
          ...(method === "POST"
            ? { headers: { "content-type": "application/json" }, body: JSON.stringify({ a: 1 }) }
            : {}),
        }),
        env(),
      );
      expect(res.status).toBe(200);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, init] = fetchMock.mock.calls[0]!;
      // query はそのまま forward される (allowlist は pathname だけ見る)。
      expect(String(url)).toBe("https://alc-api.test.example/api/scraper/history?limit=20");
      const h = (init as RequestInit).headers as Record<string, string>;
      expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
      // ★ 呼び手の申告ではなく device record の tenant が入る (詐称不能)。
      expect(h["X-Tenant-ID"]).toBe(TENANT);
    });
  }

  it("GET /api/dtako/events/etags も forward する (#933 の fetchUnsplit)", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/dtako/events/etags?date_from=2026-07-01&date_to=2026-07-31", {
        method: "GET",
        token: await relayToken(),
      }),
      env(),
    );
    expect(res.status).toBe(200);
    expect(String(fetchMock.mock.calls[0]![0])).toBe(
      "https://alc-api.test.example/api/dtako/events/etags?date_from=2026-07-01&date_to=2026-07-31",
    );
  });

  it("★ 呼び手が X-Tenant-ID を詐称しても device record の tenant で上書きされる", async () => {
    const fetchMock = okFetch();
    await handleDeviceDataProxy(
      req("/device-data-proxy/api/scraper/history", {
        method: "POST",
        token: await relayToken(),
        headers: { "content-type": "application/json", "X-Tenant-ID": "99999999-9999-9999-9999-999999999999" },
        body: "{}",
      }),
      env(),
    );
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBe(TENANT);
  });

  it("★ relay role は ingest の path を叩けない (最小権限 — 双方向に広げない)", async () => {
    const fetchMock = okFetch();
    for (const p of ["/device-data-proxy/api/upload", "/device-data-proxy/api/dtako-logs/bulk"]) {
      const res = await handleDeviceDataProxy(req(p, { token: await relayToken() }), env());
      expect(res.status, p).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("★ ingest role は履歴の path を叩けない (VPS 側に書き込み権限を渡さない)", async () => {
    const fetchMock = okFetch();
    for (const p of [
      "/device-data-proxy/api/scraper/history",
      "/device-data-proxy/api/dtako/events/etags",
    ]) {
      const res = await handleDeviceDataProxy(req(p, { token: await deviceToken() }), env());
      expect(res.status, p).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("allowlist 外は relay role でも 403", async () => {
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/employees", { token: await relayToken() }),
      env(),
    );
    expect(res.status).toBe(403);
  });
});

describe("device-uploader role (carins の車検証 upload、Refs ippoan/nuxt-pwa-carins#54)", () => {
  beforeEach(() => vi.restoreAllMocks());

  async function uploaderToken(): Promise<string> {
    return signTestJwt(
      { sub: "device-carins-1", tenant_id: TENANT, role: DEVICE_ROLE },
      TEST_JWT_SECRET,
    );
  }

  function okFetch() {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    return fetchMock;
  }

  // ★ smb-watch (無人 box) の保存も、share_target 経由の人間操作も同じ 1 path に
  //   集まる。allowlist は method を見ないので GET (一覧) / POST (upload) の
  //   両方が通ることを固定する。
  for (const method of ["GET", "POST"]) {
    it(`${method} /api/files を forward する (tenant は device record 由来)`, async () => {
      const fetchMock = okFetch();
      const res = await handleDeviceDataProxy(
        req("/device-data-proxy/api/files", {
          method,
          token: await uploaderToken(),
          ...(method === "POST"
            ? { headers: { "content-type": "multipart/form-data; boundary=x" }, body: "dummy-multipart-body" }
            : {}),
        }),
        env(),
      );
      expect(res.status).toBe(200);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, init] = fetchMock.mock.calls[0]!;
      expect(String(url)).toBe("https://alc-api.test.example/api/files");
      const h = (init as RequestInit).headers as Record<string, string>;
      expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
      // ★ 呼び手の申告ではなく device record の tenant が入る (詐称不能)。
      expect(h["X-Tenant-ID"]).toBe(TENANT);
    });
  }

  it("★ allowlist 外は uploader role でも 403 (盗難時も車検証 upload だけに限定)", async () => {
    const fetchMock = okFetch();
    for (const p of [
      "/device-data-proxy/api/employees",
      "/device-data-proxy/api/dtako-logs/bulk",
      "/device-data-proxy/api/scraper/history",
    ]) {
      const res = await handleDeviceDataProxy(req(p, { token: await uploaderToken() }), env());
      expect(res.status, p).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("★ 他 role は /api/files を叩けない (最小権限 — 双方向に広げない)", async () => {
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/files", { token: await deviceToken() }),
      env(),
    );
    expect(res.status).toBe(403);
  });
});

describe("device-kiosk role (method + path 許可表、Refs ippoan/alc-app#227)", () => {
  beforeEach(() => vi.restoreAllMocks());

  async function kioskToken(): Promise<string> {
    return signTestJwt(
      { sub: "device-kiosk-1", tenant_id: TENANT, role: DEVICE_ROLE_KIOSK },
      TEST_JWT_SECRET,
    );
  }

  function okFetch() {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    return fetchMock;
  }

  // ★ KIOSK_ROUTES の全行を method + path で固定する (表駆動)。
  const ALLOWED: ReadonlyArray<{ method: string; path: string }> = [
    { method: "GET", path: "/api/employees" },
    { method: "POST", path: "/api/employees/lookup" },
    { method: "GET", path: "/api/employees/by-code/E001" },
    { method: "GET", path: "/api/employees/face-data" },
    { method: "PUT", path: "/api/employees/emp-1/face" },
    { method: "PUT", path: "/api/vein/templates/emp-1" },
    { method: "GET", path: "/api/vein/templates" },
    { method: "POST", path: "/api/vein/identify" },
    { method: "GET", path: "/api/employees/emp-1" },
    { method: "GET", path: "/api/timecard/punches" },
    { method: "GET", path: "/api/timecard/punches/csv" },
    { method: "GET", path: "/api/timecard/cards" },
    { method: "POST", path: "/api/timecard/cards" },
    { method: "DELETE", path: "/api/timecard/cards/card-1" },
    { method: "POST", path: "/api/measurements" },
    { method: "POST", path: "/api/measurements/start" },
    { method: "PUT", path: "/api/measurements/m-1" },
    { method: "GET", path: "/api/measurements" },
    { method: "GET", path: "/api/measurements/m-1" },
    { method: "GET", path: "/api/measurements/m-1/face-photo" },
    { method: "GET", path: "/api/measurements/m-1/video" },
    { method: "POST", path: "/api/upload/face-photo" },
    { method: "POST", path: "/api/upload/blow-video" },
    { method: "POST", path: "/api/upload/report-audio" },
    { method: "GET", path: "/api/tenko/schedules/pending/emp-1" },
    { method: "POST", path: "/api/tenko/sessions/start" },
    { method: "PUT", path: "/api/tenko/sessions/s-1/alcohol" },
    { method: "PUT", path: "/api/tenko/sessions/s-1/medical" },
    { method: "PUT", path: "/api/tenko/sessions/s-1/self-declaration" },
    { method: "PUT", path: "/api/tenko/sessions/s-1/daily-inspection" },
    { method: "PUT", path: "/api/tenko/sessions/s-1/instruction-confirm" },
    { method: "PUT", path: "/api/tenko/sessions/s-1/report" },
    { method: "PUT", path: "/api/tenko/sessions/s-1/carrying-items" },
    { method: "POST", path: "/api/tenko/sessions/s-1/cancel" },
    { method: "GET", path: "/api/carrying-items" },
    { method: "GET", path: "/api/devices/settings/d-1" },
    { method: "PUT", path: "/api/devices/update-last-login" },
    { method: "GET", path: "/api/tenko/driver-info/emp-1" },
    { method: "GET", path: "/api/tenko/dashboard" },
    { method: "GET", path: "/api/tenko/sessions" },
    { method: "GET", path: "/api/tenko/sessions/s-1" },
    { method: "POST", path: "/api/tenko/sessions/s-1/interrupt" },
    { method: "POST", path: "/api/tenko/sessions/s-1/self-resume" },
    { method: "POST", path: "/api/car-inspections/lookup" },
  ];

  for (const { method, path } of ALLOWED) {
    it(`${method} ${path} を forward する`, async () => {
      const fetchMock = okFetch();
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, {
          method,
          token: await kioskToken(),
          ...(method !== "GET"
            ? { headers: { "content-type": "application/json" }, body: JSON.stringify({}) }
            : {}),
        }),
        env(),
      );
      expect(res.status, path).toBe(200);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, init] = fetchMock.mock.calls[0]!;
      expect(String(url)).toBe(`https://alc-api.test.example${path}`);
      const h = (init as RequestInit).headers as Record<string, string>;
      expect(h["X-Tenant-ID"]).toBe(TENANT);
    });
  }

  it("query は転送される (判定は pathname だけ)", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/employees?active=true", {
        method: "GET",
        token: await kioskToken(),
      }),
      env(),
    );
    expect(res.status).toBe(200);
    expect(String(fetchMock.mock.calls[0]![0])).toBe(
      "https://alc-api.test.example/api/employees?active=true",
    );
  });

  it("表にある path でも違う method は 403", async () => {
    const fetchMock = okFetch();
    const cases: ReadonlyArray<{ method: string; path: string }> = [
      { method: "DELETE", path: "/api/employees/emp-1" },
      { method: "PUT", path: "/api/tenko/dashboard" },
      { method: "DELETE", path: "/api/tenko/sessions/s-1" },
      { method: "PUT", path: "/api/timecard/cards/card-1" },
      { method: "DELETE", path: "/api/timecard/cards" },
      { method: "DELETE", path: "/api/measurements/m-1" },
      { method: "POST", path: "/api/measurements/m-1/video" },
      { method: "PUT", path: "/api/measurements/m-1/face-photo" },
      { method: "GET", path: "/api/car-inspections/lookup" },
    ];
    for (const { method, path } of cases) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method, token: await kioskToken() }),
        env(),
      );
      expect(res.status, `${method} ${path}`).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("表に無い path は 403 (resume は rust 側 AuthUser 必須のため対象外のまま)", async () => {
    const fetchMock = okFetch();
    const cases: ReadonlyArray<{ method: string; path: string }> = [
      { method: "POST", path: "/api/tenko/sessions/s-1/resume" },
      { method: "PUT", path: "/api/carrying-items/c-1" },
      { method: "GET", path: "/api/employees/emp-1/license" },
      { method: "GET", path: "/api/car-inspections/current" },
      // 指静脈: 削除口はキオスクに開けない (顔と同じ)。
      { method: "DELETE", path: "/api/vein/templates/emp-1" },
      { method: "GET", path: "/api/vein/templates/emp-1" },
      { method: "POST", path: "/api/vein/templates" },
      { method: "PUT", path: "/api/vein/identify" },
    ];
    for (const { method, path } of cases) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method, token: await kioskToken() }),
        env(),
      );
      expect(res.status, `${method} ${path}`).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("segment が 1 つ多い path は 403", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/employees/lookup/extra", {
        method: "POST",
        token: await kioskToken(),
      }),
      env(),
    );
    expect(res.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("★ 呼び手が X-Tenant-ID を詐称しても device record の tenant で上書きされる", async () => {
    const fetchMock = okFetch();
    await handleDeviceDataProxy(
      req("/device-data-proxy/api/employees", {
        method: "GET",
        token: await kioskToken(),
        headers: { "X-Tenant-ID": "99999999-9999-9999-9999-999999999999" },
      }),
      env(),
    );
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBe(TENANT);
  });

  it("★ 他 role は kiosk 用 path を叩けない (最小権限 — 双方向に広げない)", async () => {
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/employees", { token: await deviceToken() }),
      env(),
    );
    expect(res.status).toBe(403);
  });
});

describe("X-Device-Bp-Bonded ヘッダ転送 (Refs #571)", () => {
  beforeEach(() => vi.restoreAllMocks());

  async function kioskToken(claims: Record<string, unknown> = {}): Promise<string> {
    return signTestJwt(
      { sub: "device-kiosk-1", tenant_id: TENANT, role: DEVICE_ROLE_KIOSK, ...claims },
      TEST_JWT_SECRET,
    );
  }

  function okFetch() {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    return fetchMock;
  }

  it.each<[boolean, string]>([
    [true, "1"],
    [false, "0"],
  ])("JWT の bp_bonded=%s claim から X-Device-Bp-Bonded: %s を組み立てて転送する", async (bpBonded, want) => {
    const fetchMock = okFetch();
    await handleDeviceDataProxy(
      req("/device-data-proxy/api/employees", {
        method: "GET",
        token: await kioskToken({ bp_bonded: bpBonded }),
      }),
      env(),
    );
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["X-Device-Bp-Bonded"]).toBe(want);
  });

  it("bp_bonded claim が無ければヘッダ自体を付けない (「不明」)", async () => {
    const fetchMock = okFetch();
    await handleDeviceDataProxy(
      req("/device-data-proxy/api/employees", { method: "GET", token: await kioskToken() }),
      env(),
    );
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h).not.toHaveProperty("X-Device-Bp-Bonded");
  });

  it("★ 呼び手が X-Device-Bp-Bonded ヘッダを付けて送っても、転送されるのは JWT claim 由来の値 (偽装不可)", async () => {
    const fetchMock = okFetch();
    // claim は false だが、client は true (1) を偽装して送る。
    await handleDeviceDataProxy(
      req("/device-data-proxy/api/employees", {
        method: "GET",
        token: await kioskToken({ bp_bonded: false }),
        headers: { "X-Device-Bp-Bonded": "1" },
      }),
      env(),
    );
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["X-Device-Bp-Bonded"]).toBe("0");
  });

  it("★ claim が無いのに呼び手がヘッダを付けて送っても、転送側では付かない (偽装で「不明」を詐称できない)", async () => {
    const fetchMock = okFetch();
    await handleDeviceDataProxy(
      req("/device-data-proxy/api/employees", {
        method: "GET",
        token: await kioskToken(),
        headers: { "X-Device-Bp-Bonded": "1" },
      }),
      env(),
    );
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h).not.toHaveProperty("X-Device-Bp-Bonded");
  });
});

describe("device-tenko-manager role (運行管理者席、Refs ippoan/alc-app#337)", () => {
  beforeEach(() => vi.restoreAllMocks());

  async function managerToken(): Promise<string> {
    return signTestJwt(
      { sub: "alarm:deadbeefdeadbeef", tenant_id: TENANT, role: DEVICE_ROLE_TENKO_MANAGER },
      TEST_JWT_SECRET,
    );
  }

  async function kioskToken(): Promise<string> {
    return signTestJwt(
      { sub: "device-kiosk-1", tenant_id: TENANT, role: DEVICE_ROLE_KIOSK },
      TEST_JWT_SECRET,
    );
  }

  function okFetch() {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    return fetchMock;
  }

  // ★ TENKO_MANAGER_ROUTES の全行を method + path で固定する (表駆動)。
  const ALLOWED: ReadonlyArray<{ method: string; path: string }> = [
    { method: "GET", path: "/api/tenko/schedules" },
    { method: "POST", path: "/api/tenko/schedules" },
    { method: "POST", path: "/api/tenko/schedules/batch" },
    { method: "GET", path: "/api/tenko/schedules/sch-1" },
    { method: "PUT", path: "/api/tenko/schedules/sch-1" },
    { method: "DELETE", path: "/api/tenko/schedules/sch-1" },
  ];

  for (const { method, path } of ALLOWED) {
    it(`${method} ${path} を forward する (X-Tenant-ID は JWT の tenant)`, async () => {
      const fetchMock = okFetch();
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, {
          method,
          token: await managerToken(),
          ...(method !== "GET"
            ? { headers: { "content-type": "application/json" }, body: JSON.stringify({}) }
            : {}),
        }),
        env(),
      );
      expect(res.status, `${method} ${path}`).toBe(200);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, init] = fetchMock.mock.calls[0]!;
      expect(String(url)).toBe(`https://alc-api.test.example${path}`);
      const h = (init as RequestInit).headers as Record<string, string>;
      expect(h["X-Tenant-ID"]).toBe(TENANT);
    });
  }

  it("★ 予定以外の口は 1 本も通らない (既定拒否 — kiosk の許可表を引き継がない)", async () => {
    const fetchMock = okFetch();
    // kiosk が通せる口を中心に、運行管理者タブの他タブが叩く経路まで並べる。
    const cases: ReadonlyArray<{ method: string; path: string }> = [
      { method: "GET", path: "/api/employees" },
      { method: "POST", path: "/api/employees/lookup" },
      { method: "GET", path: "/api/employees/emp-1" },
      { method: "GET", path: "/api/employees/face-data" },
      { method: "PUT", path: "/api/employees/emp-1/face" },
      { method: "GET", path: "/api/tenko/dashboard" },
      { method: "GET", path: "/api/tenko/sessions" },
      { method: "GET", path: "/api/tenko/sessions/s-1" },
      { method: "POST", path: "/api/tenko/sessions/start" },
      { method: "GET", path: "/api/measurements" },
      { method: "GET", path: "/api/measurements/m-1/face-photo" },
      { method: "POST", path: "/api/measurements" },
      { method: "POST", path: "/api/upload/face-photo" },
      { method: "GET", path: "/api/timecard/punches" },
      { method: "GET", path: "/api/carrying-items" },
      { method: "POST", path: "/api/car-inspections/lookup" },
      { method: "GET", path: "/api/files" },
      { method: "POST", path: "/api/scraper/history" },
      { method: "POST", path: "/api/upload" },
      // 予定でも kiosk 側の口 (乗務員ごとの未実施一覧) は運行管理者の表に無い。
      { method: "GET", path: "/api/tenko/schedules/pending/emp-1" },
    ];
    for (const { method, path } of cases) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method, token: await managerToken() }),
        env(),
      );
      expect(res.status, `${method} ${path}`).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("表にある path でも違う method は 403", async () => {
    const fetchMock = okFetch();
    const cases: ReadonlyArray<{ method: string; path: string }> = [
      { method: "PUT", path: "/api/tenko/schedules" },
      { method: "DELETE", path: "/api/tenko/schedules" },
      { method: "POST", path: "/api/tenko/schedules/sch-1" },
    ];
    for (const { method, path } of cases) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method, token: await managerToken() }),
        env(),
      );
      expect(res.status, `${method} ${path}`).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("batch は {id} の pattern にも当たるので GET/PUT/DELETE も通る (rust 側で 405)", async () => {
    const fetchMock = okFetch();
    for (const method of ["GET", "PUT", "DELETE"]) {
      const res = await handleDeviceDataProxy(
        req("/device-data-proxy/api/tenko/schedules/batch", {
          method,
          token: await managerToken(),
        }),
        env(),
      );
      // `batch` を予約語として除外していない (negative lookahead を足すほどの実害が
      // 無い — 転送先は同じ予定リソースで、rust 側は batch に POST しか生やして
      // いないため 405 が返る)。意図した状態としてここで固定する。
      expect(res.status, method).toBe(200);
    }
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("segment が 1 つ多い path は 403", async () => {
    const fetchMock = okFetch();
    for (const path of ["/api/tenko/schedules/sch-1/extra", "/api/tenko/schedules/batch/extra"]) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method: "GET", token: await managerToken() }),
        env(),
      );
      expect(res.status, path).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("★ 呼び手が X-Tenant-ID を詐称しても JWT の tenant で上書きされる", async () => {
    const fetchMock = okFetch();
    await handleDeviceDataProxy(
      req("/device-data-proxy/api/tenko/schedules", {
        method: "GET",
        token: await managerToken(),
        headers: { "X-Tenant-ID": "99999999-9999-9999-9999-999999999999" },
      }),
      env(),
    );
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBe(TENANT);
  });

  it("★ device-kiosk は予定の CRUD を叩けないまま (KIOSK_ROUTES を広げていない)", async () => {
    const fetchMock = okFetch();
    for (const { method, path } of ALLOWED) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method, token: await kioskToken() }),
        env(),
      );
      expect(res.status, `${method} ${path}`).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("★ 他 role は運行管理者の path を叩けない (最小権限 — 双方向に広げない)", async () => {
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/tenko/schedules", { method: "GET", token: await deviceToken() }),
      env(),
    );
    expect(res.status).toBe(403);
  });

  it("role を持たない / 未知の role は何も転送できない (既定拒否)", async () => {
    const fetchMock = okFetch();
    const unknown = await signTestJwt(
      { sub: "x", tenant_id: TENANT, role: "device-unknown" },
      TEST_JWT_SECRET,
    );
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/tenko/schedules", { method: "GET", token: unknown }),
      env(),
    );
    expect(res.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("device-bp-station role (血圧測定台、Refs ippoan/alc-app#353)", () => {
  beforeEach(() => vi.restoreAllMocks());

  async function bpToken(): Promise<string> {
    return signTestJwt(
      { sub: "alarm:deadbeefdeadbeef", tenant_id: TENANT, role: DEVICE_ROLE_BP_STATION },
      TEST_JWT_SECRET,
    );
  }

  async function kioskToken(): Promise<string> {
    return signTestJwt(
      { sub: "device-kiosk-1", tenant_id: TENANT, role: DEVICE_ROLE_KIOSK },
      TEST_JWT_SECRET,
    );
  }

  function okFetch() {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    return fetchMock;
  }

  // ★ BP_STATION_ROUTES の全行を method + path で固定する (表駆動)。
  const ALLOWED: ReadonlyArray<{ method: string; path: string }> = [
    { method: "POST", path: "/api/employees/lookup" },
    { method: "GET", path: "/api/employees/face-data" },
    { method: "POST", path: "/api/measurements/start" },
    { method: "PUT", path: "/api/measurements/m-1" },
  ];

  for (const { method, path } of ALLOWED) {
    it(`${method} ${path} を forward する (X-Tenant-ID は JWT の tenant)`, async () => {
      const fetchMock = okFetch();
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, {
          method,
          token: await bpToken(),
          ...(method !== "GET"
            ? { headers: { "content-type": "application/json" }, body: JSON.stringify({}) }
            : {}),
        }),
        env(),
      );
      expect(res.status, `${method} ${path}`).toBe(200);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, init] = fetchMock.mock.calls[0]!;
      expect(String(url)).toBe(`https://alc-api.test.example${path}`);
      const h = (init as RequestInit).headers as Record<string, string>;
      expect(h["X-Tenant-ID"]).toBe(TENANT);
    });
  }

  it("★ 表に無い method+path は 403 (既定拒否 — kiosk の許可表を引き継がない)", async () => {
    const fetchMock = okFetch();
    const cases: ReadonlyArray<{ method: string; path: string }> = [
      // 表にある path でも method 違い。
      { method: "GET", path: "/api/measurements/m-1" },
      { method: "DELETE", path: "/api/employees/lookup" },
      { method: "PUT", path: "/api/employees/face-data" },
      { method: "GET", path: "/api/measurements/start" },
      // kiosk が通せる他の口 (測定台には要らない)。
      { method: "GET", path: "/api/employees" },
      { method: "GET", path: "/api/employees/emp-1" },
      { method: "GET", path: "/api/measurements" },
      { method: "POST", path: "/api/measurements" },
      { method: "GET", path: "/api/tenko/dashboard" },
      { method: "GET", path: "/api/timecard/punches" },
      // 端末レコードを持たないので settings は呼ばれない口 (表に入れていない)。
      { method: "GET", path: "/api/devices/settings/dev-1" },
      // 指静脈: kiosk だけに開けた口で、測定台には開けない。
      { method: "PUT", path: "/api/vein/templates/emp-1" },
      { method: "GET", path: "/api/vein/templates" },
      { method: "POST", path: "/api/vein/identify" },
    ];
    for (const { method, path } of cases) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method, token: await bpToken() }),
        env(),
      );
      expect(res.status, `${method} ${path}`).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("device-kiosk の許可表は BP_STATION_ROUTES 追加で変わらない (退行検知)", async () => {
    // BP_STATION_ROUTES の 4 本は KIOSK_ROUTES にも元から含まれる (両 role とも
    // 呼ぶ口)。ここでは KIOSK_ROUTES 側の table が新設した METHOD_ROUTE_TABLES
    // エントリの影響を受けず今までどおり通ることだけを固定する。
    const fetchMock = okFetch();
    for (const { method, path } of [
      { method: "POST", path: "/api/measurements/start" },
      { method: "PUT", path: "/api/measurements/m-1" },
    ]) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, {
          method,
          token: await kioskToken(),
          ...(method !== "GET"
            ? { headers: { "content-type": "application/json" }, body: JSON.stringify({}) }
            : {}),
        }),
        env(),
      );
      expect(res.status, `${method} ${path}`).toBe(200);
    }
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("★ 他 role は測定台の path を叩けない (最小権限 — 双方向に広げない)", async () => {
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/employees/lookup", {
        method: "POST",
        token: await deviceToken(),
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      }),
      env(),
    );
    expect(res.status).toBe(403);
  });

  it("★ 呼び手が X-Tenant-ID を詐称しても JWT の tenant で上書きされる", async () => {
    const fetchMock = okFetch();
    await handleDeviceDataProxy(
      req("/device-data-proxy/api/employees/face-data", {
        method: "GET",
        token: await bpToken(),
        headers: { "X-Tenant-ID": "99999999-9999-9999-9999-999999999999" },
      }),
      env(),
    );
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBe(TENANT);
  });
});
