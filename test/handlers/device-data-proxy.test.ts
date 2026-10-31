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
  DEVICE_ROLE_CAM_HOST,
} from "../../src/lib/device";

// handler の flow (device JWT 検証 → role/path allowlist → binding へ forward) を固定する。
// 振り分け表は「どの path にも binding がある」fake に差し替える (W9 で Cloud Run 退避を撤去。
// 表に無い path が 404 になることは alc-binding-route.test.ts が本物の表で確認する)。
vi.mock("../../src/lib/alc-backend-route", async (orig) =>
  (await import("../helpers/fake-alc-route")).fakeAlcRouteFactory(await orig<object>()),
);

import { handleDeviceDataProxy } from "../../src/handlers/device-data-proxy";

const TENANT = "11111111-1111-1111-1111-111111111111";
const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

function env(overrides: Record<string, unknown> = {}) {
  return createMockEnv({
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
    expect(h["Authorization"]).toBeUndefined(); // Cloud Run 用 OIDC は付けない (W9)
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
    expect(h["Authorization"]).toBeUndefined(); // Cloud Run 用 OIDC は付けない (W9)
    expect(h["X-Tenant-ID"]).toBe(TENANT);
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
      expect(h["Authorization"]).toBeUndefined(); // Cloud Run 用 OIDC は付けない (W9)
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
      expect(h["Authorization"]).toBeUndefined(); // Cloud Run 用 OIDC は付けない (W9)
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
    { method: "PUT", path: "/api/vein/templates/emp-1/module" },
    // ほかの端末で撮った記録の追加 (Refs ippoan/alc-app#558)。
    { method: "PUT", path: "/api/vein/templates/emp-1/module/devices" },
    { method: "GET", path: "/api/vein/module-templates" },
    // 運行管理者の照合による承認 (Refs ippoan/alc-app#436)。
    { method: "GET", path: "/api/vein/module-templates/pending" },
    { method: "POST", path: "/api/vein/templates/emp-1/approve-by-employee" },
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
    { method: "POST", path: "/api/measurements/m-1/tenko" },
    { method: "GET", path: "/api/measurements" },
    { method: "GET", path: "/api/measurements/m-1" },
    { method: "GET", path: "/api/measurements/m-1/face-photo" },
    { method: "GET", path: "/api/measurements/m-1/video" },
    { method: "POST", path: "/api/upload/face-photo" },
    { method: "POST", path: "/api/upload/blow-video" },
    { method: "POST", path: "/api/upload/report-audio" },
    { method: "GET", path: "/api/tenko/schedules/pending/emp-1" },
    { method: "POST", path: "/api/tenko/sessions/start" },
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
    { method: "POST", path: "/api/timecard/cards/lookup" },
  ];

  // アルコールの段は測定の保存 (`PUT /api/measurements/{id}` の tenko_session_id) で進む。本文で結果を受ける口は通さない
  it("PUT /api/tenko/sessions/{id}/alcohol はキオスクの鍵でも 403", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/tenko/sessions/s-1/alcohol", {
        method: "PUT",
        token: await kioskToken(),
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      }),
      env(),
    );
    expect(res.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

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
      { method: "GET", path: "/api/measurements/m-1/tenko" },
      { method: "PUT", path: "/api/measurements/m-1/tenko" },
      { method: "POST", path: "/api/measurements/m-1/tenko/x" },
      { method: "POST", path: "/api/measurements/tenko" },
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
      // モジュール記録: 余計な path・別 method・別の語尾は 403。
      { method: "PUT", path: "/api/vein/templates/emp-1/module/extra" },
      { method: "POST", path: "/api/vein/templates/emp-1/module" },
      { method: "GET", path: "/api/vein/templates/emp-1/module" },
      // 端末で撮った記録の追加は PUT だけ。別 method・下位 path の余りは 403。
      { method: "POST", path: "/api/vein/templates/emp-1/module/devices" },
      { method: "GET", path: "/api/vein/templates/emp-1/module/devices" },
      { method: "PUT", path: "/api/vein/templates/emp-1/module/devices/dev-1" },
      { method: "PUT", path: "/api/vein/module-templates" },
      { method: "POST", path: "/api/vein/module-templates" },
      { method: "GET", path: "/api/vein/module-templates/emp-1" },
      // 承認: 管理者のログインの口 (pending / approve) は端末に開けない。照合による承認は別 method・余りの path を 403。
      { method: "GET", path: "/api/vein/templates/pending" },
      { method: "POST", path: "/api/vein/templates/emp-1/approve" },
      { method: "POST", path: "/api/vein/module-templates/pending" },
      { method: "GET", path: "/api/vein/templates/emp-1/approve-by-employee" },
      { method: "PUT", path: "/api/vein/templates/emp-1/approve-by-employee" },
      { method: "POST", path: "/api/vein/templates/emp-1/approve-by-employee/extra" },
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

  const MID = "22222222-2222-2222-2222-222222222222";
  // ★ TENKO_MANAGER_ROUTES の全行を method + path で固定する (表駆動)。
  const ALLOWED: ReadonlyArray<{ method: string; path: string }> = [
    { method: "GET", path: "/api/tenko/schedules" },
    { method: "POST", path: "/api/tenko/schedules" },
    { method: "POST", path: "/api/tenko/schedules/batch" },
    { method: "GET", path: "/api/tenko/schedules/sch-1" },
    { method: "PUT", path: "/api/tenko/schedules/sch-1" },
    { method: "DELETE", path: "/api/tenko/schedules/sch-1" },
    // 指静脈の照合データの読み取り (運行管理者の入口の指静脈ログイン)
    { method: "GET", path: "/api/vein/module-templates" },
    { method: "GET", path: "/api/vein/templates" },
    // 席の機体で撮った記録の追加 (Refs ippoan/alc-app#558)
    { method: "PUT", path: "/api/vein/templates/emp-1/module/devices" },
    // 運行管理者のダッシュボードの読み取り専用の画面 (オーナー決定 2026-10-31)
    { method: "GET", path: "/api/tenko/dashboard" },
    { method: "GET", path: `/api/measurements/${MID}` },
    { method: "GET", path: `/api/measurements/${MID}/face-photo` },
    { method: "GET", path: `/api/measurements/${MID}/video` },
    { method: "GET", path: "/api/tenko/records/csv" },
    { method: "GET", path: "/api/tenko/health-baselines" },
    { method: "GET", path: "/api/tenko/equipment-failures" },
    { method: "GET", path: "/api/tenko/equipment-failures/csv" },
    { method: "GET", path: "/api/carrying-items" },
    { method: "GET", path: "/api/car-inspections/vehicle-categories" },
    { method: "GET", path: "/api/drivers" },
    { method: "GET", path: "/api/daily-hours" },
    { method: "GET", path: "/api/timecard/cards" },
    { method: "GET", path: "/api/timecard/punches" },
    { method: "GET", path: "/api/timecard/punches/csv" },
    { method: "GET", path: "/api/devices" },
    { method: "GET", path: "/api/devices/pending" },
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

  it("★ 予定・遠隔点呼モニターの口以外は 1 本も通らない (既定拒否 — kiosk の許可表を引き継がない)", async () => {
    const fetchMock = okFetch();
    // kiosk が通せる口を中心に、運行管理者タブの他タブが叩く経路まで並べる。
    const cases: ReadonlyArray<{ method: string; path: string }> = [
      { method: "POST", path: "/api/employees/lookup" },
      { method: "GET", path: "/api/employees/face-data" },
      { method: "PUT", path: "/api/employees/emp-1/face" },
      { method: "POST", path: "/api/tenko/sessions/start" },
      { method: "PUT", path: "/api/tenko/sessions/s-1/alcohol" },
      { method: "GET", path: "/api/measurements" },
      { method: "POST", path: "/api/measurements" },
      { method: "POST", path: "/api/upload/face-photo" },
      { method: "POST", path: "/api/car-inspections/lookup" },
      { method: "GET", path: "/api/files" },
      { method: "POST", path: "/api/scraper/history" },
      { method: "POST", path: "/api/upload" },
      // 予定でも kiosk 側の口 (乗務員ごとの未実施一覧) は運行管理者の表に無い。
      { method: "GET", path: "/api/tenko/schedules/pending/emp-1" },
      // 指静脈は照合データの読み取り 2 本と記録の追加だけ。登録し直し・照合・承認・1 件の読み取りは開けない
      { method: "PUT", path: "/api/vein/templates/emp-1" },
      { method: "PUT", path: "/api/vein/templates/emp-1/module" },
      { method: "POST", path: "/api/vein/templates/emp-1/module/devices" },
      { method: "PUT", path: "/api/vein/templates/emp-1/module/devices/dev-1" },
      { method: "POST", path: "/api/vein/identify" },
      { method: "GET", path: "/api/vein/module-templates/pending" },
      { method: "POST", path: "/api/vein/templates/emp-1/approve-by-employee" },
      { method: "GET", path: "/api/vein/templates/emp-1" },
      { method: "GET", path: "/api/vein/templates/pending" },
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

  it("★ 読み取り専用の画面の口は GET だけ — 書き込み (POST/PUT/PATCH/DELETE) と近い path は 403", async () => {
    const fetchMock = okFetch();
    const cases: ReadonlyArray<{ method: string; path: string }> = [
      // 開けた path の書き込み
      { method: "POST", path: "/api/tenko/dashboard" },
      { method: "PUT", path: `/api/measurements/${MID}` },
      { method: "POST", path: `/api/measurements/${MID}` },
      { method: "DELETE", path: `/api/measurements/${MID}` },
      { method: "POST", path: `/api/measurements/${MID}/tenko` },
      { method: "POST", path: `/api/measurements/${MID}/face-photo` },
      { method: "DELETE", path: `/api/measurements/${MID}/video` },
      { method: "POST", path: "/api/tenko/records/csv" },
      { method: "POST", path: "/api/tenko/health-baselines" },
      { method: "PUT", path: `/api/tenko/health-baselines/${MID}` },
      { method: "DELETE", path: `/api/tenko/health-baselines/${MID}` },
      { method: "POST", path: "/api/tenko/equipment-failures" },
      { method: "PUT", path: `/api/tenko/equipment-failures/${MID}` },
      { method: "POST", path: "/api/carrying-items" },
      { method: "PUT", path: `/api/carrying-items/${MID}` },
      { method: "DELETE", path: `/api/carrying-items/${MID}` },
      { method: "POST", path: "/api/drivers" },
      { method: "PUT", path: "/api/daily-hours" },
      { method: "POST", path: "/api/timecard/cards" },
      { method: "DELETE", path: `/api/timecard/cards/${MID}` },
      { method: "POST", path: "/api/timecard/punch" },
      { method: "POST", path: "/api/timecard/punches" },
      { method: "POST", path: "/api/devices" },
      { method: "DELETE", path: `/api/devices/${MID}` },
      { method: "POST", path: `/api/devices/approve/${MID}` },
      { method: "POST", path: `/api/devices/reject/${MID}` },
      { method: "POST", path: "/api/devices/pending" },
      // 近い path (予約語・下位・UUID でない id・別の口)
      { method: "GET", path: "/api/measurements/start" },
      { method: "GET", path: "/api/measurements/alert-test" },
      { method: "GET", path: "/api/measurements/m-1" },
      { method: "GET", path: `/api/measurements/${MID}/tenko` },
      { method: "GET", path: `/api/measurements/${MID}/extra` },
      { method: "GET", path: `/api/tenko/health-baselines/${MID}` },
      { method: "GET", path: `/api/tenko/equipment-failures/${MID}` },
      { method: "GET", path: "/api/tenko/records" },
      { method: "GET", path: "/api/tenko/webhooks" },
      { method: "GET", path: "/api/tenko/daily-health-status" },
      { method: "GET", path: "/api/carrying-items/x" },
      { method: "GET", path: "/api/car-inspections" },
      { method: "GET", path: "/api/car-inspections/vehicle-categories/x" },
      { method: "GET", path: "/api/daily-hours/x" },
      { method: "GET", path: `/api/daily-hours/${MID}/2026-10-01/segments` },
      { method: "GET", path: "/api/drivers/x" },
      { method: "GET", path: "/api/vehicles" },
      { method: "GET", path: `/api/timecard/cards/${MID}` },
      { method: "GET", path: "/api/timecard/punches/x" },
      { method: "GET", path: "/api/devices/settings/x" },
      { method: "GET", path: `/api/devices/${MID}` },
      { method: "GET", path: "/api/devices/pending/x" },
      { method: "GET", path: "/api/devicesx" },
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
    // 指静脈の照合データの読み取りは、もともと kiosk にも開いている口 (KIOSK_ROUTES と同じ行)
    for (const { method, path } of ALLOWED.filter(r => r.path.startsWith("/api/tenko/schedules"))) {
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

  // ── 遠隔点呼モニターと IT点呼の受け画面の 7 本 (Refs ippoan/alc-app#387) ──────────
  const MONITOR_ROUTES: ReadonlyArray<{ method: string; path: string }> = [
    { method: "GET", path: "/api/employees" },
    { method: "GET", path: `/api/employees/${MID}` },
    { method: "GET", path: "/api/employees/by-code/E-001" },
    { method: "GET", path: "/api/tenko/sessions" },
    { method: "GET", path: `/api/tenko/sessions/${MID}` },
    { method: "GET", path: `/api/tenko/driver-info/${MID}` },
    { method: "POST", path: `/api/tenko/sessions/${MID}/judgment` },
  ];

  for (const { method, path } of MONITOR_ROUTES) {
    it(`運行管理者の鍵: 遠隔点呼モニターの ${method} ${path} は backend へ転送される`, async () => {
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
      expect(String(fetchMock.mock.calls[0]![0])).toBe(`https://alc-api.test.example${path}`);
    });
  }

  it("運行管理者の鍵: GET /api/employees/face-data (生体情報) は 403", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/employees/face-data", { method: "GET", token: await managerToken() }),
      env(),
    );
    expect(res.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("運行管理者の鍵 (開発用でない): GET /api/tenko/sessions (一覧) は転送され、X-Device-Dev は付かない", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/tenko/sessions", { method: "GET", token: await managerToken() }),
      env(),
    );
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]![0])).toBe("https://alc-api.test.example/api/tenko/sessions");
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h).not.toHaveProperty("X-Device-Dev");
    expect(h["X-Device-Role"]).toBe(DEVICE_ROLE_TENKO_MANAGER);
  });

  it("運行管理者の鍵: GET /api/devices/settings/<id> は 403", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceDataProxy(
      req(`/device-data-proxy/api/devices/settings/${MID}`, { method: "GET", token: await managerToken() }),
      env(),
    );
    expect(res.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("運行管理者の鍵: 判定の path を GET で叩くと 403 (判定は POST だけ)", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceDataProxy(
      req(`/device-data-proxy/api/tenko/sessions/${MID}/judgment`, {
        method: "GET",
        token: await managerToken(),
      }),
      env(),
    );
    expect(res.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("運行管理者の鍵: UUID でない {id} (face-data / start 等) は 403、segment 過多も 403", async () => {
    const fetchMock = okFetch();
    for (const path of [
      "/api/employees/face-data",
      "/api/employees/emp-1",
      "/api/tenko/sessions/start",
      `/api/employees/${MID}/face`,
      `/api/tenko/sessions/${MID}/extra`,
    ]) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method: "GET", token: await managerToken() }),
        env(),
      );
      expect(res.status, path).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("運行管理者の鍵 (dev_device: true): 記録簿の分岐は kiosk だけ (一覧・1 件は 403。csv は席の読み取りの表で通る)", async () => {
    const fetchMock = okFetch();
    const token = await signTestJwt(
      { sub: "alarm:deadbeefdeadbeef", tenant_id: TENANT, role: DEVICE_ROLE_TENKO_MANAGER, dev_device: true },
      TEST_JWT_SECRET,
    );
    for (const path of ["/api/tenko/records", `/api/tenko/records/${MID}`]) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method: "GET", token }),
        env(),
      );
      expect(res.status, path).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
    // csv は TENKO_MANAGER_ROUTES の読み取り専用の画面の口 (オーナー決定 2026-10-31)
    const csv = await handleDeviceDataProxy(
      req("/device-data-proxy/api/tenko/records/csv", { method: "GET", token }),
      env(),
    );
    expect(csv.status).toBe(200);
  });
});

describe("dev キオスクの記録簿 GET (Refs ippoan/alc-app#387)", () => {
  beforeEach(() => vi.restoreAllMocks());

  const RID = "33333333-3333-3333-3333-333333333333";
  const RECORD_PATHS = ["/api/tenko/records", "/api/tenko/records/csv", `/api/tenko/records/${RID}`];

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

  for (const path of RECORD_PATHS) {
    it(`dev_device: true のキオスク: GET ${path} は通り、backend への要求に X-Device-Dev: 1 が付く`, async () => {
      const fetchMock = okFetch();
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method: "GET", token: await kioskToken({ dev_device: true }) }),
        env(),
      );
      expect(res.status).toBe(200);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(String(fetchMock.mock.calls[0]![0])).toBe(`https://alc-api.test.example${path}`);
      const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
      expect(h["X-Device-Dev"]).toBe("1");
      expect(h["X-Device-Role"]).toBe(DEVICE_ROLE_KIOSK);
    });

    it(`dev_device なしのキオスク: GET ${path} は 403 (本番のキオスクには開かない)`, async () => {
      const fetchMock = okFetch();
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method: "GET", token: await kioskToken() }),
        env(),
      );
      expect(res.status).toBe(403);
      expect(fetchMock).not.toHaveBeenCalled();
    });
  }

  const ADMIN_READ_PATHS = ["/api/hub/measurements", "/api/devices", "/api/devices/pending", "/api/tenko-call/drivers"];

  for (const path of ADMIN_READ_PATHS) {
    it(`dev_device: true のキオスク: GET ${path} は通り (query 付きでも)、X-Device-Dev: 1 が付く`, async () => {
      const fetchMock = okFetch();
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}?limit=5`, { method: "GET", token: await kioskToken({ dev_device: true }) }),
        env(),
      );
      expect(res.status).toBe(200);
      expect(String(fetchMock.mock.calls[0]![0])).toBe(`https://alc-api.test.example${path}?limit=5`);
      const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
      expect(h["X-Device-Dev"]).toBe("1");
    });

    it(`dev でないキオスクの鍵: GET ${path} は 403 のまま`, async () => {
      const fetchMock = okFetch();
      for (const claims of [{}, { dev_device: false }, { dev_device: "1" }]) {
        const res = await handleDeviceDataProxy(
          req(`/device-data-proxy${path}`, { method: "GET", token: await kioskToken(claims) }),
          env(),
        );
        expect(res.status, `${JSON.stringify(claims)} ${path}`).toBe(403);
      }
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it(`dev_device: true のキオスク: POST ${path} と ${path}/x は 403 (GET の完全一致だけ)`, async () => {
      const fetchMock = okFetch();
      const token = await kioskToken({ dev_device: true });
      const post = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method: "POST", token }),
        env(),
      );
      const deep = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}/x`, { method: "GET", token }),
        env(),
      );
      expect(post.status).toBe(403);
      expect(deep.status).toBe(403);
      expect(fetchMock).not.toHaveBeenCalled();
    });
  }

  it("dev_device が false / 文字列 \"1\" のキオスク: 記録簿 GET は 403", async () => {
    const fetchMock = okFetch();
    for (const dev of [false, "1"]) {
      for (const path of RECORD_PATHS) {
        const res = await handleDeviceDataProxy(
          req(`/device-data-proxy${path}`, { method: "GET", token: await kioskToken({ dev_device: dev }) }),
          env(),
        );
        expect(res.status, `${String(dev)} ${path}`).toBe(403);
      }
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("dev_device: true のキオスク: POST /api/tenko/records は 403 (記録簿は GET だけ)", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/tenko/records", { method: "POST", token: await kioskToken({ dev_device: true }) }),
      env(),
    );
    expect(res.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("dev_device: true のキオスク: POST /api/tenko/sessions/<id>/judgment は 403 (キオスクに判定は開かない)", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceDataProxy(
      req(`/device-data-proxy/api/tenko/sessions/${RID}/judgment`, {
        method: "POST",
        token: await kioskToken({ dev_device: true }),
      }),
      env(),
    );
    expect(res.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("dev_device: true のキオスク: 記録簿以外の未許可 path (segment 過多) は 403", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceDataProxy(
      req(`/device-data-proxy/api/tenko/records/${RID}/extra`, {
        method: "GET",
        token: await kioskToken({ dev_device: true }),
      }),
      env(),
    );
    expect(res.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("既存の kiosk の口は dev_device の有無に関わらず従来どおり通る", async () => {
    const fetchMock = okFetch();
    for (const claims of [{}, { dev_device: true }]) {
      const res = await handleDeviceDataProxy(
        req("/device-data-proxy/api/employees", { method: "GET", token: await kioskToken(claims) }),
        env(),
      );
      expect(res.status).toBe(200);
    }
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe("運行管理者の鍵のセッション一覧 GET (開発用の鍵に限らない、Refs ippoan/alc-app#387)", () => {
  beforeEach(() => vi.restoreAllMocks());

  const SID = "22222222-2222-2222-2222-222222222222";
  const LIST = "/api/tenko/sessions";

  async function tokenFor(role: string, claims: Record<string, unknown> = {}): Promise<string> {
    return signTestJwt(
      { sub: "alarm:deadbeefdeadbeef", tenant_id: TENANT, role, ...claims },
      TEST_JWT_SECRET,
    );
  }

  const managerToken = (claims: Record<string, unknown> = {}) => tokenFor(DEVICE_ROLE_TENKO_MANAGER, claims);

  function okFetch() {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    return fetchMock;
  }

  it("dev_device: true の運行管理者の鍵: GET /api/tenko/sessions は通り、X-Device-Dev: 1 と role が付く", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceDataProxy(
      req(`/device-data-proxy${LIST}`, { method: "GET", token: await managerToken({ dev_device: true }) }),
      env(),
    );
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]![0])).toBe(`https://alc-api.test.example${LIST}`);
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["X-Device-Dev"]).toBe("1");
    expect(h["X-Device-Role"]).toBe(DEVICE_ROLE_TENKO_MANAGER);
    expect(h["X-Tenant-ID"]).toBe(TENANT);
  });

  it("dev_device: true の運行管理者の鍵: query 付きでも通り、query はそのまま転送される", async () => {
    const fetchMock = okFetch();
    const query = "?tenko_method=it&judgment_pending=true";
    const res = await handleDeviceDataProxy(
      req(`/device-data-proxy${LIST}${query}`, { method: "GET", token: await managerToken({ dev_device: true }) }),
      env(),
    );
    expect(res.status).toBe(200);
    expect(String(fetchMock.mock.calls[0]![0])).toBe(`https://alc-api.test.example${LIST}${query}`);
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["X-Device-Dev"]).toBe("1");
    expect(h["X-Device-Role"]).toBe(DEVICE_ROLE_TENKO_MANAGER);
  });

  it("dev_device なしの運行管理者の鍵: GET /api/tenko/sessions は通る (query 付きでも)。X-Device-Dev は付かず、role と tenant が付く", async () => {
    const fetchMock = okFetch();
    for (const path of [LIST, `${LIST}?tenko_method=it&judgment_pending=true`]) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method: "GET", token: await managerToken() }),
        env(),
      );
      expect(res.status, path).toBe(200);
    }
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(String(fetchMock.mock.calls[1]![0])).toBe(
      `https://alc-api.test.example${LIST}?tenko_method=it&judgment_pending=true`,
    );
    for (const call of fetchMock.mock.calls) {
      const h = (call[1] as RequestInit).headers as Record<string, string>;
      expect(h).not.toHaveProperty("X-Device-Dev");
      expect(h["X-Device-Role"]).toBe(DEVICE_ROLE_TENKO_MANAGER);
      expect(h["X-Tenant-ID"]).toBe(TENANT);
    }
  });

  it("dev_device が true 以外 (false / \"true\" / \"1\" / 1 / null) の運行管理者の鍵: 一覧は通るが X-Device-Dev は付かない", async () => {
    const fetchMock = okFetch();
    for (const dev of [false, "true", "1", 1, null]) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${LIST}`, { method: "GET", token: await managerToken({ dev_device: dev }) }),
        env(),
      );
      expect(res.status, JSON.stringify(dev)).toBe(200);
    }
    expect(fetchMock).toHaveBeenCalledTimes(5);
    for (const call of fetchMock.mock.calls) {
      const h = (call[1] as RequestInit).headers as Record<string, string>;
      expect(h).not.toHaveProperty("X-Device-Dev");
    }
  });

  it("★ 開発用でない運行管理者の鍵に増えた口は一覧の GET だけ (start / PUT / POST / 末尾スラッシュ / 記録簿は 403)", async () => {
    const fetchMock = okFetch();
    const cases: ReadonlyArray<{ method: string; path: string }> = [
      { method: "POST", path: LIST },
      { method: "PUT", path: LIST },
      { method: "DELETE", path: LIST },
      { method: "GET", path: `${LIST}/` },
      { method: "GET", path: `${LIST}/start` },
      { method: "POST", path: `${LIST}/start` },
      { method: "PUT", path: `${LIST}/${SID}/alcohol` },
      { method: "PUT", path: `${LIST}/${SID}/report` },
      { method: "POST", path: `${LIST}/${SID}/cancel` },
      { method: "POST", path: `${LIST}/${SID}/interrupt` },
      { method: "POST", path: "/api/tenko/dashboard" },
      { method: "GET", path: "/api/tenko/records" },
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

  it("★ 開発用でないキオスクの鍵に、開発用の記録の口 (/api/tenko/records…) は 403 のまま", async () => {
    const fetchMock = okFetch();
    for (const path of ["/api/tenko/records", "/api/tenko/records/csv", `/api/tenko/records/${SID}`]) {
      for (const claims of [{}, { dev_device: false }, { dev_device: "1" }]) {
        const res = await handleDeviceDataProxy(
          req(`/device-data-proxy${path}`, { method: "GET", token: await tokenFor(DEVICE_ROLE_KIOSK, claims) }),
          env(),
        );
        expect(res.status, `${path} ${JSON.stringify(claims)}`).toBe(403);
      }
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("dev_device: true の運行管理者の鍵でも、表に無い口は 403 (開くのは一覧の GET だけ)", async () => {
    const fetchMock = okFetch();
    const cases: ReadonlyArray<{ method: string; path: string }> = [
      { method: "POST", path: LIST },
      { method: "PUT", path: LIST },
      { method: "DELETE", path: LIST },
      { method: "GET", path: `${LIST}/start` },
      { method: "POST", path: `${LIST}/start` },
      { method: "GET", path: `${LIST}/` },
      { method: "GET", path: `${LIST}/${SID}/extra` },
      { method: "POST", path: "/api/tenko/dashboard" },
      { method: "GET", path: "/api/employees/face-data" },
      { method: "GET", path: `/api/devices/settings/${SID}` },
    ];
    for (const { method, path } of cases) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method, token: await managerToken({ dev_device: true }) }),
        env(),
      );
      expect(res.status, `${method} ${path}`).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("既存の運行管理者の口は dev_device の有無に関わらず従来どおり通る", async () => {
    const fetchMock = okFetch();
    for (const claims of [{}, { dev_device: true }]) {
      for (const path of ["/api/tenko/schedules", `${LIST}/${SID}`]) {
        const res = await handleDeviceDataProxy(
          req(`/device-data-proxy${path}`, { method: "GET", token: await managerToken(claims) }),
          env(),
        );
        expect(res.status, path).toBe(200);
      }
    }
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it("dev のキオスクの鍵の挙動は変わらない (記録簿 GET は通る、一覧は KIOSK_ROUTES で dev に関わらず通る)", async () => {
    const fetchMock = okFetch();
    const records = await handleDeviceDataProxy(
      req("/device-data-proxy/api/tenko/records", {
        method: "GET",
        token: await tokenFor(DEVICE_ROLE_KIOSK, { dev_device: true }),
      }),
      env(),
    );
    expect(records.status).toBe(200);
    for (const claims of [{}, { dev_device: true }]) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${LIST}`, { method: "GET", token: await tokenFor(DEVICE_ROLE_KIOSK, claims) }),
        env(),
      );
      expect(res.status).toBe(200);
    }
    expect(fetchMock).toHaveBeenCalledTimes(3);
    // dev でないキオスクには記録簿を開かないまま。
    const closed = await handleDeviceDataProxy(
      req("/device-data-proxy/api/tenko/records", { method: "GET", token: await tokenFor(DEVICE_ROLE_KIOSK) }),
      env(),
    );
    expect(closed.status).toBe(403);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("dev_device: true でも、追加の表を持たない role (測定台 / dtako ingest) には一覧も記録簿も開かない", async () => {
    const fetchMock = okFetch();
    for (const role of [DEVICE_ROLE_BP_STATION, DEVICE_ROLE_DTAKO_INGEST]) {
      for (const path of [LIST, "/api/tenko/records"]) {
        const res = await handleDeviceDataProxy(
          req(`/device-data-proxy${path}`, { method: "GET", token: await tokenFor(role, { dev_device: true }) }),
          env(),
        );
        expect(res.status, `${role} ${path}`).toBe(403);
      }
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("運行管理者の鍵のカード照会 POST /api/timecard/cards/lookup (Refs ippoan/alc-app#387)", () => {
  beforeEach(() => vi.restoreAllMocks());

  const CID = "33333333-3333-3333-3333-333333333333";
  const LOOKUP = "/api/timecard/cards/lookup";
  const BODY = JSON.stringify({ card_id: "0123456789abcdef" });

  async function tokenFor(role: string, claims: Record<string, unknown> = {}): Promise<string> {
    return signTestJwt(
      { sub: "alarm:deadbeefdeadbeef", tenant_id: TENANT, role, ...claims },
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

  function post(path: string, token: string): Request {
    return req(`/device-data-proxy${path}`, {
      method: "POST",
      token,
      headers: { "content-type": "application/json" },
      body: BODY,
    });
  }

  it("開発用でない運行管理者の鍵: 転送される (body・role・tenant が付き、X-Device-Dev は付かない)", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceDataProxy(post(LOOKUP, await tokenFor(DEVICE_ROLE_TENKO_MANAGER)), env());
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe(`https://alc-api.test.example${LOOKUP}`);
    expect((init as RequestInit).method).toBe("POST");
    expect(await new Response((init as RequestInit).body).text()).toBe(BODY);
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBe(TENANT);
    expect(h["X-Device-Role"]).toBe(DEVICE_ROLE_TENKO_MANAGER);
    expect(h["Content-Type"]).toBe("application/json");
    expect(h).not.toHaveProperty("X-Device-Dev");
  });

  it("開発用の運行管理者の鍵 (dev_device: true): 転送され、X-Device-Dev: 1 が付く", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceDataProxy(
      post(LOOKUP, await tokenFor(DEVICE_ROLE_TENKO_MANAGER, { dev_device: true })),
      env(),
    );
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]![0])).toBe(`https://alc-api.test.example${LOOKUP}`);
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["X-Device-Dev"]).toBe("1");
    expect(h["X-Device-Role"]).toBe(DEVICE_ROLE_TENKO_MANAGER);
    expect(h["X-Tenant-ID"]).toBe(TENANT);
  });

  it("★ キオスクの鍵には開く: backend へ中継される (開発用でも。body・role・tenant が付く)", async () => {
    const fetchMock = okFetch();
    for (const claims of [{}, { dev_device: true }]) {
      fetchMock.mockClear();
      const res = await handleDeviceDataProxy(post(LOOKUP, await tokenFor(DEVICE_ROLE_KIOSK, claims)), env());
      expect(res.status, JSON.stringify(claims)).toBe(200);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, init] = fetchMock.mock.calls[0]!;
      expect(String(url)).toBe(`https://alc-api.test.example${LOOKUP}`);
      expect((init as RequestInit).method).toBe("POST");
      expect(await new Response((init as RequestInit).body).text()).toBe(BODY);
      const h = (init as RequestInit).headers as Record<string, string>;
      expect(h["X-Tenant-ID"]).toBe(TENANT);
      expect(h["X-Device-Role"]).toBe(DEVICE_ROLE_KIOSK);
    }
  });

  it("★ キオスクの鍵: 要求の X-Tenant-ID を信じず、JWT の claim の tenant が backend へ渡る", async () => {
    const fetchMock = okFetch();
    const res = await handleDeviceDataProxy(
      req(`/device-data-proxy${LOOKUP}`, {
        method: "POST",
        token: await tokenFor(DEVICE_ROLE_KIOSK),
        headers: { "content-type": "application/json", "X-Tenant-ID": "99999999-9999-9999-9999-999999999999" },
        body: BODY,
      }),
      env(),
    );
    expect(res.status).toBe(200);
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBe(TENANT);
  });

  it("★ キオスクの鍵でも、lookup の別 method (GET・PUT)・末尾スラッシュ・余分な segment は 403", async () => {
    const fetchMock = okFetch();
    const cases: ReadonlyArray<{ method: string; path: string }> = [
      { method: "GET", path: LOOKUP },
      { method: "PUT", path: LOOKUP },
      { method: "POST", path: `${LOOKUP}/` },
      { method: "POST", path: `${LOOKUP}/${CID}` },
      { method: "POST", path: `/x${LOOKUP}` },
    ];
    for (const { method, path } of cases) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method, token: await tokenFor(DEVICE_ROLE_KIOSK) }),
        env(),
      );
      expect(res.status, `${method} ${path}`).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("★ 測定台の鍵には開かない (開発用でも 403 のまま)", async () => {
    const fetchMock = okFetch();
    for (const claims of [{}, { dev_device: true }]) {
      const res = await handleDeviceDataProxy(post(LOOKUP, await tokenFor(DEVICE_ROLE_BP_STATION, claims)), env());
      expect(res.status, JSON.stringify(claims)).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("★ カードの書き込み・打刻の書き込み・employees/lookup・lookup の GET/PUT/DELETE・末尾スラッシュは 403 のまま (台帳と打刻の GET は読み取り専用の画面の口)", async () => {
    const fetchMock = okFetch();
    const cases: ReadonlyArray<{ method: string; path: string }> = [
      { method: "POST", path: "/api/timecard/cards" },
      { method: "POST", path: "/api/timecard/cards/bulk" },
      { method: "GET", path: `/api/timecard/cards/${CID}` },
      { method: "DELETE", path: `/api/timecard/cards/${CID}` },
      { method: "POST", path: "/api/timecard/punch" },
      { method: "POST", path: "/api/timecard/punches" },
      { method: "POST", path: "/api/employees/lookup" },
      { method: "GET", path: LOOKUP },
      { method: "PUT", path: LOOKUP },
      { method: "DELETE", path: LOOKUP },
      { method: "POST", path: `${LOOKUP}/` },
      { method: "POST", path: `${LOOKUP}/${CID}` },
      { method: "POST", path: `/x${LOOKUP}` },
    ];
    for (const claims of [{}, { dev_device: true }]) {
      for (const { method, path } of cases) {
        const res = await handleDeviceDataProxy(
          req(`/device-data-proxy${path}`, { method, token: await tokenFor(DEVICE_ROLE_TENKO_MANAGER, claims) }),
          env(),
        );
        expect(res.status, `${method} ${path} ${JSON.stringify(claims)}`).toBe(403);
      }
    }
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
    // 指静脈の登録画面で、社員番号のキーパッドから乗務員を選ぶ (Refs ippoan/alc-app#436)。
    { method: "GET", path: "/api/employees/by-code/1234" },
    { method: "GET", path: "/api/employees/face-data" },
    { method: "POST", path: "/api/measurements/start" },
    { method: "PUT", path: "/api/measurements/m-1" },
    // 点呼の確定 (結果カードの IT点呼 / 終了)。測定台として登録した端末でも同じ画面になる (Refs ippoan/alc-app#436)。
    { method: "POST", path: "/api/measurements/m-1/tenko" },
    // 血圧測定タブの指静脈登録 (Refs ippoan/alc-app#437)。
    { method: "PUT", path: "/api/vein/templates/emp-1" },
    // 指静脈の登録・照合・同期は測定台も端末のモジュールで行う (Refs ippoan/alc-app#436)。
    { method: "PUT", path: "/api/vein/templates/emp-1/module" },
    // ほかの端末で撮った記録の追加 (Refs ippoan/alc-app#558)。
    { method: "PUT", path: "/api/vein/templates/emp-1/module/devices" },
    { method: "GET", path: "/api/vein/module-templates" },
    // 運行管理者の照合による承認 (Refs ippoan/alc-app#436)。
    { method: "GET", path: "/api/vein/module-templates/pending" },
    { method: "POST", path: "/api/vein/templates/emp-1/approve-by-employee" },
    // 照合で当たった乗務員を引く。{id} は UUID の形だけ (下で UUID 以外は 403)。
    { method: "GET", path: "/api/employees/0b6f1c2e-3d4a-4b5c-8d9e-0f1a2b3c4d5e" },
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
      // 社員番号の照会は GET だけ。別 method・下位 path の余りは 403。
      { method: "POST", path: "/api/employees/by-code/1234" },
      { method: "PUT", path: "/api/employees/by-code/1234" },
      { method: "DELETE", path: "/api/employees/by-code/1234" },
      { method: "GET", path: "/api/employees/by-code" },
      { method: "GET", path: "/api/employees/by-code/1234/x" },
      // kiosk が通せる他の口 (測定台には要らない)。
      { method: "GET", path: "/api/employees" },
      { method: "GET", path: "/api/employees/emp-1" },
      { method: "GET", path: "/api/measurements" },
      { method: "POST", path: "/api/measurements" },
      // 点呼の確定は POST だけ。別 method・下位 path の余りは 403。
      { method: "GET", path: "/api/measurements/m-1/tenko" },
      { method: "PUT", path: "/api/measurements/m-1/tenko" },
      { method: "POST", path: "/api/measurements/m-1/tenko/x" },
      { method: "GET", path: "/api/tenko/dashboard" },
      { method: "GET", path: "/api/timecard/punches" },
      // 端末レコードを持たないので settings は呼ばれない口 (表に入れていない)。
      { method: "GET", path: "/api/devices/settings/dev-1" },
      // 乗務員の引き当ては UUID の形だけ。
      { method: "PUT", path: "/api/employees/0b6f1c2e-3d4a-4b5c-8d9e-0f1a2b3c4d5e" },
      { method: "DELETE", path: "/api/employees/0b6f1c2e-3d4a-4b5c-8d9e-0f1a2b3c4d5e" },
      { method: "GET", path: "/api/employees/0b6f1c2e-3d4a-4b5c-8d9e-0f1a2b3c4d5e/face" },
      // 指静脈: 登録 (PUT)・モジュール記録の 2 本以外は kiosk だけに開けた口か、どの端末にも無い口 (削除)。
      { method: "DELETE", path: "/api/vein/templates/emp-1" },
      { method: "GET", path: "/api/vein/templates/emp-1" },
      { method: "PUT", path: "/api/vein/templates" },
      { method: "PUT", path: "/api/vein/templates/emp-1/extra" },
      { method: "GET", path: "/api/vein/templates" },
      { method: "POST", path: "/api/vein/identify" },
      // モジュール記録は PUT / GET の 2 本だけ。別 method・下位 path の余りは 403。
      { method: "GET", path: "/api/vein/templates/emp-1/module" },
      { method: "POST", path: "/api/vein/templates/emp-1/module" },
      { method: "PUT", path: "/api/vein/templates/emp-1/module/extra" },
      { method: "POST", path: "/api/vein/templates/emp-1/module/devices" },
      { method: "PUT", path: "/api/vein/templates/emp-1/module/devices/dev-1" },
      { method: "POST", path: "/api/vein/module-templates" },
      { method: "GET", path: "/api/vein/module-templates/emp-1" },
      // 承認: 管理者のログインの口 (pending / approve) は端末に開けない。照合による承認は別 method・余りの path を 403。
      { method: "GET", path: "/api/vein/templates/pending" },
      { method: "POST", path: "/api/vein/templates/emp-1/approve" },
      { method: "POST", path: "/api/vein/module-templates/pending" },
      { method: "GET", path: "/api/vein/templates/emp-1/approve-by-employee" },
      { method: "PUT", path: "/api/vein/templates/emp-1/approve-by-employee" },
      { method: "POST", path: "/api/vein/templates/emp-1/approve-by-employee/extra" },
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

  it("★ 指静脈の承認待ち一覧・承認はどの端末の鍵でも 403 (管理者のログインだけ、Refs ippoan/alc-app#436)", async () => {
    const fetchMock = okFetch();
    const tokens = [
      await bpToken(),
      await kioskToken(),
      await signTestJwt(
        { sub: "device-kiosk-dev", tenant_id: TENANT, role: DEVICE_ROLE_KIOSK, dev_device: true },
        TEST_JWT_SECRET,
      ),
      await signTestJwt(
        { sub: "alarm:cafebabecafebabe", tenant_id: TENANT, role: DEVICE_ROLE_TENKO_MANAGER },
        TEST_JWT_SECRET,
      ),
    ];
    for (const token of tokens) {
      for (const { method, path } of [
        { method: "GET", path: "/api/vein/templates/pending" },
        { method: "POST", path: "/api/vein/templates/emp-1/approve" },
      ]) {
        const res = await handleDeviceDataProxy(
          req(`/device-data-proxy${path}`, {
            method,
            token,
            ...(method !== "GET"
              ? { headers: { "content-type": "application/json" }, body: JSON.stringify({}) }
              : {}),
          }),
          env(),
        );
        expect(res.status, `${method} ${path}`).toBe(403);
      }
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("device-kiosk の許可表は BP_STATION_ROUTES 追加で変わらない (退行検知)", async () => {
    // BP_STATION_ROUTES の各行は KIOSK_ROUTES にも元から含まれる (両 role とも
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

describe("X-Device-Dev / X-Device-Role ヘッダ転送 (Refs ippoan/alc-app#387)", () => {
  beforeEach(() => vi.restoreAllMocks());

  async function kioskToken(claims: Record<string, unknown> = {}): Promise<string> {
    return signTestJwt(
      { sub: "device-kiosk-1", tenant_id: TENANT, role: DEVICE_ROLE_KIOSK, ...claims },
      TEST_JWT_SECRET,
    );
  }

  async function forwardedHeaders(
    token: string,
    headers?: Record<string, string>,
  ): Promise<Record<string, string>> {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    await handleDeviceDataProxy(
      req("/device-data-proxy/api/employees", { method: "GET", token, headers }),
      env(),
    );
    return (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
  }

  it("dev_device claim ありなら X-Device-Dev: 1 と X-Device-Role (token の role) を付けて転送する", async () => {
    const h = await forwardedHeaders(await kioskToken({ dev_device: true }));
    expect(h["X-Device-Dev"]).toBe("1");
    expect(h["X-Device-Role"]).toBe(DEVICE_ROLE_KIOSK);
  });

  it("dev_device claim なしなら X-Device-Dev は付かず、X-Device-Role は付く", async () => {
    const h = await forwardedHeaders(await kioskToken());
    expect(h).not.toHaveProperty("X-Device-Dev");
    expect(h["X-Device-Role"]).toBe(DEVICE_ROLE_KIOSK);
  });

  it("dev_device claim が true 以外 (false / 文字列) なら X-Device-Dev は付かない", async () => {
    expect(await forwardedHeaders(await kioskToken({ dev_device: false }))).not.toHaveProperty("X-Device-Dev");
    expect(await forwardedHeaders(await kioskToken({ dev_device: "1" }))).not.toHaveProperty("X-Device-Dev");
  });

  it("★ client が X-Device-Dev: 1 と X-Device-Role: device-tenko-manager を付けても、claim の無い token なら X-Device-Dev は無く、X-Device-Role は token の role", async () => {
    const h = await forwardedHeaders(await kioskToken(), {
      "X-Device-Dev": "1",
      "X-Device-Role": DEVICE_ROLE_TENKO_MANAGER,
    });
    expect(h).not.toHaveProperty("X-Device-Dev");
    expect(h["X-Device-Role"]).toBe(DEVICE_ROLE_KIOSK);
  });
});

describe("X-Device-Id ヘッダ転送 (token の sub を下流へ渡す, Refs ippoan/alc-app#436)", () => {
  beforeEach(() => vi.restoreAllMocks());

  async function tokenWithSub(sub: unknown): Promise<string> {
    return signTestJwt(
      { ...(sub === undefined ? {} : { sub }), tenant_id: TENANT, role: DEVICE_ROLE_KIOSK },
      TEST_JWT_SECRET,
    );
  }

  // Cloud Run 経路 (GET /api/employees)
  async function cloudRunHeaders(token: string, headers?: Record<string, string>) {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    await handleDeviceDataProxy(
      req("/device-data-proxy/api/employees", { method: "GET", token, headers }),
      env(),
    );
    return (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
  }

  // Service Binding 経路 (PUT /api/vein/templates/{id})
  async function bindingHeaders(token: string, headers?: Record<string, string>) {
    const binding = { fetch: vi.fn(async (): Promise<Response> => new Response("from-binding")) };
    await handleDeviceDataProxy(
      req("/device-data-proxy/api/vein/templates/emp-1", {
        method: "PUT",
        token,
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({}),
      }),
      env({ ALC_VEIN: binding as unknown as Fetcher }),
    );
    expect(binding.fetch).toHaveBeenCalledTimes(1);
    const init = (binding.fetch.mock.calls[0] as unknown as [string, RequestInit])[1];
    return init.headers as Record<string, string>;
  }

  it("検証済み token の sub を X-Device-Id で付ける (Cloud Run / Service Binding)", async () => {
    expect((await cloudRunHeaders(await tokenWithSub("device-kiosk-1")))["X-Device-Id"]).toBe("device-kiosk-1");
    expect((await bindingHeaders(await tokenWithSub("device-kiosk-1")))["X-Device-Id"]).toBe("device-kiosk-1");
  });

  it("鍵で取った端末の sub (alarm:<16 hex>) もそのまま付く", async () => {
    const t = await tokenWithSub("alarm:deadbeefdeadbeef");
    expect((await cloudRunHeaders(t))["X-Device-Id"]).toBe("alarm:deadbeefdeadbeef");
    expect((await bindingHeaders(t))["X-Device-Id"]).toBe("alarm:deadbeefdeadbeef");
  });

  it("★ client が X-Device-Id を送っても claim の値で上書きされる (Cloud Run / Service Binding)", async () => {
    const t = await tokenWithSub("device-kiosk-1");
    const fake = { "X-Device-Id": "device-fake-9" };
    expect((await cloudRunHeaders(t, fake))["X-Device-Id"]).toBe("device-kiosk-1");
    expect((await bindingHeaders(t, fake))["X-Device-Id"]).toBe("device-kiosk-1");
  });

  it("★ sub が無い・空・文字列でないなら付けず、client の値も通さない (Cloud Run / Service Binding)", async () => {
    const fake = { "X-Device-Id": "device-fake-9" };
    for (const sub of [undefined, "", 123]) {
      const t = await tokenWithSub(sub);
      expect(await cloudRunHeaders(t, fake)).not.toHaveProperty("X-Device-Id");
      expect(await bindingHeaders(t, fake)).not.toHaveProperty("X-Device-Id");
    }
  });
});

describe("Service Binding へ振り分ける path の defense-in-depth (isUnsafeBackendPath)", () => {
  beforeEach(() => vi.restoreAllMocks());

  // `%2f` は pathname に残るので KIOSK_ROUTES の `[^/]+` には当たる。binding へ渡す前に 403 で止める。
  it("kiosk の PUT /api/vein/templates/%2e%2e%2fadmin は 403 で、binding にも Cloud Run にも届かない", async () => {
    const cloudRun = vi.fn(async (): Promise<Response> => new Response("ok", { status: 200 }));
    globalThis.fetch = cloudRun as unknown as typeof fetch;
    const binding = { fetch: vi.fn(async (): Promise<Response> => new Response("from-binding")) };
    const token = await signTestJwt(
      { sub: "device-kiosk-1", tenant_id: TENANT, role: DEVICE_ROLE_KIOSK },
      TEST_JWT_SECRET,
    );
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/vein/templates/%2e%2e%2fadmin", { method: "PUT", token }),
      env({ ALC_VEIN: binding as unknown as Fetcher }),
    );
    expect(res.status).toBe(403);
    expect(binding.fetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
  });

  // 測定台にも指静脈の登録を開けた (Refs ippoan/alc-app#437) ので、同じ止め方が効くことを固定する。
  it("bp-station の PUT /api/vein/templates/%2e%2e%2fadmin も 403 で、binding にも Cloud Run にも届かない", async () => {
    const cloudRun = vi.fn(async (): Promise<Response> => new Response("ok", { status: 200 }));
    globalThis.fetch = cloudRun as unknown as typeof fetch;
    const binding = { fetch: vi.fn(async (): Promise<Response> => new Response("from-binding")) };
    const token = await signTestJwt(
      { sub: "alarm:deadbeefdeadbeef", tenant_id: TENANT, role: DEVICE_ROLE_BP_STATION },
      TEST_JWT_SECRET,
    );
    const res = await handleDeviceDataProxy(
      req("/device-data-proxy/api/vein/templates/%2e%2e%2fadmin", { method: "PUT", token }),
      env({ ALC_VEIN: binding as unknown as Fetcher }),
    );
    expect(res.status).toBe(403);
    expect(binding.fetch).not.toHaveBeenCalled();
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("運行管理者席の鍵のカメラ一覧 GET /api/cam-clips/cameras → ALC_CAM_CLIPS (ippoan/alc-cam)", () => {
  beforeEach(() => vi.restoreAllMocks());

  const CAMERAS = "/api/cam-clips/cameras";

  function setupClips() {
    const clips = { fetch: vi.fn(async (): Promise<Response> => new Response("from-clips")) };
    const fetchMock = vi.fn(async (): Promise<Response> => new Response("from-cloud-run"));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    return { clips, fetchMock, env: env({ ALC_CAM_CLIPS: clips as unknown as Fetcher }) };
  }

  const managerToken = (claims: Record<string, unknown> = {}) =>
    signTestJwt(
      { sub: "alarm:deadbeefdeadbeef", tenant_id: TENANT, role: DEVICE_ROLE_TENKO_MANAGER, ...claims },
      TEST_JWT_SECRET,
    );

  it("席の鍵の GET は binding へ。ingest に付くのは X-Tenant-ID / X-Device-Role / X-Device-Id で、X-User-Role は付かない", async () => {
    const { clips, fetchMock, env: e } = setupClips();
    const res = await handleDeviceDataProxy(
      req(`/device-data-proxy${CAMERAS}`, {
        method: "GET",
        token: await managerToken(),
        // client が名乗っても下流には届かない
        headers: { "X-User-Role": "admin", "X-Tenant-ID": "22222222-2222-2222-2222-222222222222" },
      }),
      e,
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("from-clips");
    expect(fetchMock).not.toHaveBeenCalled();
    const [url, init] = clips.fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`https://alc-cam-sd-ingest${CAMERAS}`);
    expect(init.method).toBe("GET");
    expect(init.headers).toEqual({
      "X-Tenant-ID": TENANT,
      "X-Device-Role": DEVICE_ROLE_TENKO_MANAGER,
      "X-Device-Id": "alarm:deadbeefdeadbeef",
    });
  });

  it("開発用の席の鍵なら X-Device-Dev: 1 も付く", async () => {
    const { clips, env: e } = setupClips();
    await handleDeviceDataProxy(
      req(`/device-data-proxy${CAMERAS}`, { method: "GET", token: await managerToken({ dev_device: true }) }),
      e,
    );
    const init = (clips.fetch.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect((init.headers as Record<string, string>)["X-Device-Dev"]).toBe("1");
  });

  it("★ 席の鍵でも GET /cameras 以外の cam-clips の口と、GET 以外の method は 403 (binding にも Cloud Run にも届かない)", async () => {
    const { clips, fetchMock, env: e } = setupClips();
    const cases: ReadonlyArray<{ method: string; path: string }> = [
      { method: "POST", path: CAMERAS },
      { method: "PUT", path: CAMERAS },
      { method: "PATCH", path: CAMERAS },
      { method: "DELETE", path: CAMERAS },
      { method: "GET", path: `${CAMERAS}/` },
      { method: "GET", path: `${CAMERAS}/TS-NS320W-55` },
      { method: "PATCH", path: `${CAMERAS}/TS-NS320W-55` },
      { method: "GET", path: "/api/cam-clips/clips" },
      { method: "POST", path: "/api/cam-clips/clips" },
      { method: "GET", path: "/api/cam-clips/clips/TS-NS320W-55/x.mp4" },
      { method: "GET", path: "/api/cam-clips/device-candidates" },
      { method: "GET", path: "/api/cam-clips/camerasx" },
    ];
    for (const { method, path } of cases) {
      const res = await handleDeviceDataProxy(
        req(`/device-data-proxy${path}`, { method, token: await managerToken() }),
        e,
      );
      expect(res.status, `${method} ${path}`).toBe(403);
    }
    expect(clips.fetch).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("★ 席の鍵以外の device 鍵は GET /cameras も 403", async () => {
    const { clips, fetchMock, env: e } = setupClips();
    for (const role of [
      DEVICE_ROLE,
      DEVICE_ROLE_KIOSK,
      DEVICE_ROLE_BP_STATION,
      DEVICE_ROLE_CAM_HOST,
      DEVICE_ROLE_DTAKO_INGEST,
      DEVICE_ROLE_DTAKO_RELAY,
    ]) {
      for (const claims of [{}, { dev_device: true }]) {
        const token = await signTestJwt({ sub: "device-1", tenant_id: TENANT, role, ...claims }, TEST_JWT_SECRET);
        const res = await handleDeviceDataProxy(req(`/device-data-proxy${CAMERAS}`, { method: "GET", token }), e);
        expect(res.status, `${role} ${JSON.stringify(claims)}`).toBe(403);
      }
    }
    expect(clips.fetch).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("拠点 PC の拡張の鍵の担当カメラ GET /api/cam-clips/cameras/mine → ALC_CAM_CLIPS (device-cam-host)", () => {
  beforeEach(() => vi.restoreAllMocks());

  const MINE = "/api/cam-clips/cameras/mine";

  function setupClips() {
    const clips = { fetch: vi.fn(async (): Promise<Response> => new Response("from-clips")) };
    const fetchMock = vi.fn(async (): Promise<Response> => new Response("from-cloud-run"));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    return { clips, fetchMock, env: env({ ALC_CAM_CLIPS: clips as unknown as Fetcher }) };
  }

  const camHostToken = (claims: Record<string, unknown> = {}) =>
    signTestJwt(
      { sub: "alarm:deadbeefdeadbeef", tenant_id: TENANT, role: DEVICE_ROLE_CAM_HOST, ...claims },
      TEST_JWT_SECRET,
    );

  it("GET /cameras/mine は binding へ。X-Device-Id は sub (= cam_camera_devices の紐づけ ID)", async () => {
    const { clips, fetchMock, env: e } = setupClips();
    const res = await handleDeviceDataProxy(
      req(`/device-data-proxy${MINE}`, {
        method: "GET",
        token: await camHostToken(),
        // client が名乗っても下流には届かない
        headers: { "X-Device-Id": "alarm:0000000000000000", "X-Tenant-ID": "22222222-2222-2222-2222-222222222222" },
      }),
      e,
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("from-clips");
    expect(fetchMock).not.toHaveBeenCalled();
    const [url, init] = clips.fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`https://alc-cam-sd-ingest${MINE}`);
    expect(init.method).toBe("GET");
    expect(init.headers).toEqual({
      "X-Tenant-ID": TENANT,
      "X-Device-Role": DEVICE_ROLE_CAM_HOST,
      "X-Device-Id": "alarm:deadbeefdeadbeef",
    });
  });

  it("★ 拡張の鍵は /cameras/mine の GET 以外すべて 403 (他の cam-clips の口・他 method・点呼の口)", async () => {
    const { clips, fetchMock, env: e } = setupClips();
    const cases: ReadonlyArray<{ method: string; path: string }> = [
      { method: "POST", path: MINE },
      { method: "PUT", path: MINE },
      { method: "PATCH", path: MINE },
      { method: "DELETE", path: MINE },
      { method: "GET", path: `${MINE}/` },
      { method: "GET", path: `${MINE}x` },
      { method: "GET", path: "/api/cam-clips/cameras" },
      { method: "GET", path: "/api/cam-clips/cameras/TS-NS320W-55" },
      { method: "GET", path: "/api/cam-clips/clips" },
      { method: "GET", path: "/api/cam-clips/device-candidates" },
      { method: "GET", path: "/api/employees/face-data" },
      { method: "POST", path: "/api/employees/lookup" },
      { method: "POST", path: "/api/measurements/start" },
      { method: "GET", path: "/api/tenko/schedules" },
    ];
    for (const { method, path } of cases) {
      for (const claims of [{}, { dev_device: true }]) {
        const res = await handleDeviceDataProxy(
          req(`/device-data-proxy${path}`, { method, token: await camHostToken(claims) }),
          e,
        );
        expect(res.status, `${method} ${path} ${JSON.stringify(claims)}`).toBe(403);
      }
    }
    expect(clips.fetch).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("★ 拡張の鍵以外の device 鍵 (kiosk / 運行管理者席 / 測定台 ほか) は /cameras/mine が 403", async () => {
    const { clips, fetchMock, env: e } = setupClips();
    for (const role of [
      DEVICE_ROLE,
      DEVICE_ROLE_KIOSK,
      DEVICE_ROLE_TENKO_MANAGER,
      DEVICE_ROLE_BP_STATION,
      DEVICE_ROLE_DTAKO_INGEST,
      DEVICE_ROLE_DTAKO_RELAY,
    ]) {
      for (const claims of [{}, { dev_device: true }]) {
        const token = await signTestJwt(
          { sub: "alarm:deadbeefdeadbeef", tenant_id: TENANT, role, ...claims },
          TEST_JWT_SECRET,
        );
        const res = await handleDeviceDataProxy(req(`/device-data-proxy${MINE}`, { method: "GET", token }), e);
        expect(res.status, `${role} ${JSON.stringify(claims)}`).toBe(403);
      }
    }
    expect(clips.fetch).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
