import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";
import { DEVICE_ROLE_DTAKO_INGEST, DEVICE_ROLE_DTAKO_RELAY } from "../../src/lib/device";

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
        token: await deviceToken({ role: "device-uploader" }),
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
