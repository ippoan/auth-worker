import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

// OIDC mint は別ユニットでテスト済み。ここでは handler の flow
// (consumer proof → path allowlist → tenant 必須 → OIDC mint → forward) を固定する。
vi.mock("../../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async () => "fake-oidc-token"),
}));

// internal-jwt class (schedule fire) は internalAuthToken (aud=alc-api-internal) を
// 使う。mint 実体は lib/alc-internal 側でテスト済みなのでここでは mock で固定する。
vi.mock("../../src/lib/alc-internal", () => ({
  internalAuthToken: vi.fn(async () => "fake-internal-jwt"),
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
      "/alc-internal-proxy/api/hub/other", // hub prefix でも列挙外は拒否 (#363)
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

  it("正常 (POST /api/hub/measurements): shared-secret クラスとして X-Tenant-ID 付きで forward (#363)", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/hub/measurements", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify([{ device_id: "dev-1", kind: "alcohol", seq: 1, payload: {} }]),
      }),
      env(),
    );
    expect(res.status).toBe(200);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/hub/measurements");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
    expect(h["X-Internal-Shared-Secret"]).toBe(PROXY_SECRET);
    expect(h["X-Tenant-ID"]).toBe(TENANT);
    expect((init as RequestInit).method).toBe("POST");
  });

  it("POST /api/hub/measurements は X-Tenant-ID 欠落で 400 (shared-secret クラスの必須ヘッダー)", async () => {
    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/hub/measurements", { method: "POST", tenant: null }),
      env(),
    );
    expect(res.status).toBe(400);
  });

  it("正常 (POST /api/upload): multipart body も raw のまま forward (dtako-scraper#22)", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response('{"upload_id":"x"}', { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const boundary = "----test";
    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/upload", {
        method: "POST",
        headers: { "content-type": `multipart/form-data; boundary=${boundary}` },
        body: `--${boundary}\r\ncontent\r\n--${boundary}--\r\n`,
      }),
      env(),
    );
    expect(res.status).toBe(200);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/upload");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["X-Internal-Shared-Secret"]).toBe(PROXY_SECRET);
    expect(h["X-Tenant-ID"]).toBe(TENANT);
    expect(h["Content-Type"]).toBe(`multipart/form-data; boundary=${boundary}`);
  });

  it("正常 (GET /api/internal/operations): dtako 実運行一覧を query 付きで forward (nuxt-ichibanboshi 突合用、ohishi-exp/nuxt-dtako-admin#198 Phase 8)", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response('{"operations":[]}', { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/internal/operations?vehicle_cd=0272&date_from=2026-06-01", {
        method: "GET",
      }),
      env(),
    );
    expect(res.status).toBe(200);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe(
      "https://alc-api.test.example/api/internal/operations?vehicle_cd=0272&date_from=2026-06-01",
    );
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
    expect(h["X-Internal-Shared-Secret"]).toBe(PROXY_SECRET);
    expect(h["X-Tenant-ID"]).toBe(TENANT);
    expect((init as RequestInit).method).toBe("GET");
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

  it("public-ingest (fcm-dismiss-test) も X-Tenant-ID を strip する", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/devices/fcm-dismiss-test", { method: "POST" }),
      env(),
    );
    expect(res.status).toBe(200);
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
    expect(h["X-Tenant-ID"]).toBeUndefined();
  });

  it("public-ingest (re-pair): 端末の再認証を forward し X-Tenant-ID を strip する (Refs rust-alc-api#495)", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/devices/re-pair", { method: "POST" }),
      env(),
    );
    expect(res.status).toBe(200);
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
    expect(h["X-Tenant-ID"]).toBeUndefined();
  });

  it("internal-secret (trigger-update-dev): caller の X-Internal-Secret を pass-through、tenant/base-secret は載せない", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/devices/trigger-update-dev", {
        method: "POST",
        headers: { "X-Internal-Secret": "fcm-secret-xyz" },
      }),
      env(),
    );
    expect(res.status).toBe(200);
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
    expect(h["X-Internal-Secret"]).toBe("fcm-secret-xyz");
    expect(h["X-Tenant-ID"]).toBeUndefined();
    expect(h["X-Internal-Shared-Secret"]).toBeUndefined();
  });

  it("internal-jwt (schedule fire): aud=alc-api-internal の Bearer で forward、tenant/secret は載せない (ippoan/auth-worker#359)", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleAlcInternalProxy(
      req(
        "/alc-internal-proxy/api/internal/trouble/schedules/61cf27f0-b192-4ca4-a608-1cc1b24f45c3/fire",
        { method: "POST" },
      ),
      env(),
    );
    expect(res.status).toBe(200);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe(
      "https://alc-api.test.example/api/internal/trouble/schedules/61cf27f0-b192-4ca4-a608-1cc1b24f45c3/fire",
    );
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-internal-jwt");
    expect(h["X-Tenant-ID"]).toBeUndefined();
    expect(h["X-Internal-Shared-Secret"]).toBeUndefined();
  });

  it("internal-jwt (LINE WORKS 送信): aud=alc-api-internal の Bearer で forward、tenant/secret は載せない (Refs ohishi-exp/nuxt-dtako-admin#874)", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleAlcInternalProxy(
      req("/alc-internal-proxy/api/internal/lineworks/send", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ channel_id: TENANT, text: "予約番号: J5JZPEQJ" }),
      }),
      env(),
    );
    expect(res.status).toBe(200);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/internal/lineworks/send");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-internal-jwt");
    // tenant は rust 側が channel id 引きで解決する。詐称材料を渡さない。
    expect(h["X-Tenant-ID"]).toBeUndefined();
    expect(h["X-Internal-Shared-Secret"]).toBeUndefined();
  });

  it("internal-jwt: LINE WORKS 送信も POST 以外は 403", async () => {
    for (const method of ["GET", "DELETE", "PUT"]) {
      const res = await handleAlcInternalProxy(
        req("/alc-internal-proxy/api/internal/lineworks/send", { method }),
        env(),
      );
      expect(res.status, method).toBe(403);
    }
  });

  it("LINE WORKS の tenant 経路 (require_tenant_header) は allowlist に載せない — 403 のまま (#434 再現防止)", async () => {
    for (const p of [
      // test-send は名前に反して {text} を渡すだけの汎用テキスト送信で、
      // /api/internal/lineworks/send と機能はほぼ同じ。だが rust 側は
      // require_tenant_header (data 経路) で守っており、proxy が forward すると
      // consumer が X-Alc-Proxy-Secret を持つだけで任意の X-Tenant-ID を名乗れて
      // しまう = rust-alc-api#434 の脆弱性の再現になる。**似ているからという理由で
      // ここを allowlist に足さないこと** (browser JWT 経路 = /alc-proxy 専用)。
      "/alc-internal-proxy/api/notify/lineworks/channels/61cf27f0-b192-4ca4-a608-1cc1b24f45c3/test-send",
      "/alc-internal-proxy/api/notify/lineworks/channels",
      // 近いが別物のパス (prefix/suffix ずらし) も落ちること。
      "/alc-internal-proxy/api/internal/lineworks/send/x",
      "/alc-internal-proxy/api/internal/lineworks",
      "/alc-internal-proxy/api/lineworks/send",
    ]) {
      const res = await handleAlcInternalProxy(req(p, { method: "POST" }), env());
      expect(res.status, p).toBe(403);
    }
  });

  it("internal-jwt: UUID 形式不正の fire path は 403", async () => {
    for (const p of [
      "/alc-internal-proxy/api/internal/trouble/schedules/not-a-uuid/fire",
      "/alc-internal-proxy/api/internal/trouble/schedules/61cf27f0-b192-4ca4-a608-1cc1b24f45c3/../fire",
      "/alc-internal-proxy/api/internal/trouble/schedules/61cf27f0-b192-4ca4-a608-1cc1b24f45c3/fire/x",
      "/alc-internal-proxy/api/internal/auth/sso-config",
    ]) {
      const res = await handleAlcInternalProxy(req(p, { method: "POST" }), env());
      expect(res.status, p).toBe(403);
    }
  });

  it("internal-jwt: POST 以外は 403", async () => {
    for (const method of ["GET", "DELETE", "PUT"]) {
      const res = await handleAlcInternalProxy(
        req(
          "/alc-internal-proxy/api/internal/trouble/schedules/61cf27f0-b192-4ca4-a608-1cc1b24f45c3/fire",
          { method },
        ),
        env(),
      );
      expect(res.status, method).toBe(403);
    }
  });

  it("internal-jwt も consumer proof は必須 (X-Alc-Proxy-Secret 欠落は 401)", async () => {
    const res = await handleAlcInternalProxy(
      req(
        "/alc-internal-proxy/api/internal/trouble/schedules/61cf27f0-b192-4ca4-a608-1cc1b24f45c3/fire",
        { method: "POST", proxySecret: null },
      ),
      env(),
    );
    expect(res.status).toBe(401);
  });

  it("internal-jwt: internalAuthToken 失敗は 502 (詳細は出さない)", async () => {
    const { internalAuthToken } = await import("../../src/lib/alc-internal");
    (internalAuthToken as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("boom"),
    );
    const res = await handleAlcInternalProxy(
      req(
        "/alc-internal-proxy/api/internal/trouble/schedules/61cf27f0-b192-4ca4-a608-1cc1b24f45c3/fire",
        { method: "POST" },
      ),
      env(),
    );
    expect(res.status).toBe(502);
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
