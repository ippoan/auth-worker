import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";
import { DEVICE_ROLE_CAM_FLICKR } from "../../src/lib/device";

// OIDC mint は別ユニットでテスト済み。ここでは handler の flow
// (device JWT 検証 → role/path allowlist → OIDC mint → forward) を固定する。
vi.mock("../../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async () => "fake-oidc-token"),
}));

import { handleOhishiLogiProxy } from "../../src/handlers/ohishi-logi-proxy";

const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

function env(overrides: Record<string, unknown> = {}) {
  return createMockEnv({
    OHISHI_LOGI_ORIGIN: "https://ohishi-logi.test.example",
    OHISHI_LOGI_PROXY_SA_KEY: "{}", // resolveSecret が非空を返せばよい (oidc は mock)
    ...overrides,
  });
}

async function deviceToken(claims: Record<string, unknown> = {}): Promise<string> {
  return signTestJwt(
    { sub: "device-1", tenant_id: "irrelevant", role: DEVICE_ROLE_CAM_FLICKR, ...claims },
    TEST_JWT_SECRET,
  );
}

function req(path: string, init: RequestInit & { token?: string | null } = {}): Request {
  const headers: Record<string, string> = { ...(init.headers as Record<string, string>) };
  if (init.token !== null && init.token !== undefined) headers["Authorization"] = `Bearer ${init.token}`;
  return new Request(`https://auth.ippoan.org${path}`, {
    method: init.method ?? "GET",
    headers,
    body: init.body,
  });
}

describe("handleOhishiLogiProxy (ohishi-exp/ohishi-logi#1, cf-flickr-cam-worker#1)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("Authorization ヘッダー欠落は 401", async () => {
    const res = await handleOhishiLogiProxy(req("/ohishi-logi-proxy/cam/dates"), env());
    expect(res.status).toBe(401);
  });

  it("不正な device JWT は 401", async () => {
    const res = await handleOhishiLogiProxy(
      req("/ohishi-logi-proxy/cam/dates", { token: "garbage" }),
      env(),
    );
    expect(res.status).toBe(401);
  });

  it("JWT_SECRET 未 bind は 503", async () => {
    const res = await handleOhishiLogiProxy(
      req("/ohishi-logi-proxy/cam/dates", { token: await deviceToken() }),
      env({ JWT_SECRET: undefined }),
    );
    expect(res.status).toBe(503);
  });

  it("OHISHI_LOGI_PROXY_SA_KEY 未設定は 503", async () => {
    const res = await handleOhishiLogiProxy(
      req("/ohishi-logi-proxy/cam/dates", { token: await deviceToken() }),
      env({ OHISHI_LOGI_PROXY_SA_KEY: undefined }),
    );
    expect(res.status).toBe(503);
  });

  it("OHISHI_LOGI_ORIGIN 未設定は 503", async () => {
    const res = await handleOhishiLogiProxy(
      req("/ohishi-logi-proxy/cam/dates", { token: await deviceToken() }),
      env({ OHISHI_LOGI_ORIGIN: undefined }),
    );
    expect(res.status).toBe(503);
  });

  it("role クレーム欠落は 401", async () => {
    const res = await handleOhishiLogiProxy(
      req("/ohishi-logi-proxy/cam/dates", { token: await deviceToken({ role: undefined }) }),
      env(),
    );
    expect(res.status).toBe(401);
  });

  it("device-cam-flickr 以外の role は 403", async () => {
    const res = await handleOhishiLogiProxy(
      req("/ohishi-logi-proxy/cam/dates", { token: await deviceToken({ role: "device-uploader" }) }),
      env(),
    );
    expect(res.status).toBe(403);
  });

  it("role は正しいが /cam/ 配下でない path は 403 (盗難時の blast radius 限定)", async () => {
    const res = await handleOhishiLogiProxy(
      req("/ohishi-logi-proxy/admin/secret", { token: await deviceToken() }),
      env(),
    );
    expect(res.status).toBe(403);
  });

  it("正常: OIDC Bearer を付けて /cam/dates を forward する (X-Tenant-ID は注入しない)", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response(JSON.stringify({ dates: ["20260101"] }), { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleOhishiLogiProxy(
      req("/ohishi-logi-proxy/cam/dates", { token: await deviceToken() }),
      env(),
    );
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://ohishi-logi.test.example/cam/dates");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
    expect(h["X-Tenant-ID"]).toBeUndefined();
  });

  it("動的セグメントを含む path (日付/時間/ファイル名) も forward できる", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response(new Uint8Array([1, 2, 3]), {
          status: 200,
          headers: { "content-type": "application/octet-stream" },
        }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleOhishiLogiProxy(
      req("/ohishi-logi-proxy/cam/dates/20260101/hours/120000/files/a.jpg", {
        token: await deviceToken(),
      }),
      env(),
    );
    expect(res.status).toBe(200);
    const [url] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe(
      "https://ohishi-logi.test.example/cam/dates/20260101/hours/120000/files/a.jpg",
    );
  });

  it("OIDC mint 失敗は 502 (詳細は出さない)", async () => {
    const { mintGoogleIdToken } = await import("../../src/lib/oidc");
    (mintGoogleIdToken as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("boom"),
    );
    const res = await handleOhishiLogiProxy(
      req("/ohishi-logi-proxy/cam/dates", { token: await deviceToken() }),
      env(),
    );
    expect(res.status).toBe(502);
  });
});
