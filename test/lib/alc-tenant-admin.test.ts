/**
 * `lib/alc-tenant-admin.ts` — 会社の管理の API が使う認可 (`requireCaller`) と alc-auth-worker の呼び出し
 * (`callTenantAdmin`) (Refs ippoan/rust-alc-api#680)。
 */
import { describe, it, expect } from "vitest";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { makeJwt, TEST_TENANT_ID, TEST_USER_ID } from "../helpers/live-env";
import { createFakeAlcAuth, FAKE_ALC_AUTH_SECRET } from "../helpers/fake-alc-auth";
import {
  callTenantAdmin,
  errorResponse,
  extractToken,
  requireCaller,
  tenantPath,
} from "../../src/lib/alc-tenant-admin";
import type { Env } from "../../src/index";

function req(token: string | null): Request {
  return new Request("https://auth.test.example/api/x", {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function envWith(respond: (req: Request) => Response): { env: Env; calls: { method: string; url: string; body: string }[] } {
  const alcAuth = createFakeAlcAuth({ override: respond });
  return {
    calls: alcAuth.calls,
    env: createMockEnv({ ALC_AUTH: alcAuth.fetcher, INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET }),
  };
}

describe("requireCaller", () => {
  const admin = { admin: true, write: false };

  it("検証済みの JWT の tenant と sub を返す", async () => {
    const r = await requireCaller(req(makeJwt(TEST_JWT_SECRET)), createMockEnv(), admin);
    expect(r).toEqual({ tenantId: TEST_TENANT_ID, userId: TEST_USER_ID });
  });

  it("token 無し・Bearer でない・署名不正・JWT_SECRET 無し・tenant / sub 無しは 401", async () => {
    const env = createMockEnv();
    const cases: [Request, Env][] = [
      [req(null), env],
      [new Request("https://auth.test.example/", { headers: { Authorization: "Basic x" } }), env],
      [req(makeJwt("wrong-secret")), env],
      [req(makeJwt(TEST_JWT_SECRET)), createMockEnv({ JWT_SECRET: undefined })],
      [req(makeJwt(TEST_JWT_SECRET, { tenant_id: "" })), env],
      [req(makeJwt(TEST_JWT_SECRET, { tenant_id: 1 })), env],
      [req(makeJwt(TEST_JWT_SECRET, { sub: "" })), env],
      [req(makeJwt(TEST_JWT_SECRET, { sub: 1 })), env],
    ];
    for (const [r, e] of cases) {
      const got = await requireCaller(r, e, admin);
      expect(got).toBeInstanceOf(Response);
      expect((got as Response).status).toBe(401);
    }
  });

  it("admin が要るのに admin でなければ 403、要らなければ通す", async () => {
    const t = makeJwt(TEST_JWT_SECRET, { role: "viewer" });
    const got = await requireCaller(req(t), createMockEnv(), admin);
    expect((got as Response).status).toBe(403);
    expect(await requireCaller(req(t), createMockEnv(), { admin: false, write: true })).toEqual({
      tenantId: TEST_TENANT_ID,
      userId: TEST_USER_ID,
    });
  });

  it("書き込みは開発用・端末の token なら 403、読み取りは通す", async () => {
    for (const kind of ["dev", "device-key"]) {
      const t = makeJwt(TEST_JWT_SECRET, { token_kind: kind });
      const got = await requireCaller(req(t), createMockEnv(), { admin: true, write: true });
      expect((got as Response).status).toBe(403);
      expect(await requireCaller(req(t), createMockEnv(), admin)).not.toBeInstanceOf(Response);
    }
  });
});

describe("extractToken・tenantPath", () => {
  it("Bearer の値だけを取る", () => {
    expect(extractToken(req("abc"))).toBe("abc");
    expect(extractToken(req(null))).toBeNull();
  });

  it("各段を URL エンコードする", () => {
    expect(tenantPath("t1", "users", "a/b")).toBe("/internal/tenants/t1/users/a%2Fb");
    expect(tenantPath("t 1")).toBe("/internal/tenants/t%201");
  });
});

describe("callTenantAdmin", () => {
  it("共有 secret 付きで叩き、JSON の本文を返す (body は JSON にして送る)", async () => {
    const { env, calls } = envWith(() => json(200, { ok: 1 }));
    const r = await callTenantAdmin(env, "/internal/x", { method: "PUT", body: { a: 1 } });
    expect(r).toEqual({ status: 200, body: { ok: 1 } });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.method).toBe("PUT");
    expect(JSON.parse(calls[0]!.body)).toEqual({ a: 1 });
  });

  it("method の既定は GET で body を送らない", async () => {
    const { env, calls } = envWith(() => json(200, []));
    await callTenantAdmin(env, "/internal/x");
    expect(calls[0]!.method).toBe("GET");
    expect(calls[0]!.body).toBe("");
  });

  it("204 は本文 null、{error} 付きの 4xx はそのまま", async () => {
    expect(await callTenantAdmin(envWith(() => new Response(null, { status: 204 })).env, "/x")).toEqual({
      status: 204,
      body: null,
    });
    expect(await callTenantAdmin(envWith(() => json(409, { error: "email_taken" })).env, "/x")).toEqual({
      status: 409,
      body: { error: "email_taken" },
    });
  });

  it("binding / secret 無し・例外・5xx・本文の空の 404 (secret 不一致)・JSON でない本文は 502", async () => {
    const upstream = { status: 502, body: { error: "upstream_error" } };
    expect(await callTenantAdmin(createMockEnv({ ALC_AUTH: undefined }), "/x")).toEqual(upstream);
    const throwing = createMockEnv({
      ALC_AUTH: { fetch: async () => { throw new Error("boom"); } } as unknown as Fetcher,
      INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET,
    });
    expect(await callTenantAdmin(throwing, "/x")).toEqual(upstream);
    for (const res of [
      json(500, { error: "internal_error" }),
      new Response(null, { status: 404 }),
      new Response("not json", { status: 200 }),
    ]) {
      expect(await callTenantAdmin(envWith(() => res).env, "/x")).toEqual(upstream);
    }
  });

  it("errorResponse は状態と本文をそのまま返す", async () => {
    const res = errorResponse({ status: 404, body: { error: "x" } });
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "x" });
  });
});
