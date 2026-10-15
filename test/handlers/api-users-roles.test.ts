/**
 * `/api/users/roles` (GET 一覧 / POST 付け外し) と `lib/alc-internal.ts` の `listUserRoles` /
 * `setUserRole` (Refs ohishi-exp/rust-leave-worker#1)。ロールの持ち主は alc-auth-worker (`ALC_AUTH`)。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { makeJwt } from "../helpers/live-env";
import { createFakeAlcAuth, FAKE_ALC_AUTH_SECRET, type FakeAlcAuth } from "../helpers/fake-alc-auth";
import { handleUserRolesList, handleUserRoleSet } from "../../src/handlers/api-users";
import { listUserRoles, setUserRole } from "../../src/lib/alc-internal";
import type { Env } from "../../src/index";

const TENANT = "11111111-1111-1111-1111-111111111111"; // makeJwt の既定 tenant_id
const USER_ID = "33333333-3333-3333-3333-333333333333";

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

/** 応答を `respond` で決める fake の ALC_AUTH と、それを持つ env。 */
function withAlcAuth(respond: (req: Request) => Response): { env: Env; alcAuth: FakeAlcAuth } {
  const alcAuth = createFakeAlcAuth({ override: respond });
  return {
    alcAuth,
    env: createMockEnv({ ALC_AUTH: alcAuth.fetcher, INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET }),
  };
}

function get(token: string | null = makeJwt(TEST_JWT_SECRET)): Request {
  return new Request("https://auth.test.example/api/users/roles", {
    method: "GET",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
}

function post(body: unknown, token: string | null = makeJwt(TEST_JWT_SECRET)): Request {
  return new Request("https://auth.test.example/api/users/roles", {
    method: "POST",
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), "Content-Type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

beforeEach(() => {
  // Cloud Run (global fetch) へは行かない口。行ったら落とす。
  vi.stubGlobal("fetch", vi.fn(async () => new Response("cloud run should not be called", { status: 599 })));
});

describe("認可 (GET / POST 共通)", () => {
  const handlers = [
    ["GET", (t: string | null, env: Env) => handleUserRolesList(get(t), env)],
    ["POST", (t: string | null, env: Env) => handleUserRoleSet(post({ user_id: USER_ID, role: "leave", on: true }, t), env)],
  ] as const;

  for (const [name, call] of handlers) {
    it(`${name}: token 無し・署名不正・tenant_id 無しは 401 (alc-auth-worker を呼ばない)`, async () => {
      const { env, alcAuth } = withAlcAuth(() => json(200, []));
      expect((await call(null, env)).status).toBe(401);
      expect((await call(makeJwt("wrong-secret"), env)).status).toBe(401);
      expect((await call(makeJwt(TEST_JWT_SECRET, { tenant_id: "" }), env)).status).toBe(401);
      expect((await call(makeJwt(TEST_JWT_SECRET, { tenant_id: 1 }), env)).status).toBe(401);
      expect(alcAuth.calls).toHaveLength(0);
    });

    it(`${name}: JWT_SECRET が無ければ 401`, async () => {
      const { alcAuth } = withAlcAuth(() => json(200, []));
      const env = createMockEnv({ JWT_SECRET: undefined, ALC_AUTH: alcAuth.fetcher });
      expect((await call(makeJwt(TEST_JWT_SECRET), env)).status).toBe(401);
    });

    it(`${name}: admin でなければ 403 (alc-auth-worker を呼ばない)`, async () => {
      const { env, alcAuth } = withAlcAuth(() => json(200, []));
      const res = await call(makeJwt(TEST_JWT_SECRET, { role: "viewer" }), env);
      expect(res.status).toBe(403);
      expect(alcAuth.calls).toHaveLength(0);
    });
  }

  it("POST: 開発用・端末の token は admin でも 403 (GET は通す)", async () => {
    const { env, alcAuth } = withAlcAuth((req) => (req.method === "GET" ? json(200, []) : new Response(null, { status: 204 })));
    for (const kind of ["dev", "device-key"]) {
      const t = makeJwt(TEST_JWT_SECRET, { token_kind: kind });
      expect((await handleUserRoleSet(post({ user_id: USER_ID, role: "leave", on: true }, t), env)).status).toBe(403);
      expect((await handleUserRolesList(get(t), env)).status).toBe(200);
    }
    expect(alcAuth.calls.every((c) => c.method === "GET")).toBe(true);
  });
});

describe("GET /api/users/roles", () => {
  it("JWT の tenant で alc-auth-worker を引き、user_roles で返す (query の tenant は使わない)", async () => {
    const rows = [{ user_id: USER_ID, roles: ["leave"] }];
    const { env, alcAuth } = withAlcAuth(() => json(200, rows));
    const req = new Request("https://auth.test.example/api/users/roles?tenant_id=other", {
      headers: { Authorization: `Bearer ${makeJwt(TEST_JWT_SECRET)}` },
    });
    const res = await handleUserRolesList(req, env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ user_roles: rows });
    expect(alcAuth.calls).toHaveLength(1);
    expect(new URL(alcAuth.calls[0]!.url).pathname).toBe(`/internal/tenants/${TENANT}/user-roles`);
    expect(alcAuth.calls[0]!.headers.get("X-Internal-Shared-Secret")).toBe(FAKE_ALC_AUTH_SECRET);
  });

  it("alc-auth-worker の失敗は 502", async () => {
    const { env } = withAlcAuth(() => json(500, { error: "x" }));
    const res = await handleUserRolesList(get(), env);
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ error: "upstream_error" });
  });
});

describe("POST /api/users/roles", () => {
  it("on=true は PUT、on=false は DELETE。tenant は JWT から (body の tenant_id は無視)", async () => {
    const { env, alcAuth } = withAlcAuth(() => new Response(null, { status: 204 }));
    for (const on of [true, false]) {
      const res = await handleUserRoleSet(post({ user_id: USER_ID, role: "leave", on, tenant_id: "other" }), env);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ success: true });
    }
    expect(alcAuth.calls.map((c) => [c.method, new URL(c.url).pathname])).toEqual([
      ["PUT", `/internal/tenants/${TENANT}/users/${USER_ID}/roles/leave`],
      ["DELETE", `/internal/tenants/${TENANT}/users/${USER_ID}/roles/leave`],
    ]);
  });

  it("body が壊れている・user_id / on が無い・型違いは 400", async () => {
    const { env, alcAuth } = withAlcAuth(() => new Response(null, { status: 204 }));
    for (const body of [
      "not json",
      null,
      { role: "leave", on: true },
      { user_id: "", role: "leave", on: true },
      { user_id: 1, role: "leave", on: true },
      { user_id: USER_ID, role: "leave" },
      { user_id: USER_ID, role: "leave", on: "true" },
    ]) {
      expect((await handleUserRoleSet(post(body), env)).status).toBe(400);
    }
    expect(alcAuth.calls).toHaveLength(0);
  });

  it("leave 以外のロールは 400 unknown_role (alc-auth-worker を呼ばない)", async () => {
    const { env, alcAuth } = withAlcAuth(() => new Response(null, { status: 204 }));
    for (const role of ["admin", "Leave", 1, undefined]) {
      const res = await handleUserRoleSet(post({ user_id: USER_ID, role, on: true }), env);
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "unknown_role" });
    }
    expect(alcAuth.calls).toHaveLength(0);
  });

  it("alc-auth-worker の 404 user_not_found はそのまま 404", async () => {
    const { env } = withAlcAuth(() => json(404, { error: "user_not_found" }));
    const res = await handleUserRoleSet(post({ user_id: USER_ID, role: "leave", on: true }), env);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "user_not_found" });
  });
});

describe("lib: listUserRoles / setUserRole", () => {
  it("binding・secret が無い・通信の例外は 502 (Cloud Run へは退避しない)", async () => {
    const noBinding = createMockEnv({ INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET, ALC_AUTH_LOGIN: "1" });
    const noSecret = createMockEnv({ ALC_AUTH: createFakeAlcAuth().fetcher, INTERNAL_SHARED_SECRET: undefined });
    const throwing = createMockEnv({
      ALC_AUTH: { fetch: async () => { throw new Error("down"); } } as unknown as Fetcher,
      INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET,
    });
    for (const env of [noBinding, noSecret, throwing]) {
      expect(await listUserRoles(env, TENANT)).toEqual({ ok: false, status: 502, error: "upstream_error" });
      expect(await setUserRole(env, TENANT, USER_ID, "leave", true)).toEqual({
        ok: false,
        status: 502,
        error: "upstream_error",
      });
    }
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("listUserRoles: 配列でない・JSON でない応答は 502", async () => {
    for (const r of [json(200, { user_roles: [] }), new Response("x", { status: 200 })]) {
      const { env } = withAlcAuth(() => r);
      expect(await listUserRoles(env, TENANT)).toEqual({ ok: false, status: 502, error: "upstream_error" });
    }
  });

  it("listUserRoles: tenant を path に encode する", async () => {
    const { env, alcAuth } = withAlcAuth(() => json(200, []));
    expect(await listUserRoles(env, "a/b")).toEqual({ ok: true, value: [] });
    expect(alcAuth.calls[0]!.url).toContain("/internal/tenants/a%2Fb/user-roles");
  });

  it("setUserRole: 400 unknown_role はそのまま、本文の無い 404 (secret 不一致) や 5xx は 502", async () => {
    const cases: Array<[Response, unknown]> = [
      [json(400, { error: "unknown_role" }), { ok: false, status: 400, error: "unknown_role" }],
      [new Response(null, { status: 404 }), { ok: false, status: 502, error: "upstream_error" }],
      [json(404, { error: "other" }), { ok: false, status: 502, error: "upstream_error" }],
      [json(400, { error: "other" }), { ok: false, status: 502, error: "upstream_error" }],
      [json(500, { error: "x" }), { ok: false, status: 502, error: "upstream_error" }],
    ];
    for (const [r, expected] of cases) {
      const { env } = withAlcAuth(() => r);
      expect(await setUserRole(env, TENANT, USER_ID, "leave", false)).toEqual(expected);
    }
  });
});
