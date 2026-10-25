/**
 * `/api/users/*` (会社のユーザー・招待) — alc-auth-worker (`ALC_AUTH`) の内部口を叩く (Refs ippoan/rust-alc-api#680)。
 * 認可 (`requireCaller`) の細部は test/lib/alc-tenant-admin.test.ts。ロールの口は api-users-roles.test.ts。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { makeJwt, TEST_TENANT_ID, TEST_USER_ID } from "../helpers/live-env";
import { createFakeAlcAuth, FAKE_ALC_AUTH_SECRET, type FakeAlcAuth } from "../helpers/fake-alc-auth";
import {
  handleUsersList,
  handleInvitationsList,
  handleInviteUser,
  handleDeleteInvitation,
  handleDeleteUser,
} from "../../src/handlers/api-users";
import type { Env } from "../../src/index";

const OTHER = "33333333-3333-3333-3333-333333333333";

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function withAlcAuth(respond: (req: Request) => Response): { env: Env; alcAuth: FakeAlcAuth } {
  const alcAuth = createFakeAlcAuth({ override: respond });
  return {
    alcAuth,
    env: createMockEnv({ ALC_AUTH: alcAuth.fetcher, INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET }),
  };
}

function req(body?: unknown, token: string | null = makeJwt(TEST_JWT_SECRET)): Request {
  return new Request("https://auth.test.example/api/users/x", {
    method: body === undefined ? "GET" : "POST",
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), "Content-Type": "application/json" },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
  });
}

const path = (a: FakeAlcAuth, i = 0) => new URL(a.calls[i]!.url).pathname;

beforeEach(() => {
  // Cloud Run (global fetch) へは行かない。行ったら落とす
  vi.stubGlobal("fetch", vi.fn(async () => new Response("cloud run should not be called", { status: 599 })));
});

describe("認可", () => {
  const handlers = [
    ["list", (t: string | null, env: Env) => handleUsersList(req(undefined, t), env)],
    ["invitations", (t: string | null, env: Env) => handleInvitationsList(req(undefined, t), env)],
    ["invite", (t: string | null, env: Env) => handleInviteUser(req({ email: "a@example.test" }, t), env)],
    ["invite/delete", (t: string | null, env: Env) => handleDeleteInvitation(req({ id: OTHER }, t), env)],
    ["delete", (t: string | null, env: Env) => handleDeleteUser(req({ id: OTHER }, t), env)],
  ] as const;

  for (const [name, call] of handlers) {
    it(`${name}: token 無しは 401・admin でなければ 403 (alc-auth-worker を呼ばない)`, async () => {
      const { env, alcAuth } = withAlcAuth(() => json(200, {}));
      expect((await call(null, env)).status).toBe(401);
      expect((await call(makeJwt(TEST_JWT_SECRET, { role: "viewer" }), env)).status).toBe(403);
      expect(alcAuth.calls).toHaveLength(0);
    });
  }

  it("書き込みの 3 口は開発用の token なら 403", async () => {
    const { env, alcAuth } = withAlcAuth(() => new Response(null, { status: 204 }));
    const t = makeJwt(TEST_JWT_SECRET, { token_kind: "dev" });
    expect((await handleInviteUser(req({ email: "a@example.test" }, t), env)).status).toBe(403);
    expect((await handleDeleteInvitation(req({ id: OTHER }, t), env)).status).toBe(403);
    expect((await handleDeleteUser(req({ id: OTHER }, t), env)).status).toBe(403);
    expect(alcAuth.calls).toHaveLength(0);
  });
});

describe("一覧", () => {
  it("JWT の会社の users / invitations を引いてそのまま返す", async () => {
    const users = { users: [{ id: OTHER, email: "a@example.test", name: "A", role: "viewer", created_at: "t" }] };
    const invitations = { invitations: [] };
    const { env, alcAuth } = withAlcAuth((r) =>
      json(200, new URL(r.url).pathname.endsWith("/users") ? users : invitations),
    );
    let res = await handleUsersList(req(), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(users);
    res = await handleInvitationsList(req(), env);
    expect(await res.json()).toEqual(invitations);
    expect(path(alcAuth, 0)).toBe(`/internal/tenants/${TEST_TENANT_ID}/users`);
    expect(path(alcAuth, 1)).toBe(`/internal/tenants/${TEST_TENANT_ID}/invitations`);
    expect(alcAuth.calls.every((c) => c.method === "GET")).toBe(true);
  });

  it("alc-auth-worker の失敗は 502", async () => {
    const { env } = withAlcAuth(() => json(500, { error: "internal_error" }));
    for (const h of [handleUsersList, handleInvitationsList]) {
      const res = await h(req(), env);
      expect(res.status).toBe(502);
      expect(await res.json()).toEqual({ error: "upstream_error" });
    }
  });
});

describe("handleInviteUser", () => {
  it("email と role (省略は admin) を JWT の会社に送り、招待の 1 行を返す", async () => {
    const row = { id: OTHER, tenant_id: TEST_TENANT_ID, email: "a@example.test", role: "admin", created_at: "t" };
    const { env, alcAuth } = withAlcAuth(() => json(200, row));
    const res = await handleInviteUser(req({ email: "a@example.test" }), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(row);
    expect(path(alcAuth)).toBe(`/internal/tenants/${TEST_TENANT_ID}/invitations`);
    expect(alcAuth.calls[0]!.method).toBe("POST");
    expect(JSON.parse(alcAuth.calls[0]!.body)).toEqual({ email: "a@example.test", role: "admin" });

    await handleInviteUser(req({ email: "b@example.test", role: "payroll" }), env);
    expect(JSON.parse(alcAuth.calls[1]!.body)).toEqual({ email: "b@example.test", role: "payroll" });
  });

  it("email 無し・JSON でない body は 400 (alc-auth-worker を呼ばない)", async () => {
    const { env, alcAuth } = withAlcAuth(() => json(200, {}));
    for (const b of [{}, { email: "" }, { email: 1 }, "{"]) {
      const res = await handleInviteUser(req(b), env);
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "email is required" });
    }
    expect(alcAuth.calls).toHaveLength(0);
  });

  it("alc-auth-worker の 4xx はそのまま返す", async () => {
    const { env } = withAlcAuth(() => json(409, { error: "email_taken" }));
    const res = await handleInviteUser(req({ email: "a@example.test" }), env);
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "email_taken" });
  });
});

describe("削除", () => {
  it("招待と user を JWT の会社の path で消し、{success:true} を返す", async () => {
    const { env, alcAuth } = withAlcAuth(() => new Response(null, { status: 204 }));
    let res = await handleDeleteInvitation(req({ id: OTHER }), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true });
    res = await handleDeleteUser(req({ id: OTHER }), env);
    expect(await res.json()).toEqual({ success: true });
    expect(path(alcAuth, 0)).toBe(`/internal/tenants/${TEST_TENANT_ID}/invitations/${OTHER}`);
    expect(path(alcAuth, 1)).toBe(`/internal/tenants/${TEST_TENANT_ID}/users/${OTHER}`);
    expect(alcAuth.calls.every((c) => c.method === "DELETE")).toBe(true);
  });

  it("id 無し・JSON でない body は 400", async () => {
    const { env, alcAuth } = withAlcAuth(() => new Response(null, { status: 204 }));
    for (const h of [handleDeleteInvitation, handleDeleteUser]) {
      for (const b of [{}, { id: "" }, { id: 1 }, "{"]) {
        const res = await h(req(b), env);
        expect(res.status).toBe(400);
        expect(await res.json()).toEqual({ error: "id is required" });
      }
    }
    expect(alcAuth.calls).toHaveLength(0);
  });

  it("自分自身は消せない (400、alc-auth-worker を呼ばない)", async () => {
    const { env, alcAuth } = withAlcAuth(() => new Response(null, { status: 204 }));
    const res = await handleDeleteUser(req({ id: TEST_USER_ID }), env);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "cannot_delete_self" });
    expect(alcAuth.calls).toHaveLength(0);
  });

  it("alc-auth-worker の失敗はそのまま (4xx) / 502 (5xx)", async () => {
    const { env } = withAlcAuth(() => json(400, { error: "invalid_id" }));
    const res = await handleDeleteInvitation(req({ id: "x" }), env);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_id" });
    const failing = withAlcAuth(() => json(500, { error: "internal_error" })).env;
    expect((await handleDeleteUser(req({ id: OTHER }), failing)).status).toBe(502);
  });
});
