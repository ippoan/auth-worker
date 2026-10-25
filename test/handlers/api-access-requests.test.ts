/**
 * `/api/access-requests/*` (参加の申請) — alc-auth-worker (`ALC_AUTH`) の内部口を叩く (Refs ippoan/rust-alc-api#680)。
 * 申請はログイン中の誰でも (申請者は JWT の sub)、一覧・承認・却下は申請先の会社の管理者だけ。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { makeJwt, TEST_TENANT_ID, TEST_USER_ID } from "../helpers/live-env";
import { createFakeAlcAuth, FAKE_ALC_AUTH_SECRET, type FakeAlcAuth } from "../helpers/fake-alc-auth";
import {
  handleAccessRequestCreate,
  handleAccessRequestList,
  handleAccessRequestApprove,
  handleAccessRequestDecline,
} from "../../src/handlers/api-access-requests";
import type { Env } from "../../src/index";

const REQ_ID = "44444444-4444-4444-4444-444444444444";

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

function req(body: unknown, token: string | null = makeJwt(TEST_JWT_SECRET)): Request {
  return new Request("https://auth.test.example/api/access-requests/x", {
    method: "POST",
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

const url = (a: FakeAlcAuth, i = 0) => new URL(a.calls[i]!.url);

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response("cloud run should not be called", { status: 599 })));
});

describe("handleAccessRequestCreate", () => {
  it("slug と JWT の sub で申請し、申請の 1 行を返す (admin でなくてよい)", async () => {
    const row = { id: REQ_ID, tenant_id: "t", user_id: TEST_USER_ID, status: "pending", role: "viewer", org_name: "Org", created_at: "c" };
    const { env, alcAuth } = withAlcAuth(() => json(201, row));
    const res = await handleAccessRequestCreate(req({ orgSlug: "acme" }, makeJwt(TEST_JWT_SECRET, { role: "viewer" })), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(row);
    expect(url(alcAuth).pathname).toBe("/internal/access-requests");
    expect(alcAuth.calls[0]!.method).toBe("POST");
    expect(JSON.parse(alcAuth.calls[0]!.body)).toEqual({ org_slug: "acme", user_id: TEST_USER_ID });
  });

  it("token 無しは 401・開発用の token は 403・orgSlug 無しは 400 (alc-auth-worker を呼ばない)", async () => {
    const { env, alcAuth } = withAlcAuth(() => json(201, {}));
    expect((await handleAccessRequestCreate(req({ orgSlug: "acme" }, null), env)).status).toBe(401);
    const dev = makeJwt(TEST_JWT_SECRET, { token_kind: "dev" });
    expect((await handleAccessRequestCreate(req({ orgSlug: "acme" }, dev), env)).status).toBe(403);
    expect((await handleAccessRequestCreate(req({}), env)).status).toBe(400);
    expect(alcAuth.calls).toHaveLength(0);
  });

  it("無い slug の 404 はそのまま返す", async () => {
    const { env } = withAlcAuth(() => json(404, { error: "tenant_not_found" }));
    const res = await handleAccessRequestCreate(req({ orgSlug: "nope" }), env);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "tenant_not_found" });
  });
});

describe("handleAccessRequestList", () => {
  it("JWT の会社の申請を引く (statusFilter は query に)", async () => {
    const { env, alcAuth } = withAlcAuth(() => json(200, { requests: [] }));
    let res = await handleAccessRequestList(req({}), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ requests: [] });
    expect(url(alcAuth, 0).pathname).toBe(`/internal/tenants/${TEST_TENANT_ID}/access-requests`);
    expect(url(alcAuth, 0).search).toBe("");
    res = await handleAccessRequestList(req({ statusFilter: "pending" }), env);
    expect(url(alcAuth, 1).searchParams.get("status")).toBe("pending");
  });

  it("admin でなければ 403、失敗は 502", async () => {
    const { env, alcAuth } = withAlcAuth(() => json(500, {}));
    expect((await handleAccessRequestList(req({}, makeJwt(TEST_JWT_SECRET, { role: "viewer" })), env)).status).toBe(403);
    expect(alcAuth.calls).toHaveLength(0);
    expect((await handleAccessRequestList(req({}), env)).status).toBe(502);
  });
});

describe("承認・却下", () => {
  it("JWT の会社の path で承認 (role を送る)・却下し {success:true}", async () => {
    const { env, alcAuth } = withAlcAuth(() => new Response(null, { status: 204 }));
    let res = await handleAccessRequestApprove(req({ requestId: REQ_ID, role: "payroll" }), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true });
    res = await handleAccessRequestDecline(req({ requestId: REQ_ID }), env);
    expect(await res.json()).toEqual({ success: true });
    expect(url(alcAuth, 0).pathname).toBe(`/internal/tenants/${TEST_TENANT_ID}/access-requests/${REQ_ID}/approve`);
    expect(JSON.parse(alcAuth.calls[0]!.body)).toEqual({ role: "payroll" });
    expect(url(alcAuth, 1).pathname).toBe(`/internal/tenants/${TEST_TENANT_ID}/access-requests/${REQ_ID}/decline`);
    expect(alcAuth.calls.every((c) => c.method === "POST")).toBe(true);
  });

  it("requestId 無しは 400・admin でなければ 403 (alc-auth-worker を呼ばない)", async () => {
    const { env, alcAuth } = withAlcAuth(() => new Response(null, { status: 204 }));
    const viewer = makeJwt(TEST_JWT_SECRET, { role: "viewer" });
    for (const h of [handleAccessRequestApprove, handleAccessRequestDecline]) {
      expect((await h(req({}), env)).status).toBe(400);
      expect((await h(req({ requestId: REQ_ID }, viewer), env)).status).toBe(403);
    }
    expect(alcAuth.calls).toHaveLength(0);
  });

  it("無い・pending でない申請の 404 はそのまま返す", async () => {
    const { env } = withAlcAuth(() => json(404, { error: "request_not_found" }));
    for (const h of [handleAccessRequestApprove, handleAccessRequestDecline]) {
      const res = await h(req({ requestId: REQ_ID }), env);
      expect(res.status).toBe(404);
      expect(await res.json()).toEqual({ error: "request_not_found" });
    }
  });
});
