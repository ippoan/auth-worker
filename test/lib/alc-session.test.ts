/**
 * staging だけ me・logout・my-orgs を alc-auth-worker から組む (Refs ohishi-exp/rust-leave-worker#1)。
 * 切り替えの判定 (`ALC_AUTH_SESSION` + binding + secret)・404 の読み分け・応答の形。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("../../src/lib/internal-jwt", () => ({
  signInternalJWT: vi.fn(async () => "hs256-internal-jwt"),
}));

import { fetchMyOrgs, handleSessionPath } from "../../src/lib/alc-session";
import { createMockEnv } from "../helpers/mock-env";
import { FAKE_ALC_AUTH_SECRET } from "../helpers/fake-alc-auth";
import type { Env } from "../../src/index";

const CLAIMS = { tenantId: "t-1", sub: "u-1", email: "a@example.com", role: "admin" };
const IDENTITY = {
  "X-Tenant-ID": "t-1",
  "X-User-ID": "u-1",
  "X-User-Email": "a@example.com",
  "X-User-Role": "admin",
};
const TENANT = { id: "t-1", name: "Acme", slug: "acme", short_id: "ac01" };

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

interface Stub {
  fetcher: Fetcher;
  calls: Array<{ method: string; url: string; secret: string | null }>;
}

/** alc-auth-worker の代わり。`respond` が返した応答 (または投げた例外) をそのまま返す。 */
function stubAlcAuth(respond: (req: Request) => Response | Promise<Response>): Stub {
  const calls: Stub["calls"] = [];
  const fetcher = {
    fetch: async (input: Request) => {
      calls.push({
        method: input.method,
        url: new URL(input.url).pathname,
        secret: input.headers.get("X-Internal-Shared-Secret"),
      });
      return respond(input);
    },
  } as unknown as Fetcher;
  return { fetcher, calls };
}

function envWith(over: Partial<Env> = {}): Env {
  return createMockEnv({
    ALC_AUTH_SESSION: "1",
    INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET,
    ...over,
  });
}

let cloudRun: ReturnType<typeof vi.fn>;
const originalFetch = globalThis.fetch;
beforeEach(() => {
  cloudRun = vi.fn(async () => json(200, { organizations: [{ id: "cr" }] }));
  globalThis.fetch = cloudRun as unknown as typeof fetch;
});
afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("切り替えの判定", () => {
  it("フラグ無し → alc-auth-worker を呼ばず、me/logout は null・my-orgs は Cloud Run", async () => {
    const stub = stubAlcAuth(() => json(200, TENANT));
    const env = envWith({ ALC_AUTH: stub.fetcher, ALC_AUTH_SESSION: undefined });
    expect(await handleSessionPath(env, "/api/auth/me", "GET", CLAIMS)).toBeNull();
    expect(await handleSessionPath(env, "/api/auth/logout", "POST", CLAIMS)).toBeNull();
    const r = await fetchMyOrgs(env, IDENTITY);
    expect(r).toEqual({ ok: true, data: { organizations: [{ id: "cr" }] } });
    expect(stub.calls).toHaveLength(0);
    expect(String(cloudRun.mock.calls[0]![0])).toBe("https://alc-api.test.example/api/my-orgs");
  });

  it("フラグが '1' 以外 / binding 無し / secret 無し → 今の経路", async () => {
    const stub = stubAlcAuth(() => json(200, TENANT));
    for (const env of [
      envWith({ ALC_AUTH: stub.fetcher, ALC_AUTH_SESSION: "0" }),
      envWith({ ALC_AUTH: undefined }),
      envWith({ ALC_AUTH: stub.fetcher, INTERNAL_SHARED_SECRET: undefined }),
    ]) {
      expect(await handleSessionPath(env, "/api/auth/me", "GET", CLAIMS)).toBeNull();
      const r = await fetchMyOrgs(env, IDENTITY);
      expect(r.ok && (r.data as { organizations: unknown[] }).organizations).toEqual([{ id: "cr" }]);
    }
    expect(stub.calls).toHaveLength(0);
  });

  it("対象外の path / method は null (有効でも alc-auth-worker を呼ばない)", async () => {
    const stub = stubAlcAuth(() => json(200, TENANT));
    const env = envWith({ ALC_AUTH: stub.fetcher });
    expect(await handleSessionPath(env, "/api/employees", "GET", CLAIMS)).toBeNull();
    expect(await handleSessionPath(env, "/api/auth/me", "POST", CLAIMS)).toBeNull();
    expect(await handleSessionPath(env, "/api/auth/logout", "GET", CLAIMS)).toBeNull();
    expect(stub.calls).toHaveLength(0);
  });
});

describe("me", () => {
  it("200: rust と同じ形 (name は空、tenant_slug の key は無い) + 共有 secret 付きで path どおり", async () => {
    const stub = stubAlcAuth(() => json(200, TENANT));
    const res = await handleSessionPath(envWith({ ALC_AUTH: stub.fetcher }), "/api/auth/me", "GET", CLAIMS);
    expect(res!.status).toBe(200);
    expect(await res!.json()).toEqual({
      id: "u-1",
      email: "a@example.com",
      name: "",
      tenant_id: "t-1",
      tenant_short_id: "ac01",
      role: "admin",
    });
    expect(stub.calls).toEqual([
      { method: "GET", url: "/internal/tenants/t-1", secret: FAKE_ALC_AUTH_SECRET },
    ]);
  });

  it("tenant_not_found → 401 {error: tenant_not_found}", async () => {
    const stub = stubAlcAuth(() => json(404, { error: "tenant_not_found" }));
    const res = await handleSessionPath(envWith({ ALC_AUTH: stub.fetcher }), "/api/auth/me", "GET", CLAIMS);
    expect(res!.status).toBe(401);
    expect(await res!.json()).toEqual({ error: "tenant_not_found" });
  });

  it("本文空の 404 (secret 不一致) / 500 / 形が壊れた 200 / 例外 → 502", async () => {
    const cases: Array<() => Response | Promise<Response>> = [
      () => new Response(null, { status: 404 }),
      () => json(404, { error: "other" }),
      () => json(500, { error: "boom" }),
      () => json(200, { id: "t-1" }),
      () => json(200, { ...TENANT, slug: 5 }),
      () => new Response("not json", { status: 200 }),
      () => {
        throw new Error("binding down");
      },
    ];
    for (const respond of cases) {
      const stub = stubAlcAuth(respond);
      const res = await handleSessionPath(envWith({ ALC_AUTH: stub.fetcher }), "/api/auth/me", "GET", CLAIMS);
      expect(res!.status).toBe(502);
    }
  });

  it("slug が null でも 200", async () => {
    const stub = stubAlcAuth(() => json(200, { ...TENANT, slug: null }));
    const res = await handleSessionPath(envWith({ ALC_AUTH: stub.fetcher }), "/api/auth/me", "GET", CLAIMS);
    expect(res!.status).toBe(200);
  });
});

describe("logout", () => {
  it("DELETE が path どおり飛び、204 をそのまま返す", async () => {
    const stub = stubAlcAuth(() => new Response(null, { status: 204 }));
    const res = await handleSessionPath(
      envWith({ ALC_AUTH: stub.fetcher }),
      "/api/auth/logout",
      "POST",
      CLAIMS,
    );
    expect(res!.status).toBe(204);
    expect(stub.calls).toEqual([
      { method: "DELETE", url: "/internal/tenants/t-1/users/u-1/refresh-token", secret: FAKE_ALC_AUTH_SECRET },
    ]);
  });

  it("失敗 (500 / 404 / 例外) → 502", async () => {
    for (const respond of [
      () => json(500, {}),
      () => new Response(null, { status: 404 }),
      () => {
        throw new Error("down");
      },
    ] as Array<() => Response>) {
      const stub = stubAlcAuth(respond);
      const res = await handleSessionPath(
        envWith({ ALC_AUTH: stub.fetcher }),
        "/api/auth/logout",
        "POST",
        CLAIMS,
      );
      expect(res!.status).toBe(502);
    }
  });
});

describe("fetchMyOrgs", () => {
  it("200: 現テナント 1 件 (role は identity から、slug null は '')", async () => {
    const stub = stubAlcAuth(() => json(200, { ...TENANT, slug: null }));
    const r = await fetchMyOrgs(envWith({ ALC_AUTH: stub.fetcher }), IDENTITY);
    expect(r).toEqual({
      ok: true,
      data: { organizations: [{ id: "t-1", name: "Acme", slug: "", role: "admin" }] },
    });
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("slug が有れば slug を返す", async () => {
    const stub = stubAlcAuth(() => json(200, TENANT));
    const r = await fetchMyOrgs(envWith({ ALC_AUTH: stub.fetcher }), IDENTITY);
    expect(r).toMatchObject({ data: { organizations: [{ slug: "acme" }] } });
  });

  it("tenant_not_found → 空の一覧", async () => {
    const stub = stubAlcAuth(() => json(404, { error: "tenant_not_found" }));
    const r = await fetchMyOrgs(envWith({ ALC_AUTH: stub.fetcher }), IDENTITY);
    expect(r).toEqual({ ok: true, data: { organizations: [] } });
  });

  it("他の失敗 → 502 (本文空の 404 も)", async () => {
    for (const respond of [
      () => new Response(null, { status: 404 }),
      () => json(500, {}),
    ]) {
      const stub = stubAlcAuth(respond);
      const r = await fetchMyOrgs(envWith({ ALC_AUTH: stub.fetcher }), IDENTITY);
      expect(r).toEqual({ ok: false, status: 502, error: "upstream_error" });
    }
  });

  it("identity に X-Tenant-ID / X-User-Role が無くても落ちない", async () => {
    const stub = stubAlcAuth(() => json(200, TENANT));
    const r = await fetchMyOrgs(envWith({ ALC_AUTH: stub.fetcher }), {});
    expect(r).toMatchObject({ ok: true, data: { organizations: [{ role: "" }] } });
  });

  it("Cloud Run 経路: 非 2xx は status と本文を返す", async () => {
    cloudRun.mockResolvedValueOnce(new Response("forbidden", { status: 403 }));
    const r = await fetchMyOrgs(envWith({ ALC_AUTH_SESSION: undefined }), IDENTITY);
    expect(r).toEqual({ ok: false, status: 403, error: "forbidden" });
  });
});
