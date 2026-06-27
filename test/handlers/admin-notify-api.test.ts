import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { makeJwt } from "../helpers/live-env";

import { handleAdminNotifyApi } from "../../src/handlers/admin-notify-api";

const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

function req(
  path: string,
  init: RequestInit & { token?: string | null } = {},
) {
  const headers: Record<string, string> = {};
  const token = init.token === undefined ? makeJwt(TEST_JWT_SECRET) : init.token;
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return new Request(`https://auth.test.example${path}`, {
    method: init.method ?? "GET",
    headers: { ...headers, ...(init.headers as Record<string, string>) },
    body: init.body,
  });
}

describe("handleAdminNotifyApi (rust-alc-api#434 admin/notify forward)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("/notify/ 以外の path は 403 (allowlist)", async () => {
    const res = await handleAdminNotifyApi(
      req("/admin/notify/api/employees"),
      createMockEnv(),
    );
    expect(res.status).toBe(403);
  });

  it("token 無しは 401", async () => {
    const res = await handleAdminNotifyApi(
      req("/admin/notify/api/notify/recipients", { token: null }),
      createMockEnv(),
    );
    expect(res.status).toBe(401);
  });

  it("署名不正な token は 401", async () => {
    const res = await handleAdminNotifyApi(
      req("/admin/notify/api/notify/recipients", { token: makeJwt("wrong-secret") }),
      createMockEnv(),
    );
    expect(res.status).toBe(401);
  });

  it("正常 GET: X-Tenant-ID/X-User-* を注入して ALC_API_ORIGIN/api/notify/* に forward", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response(JSON.stringify([{ id: "u1" }]), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleAdminNotifyApi(
      req("/admin/notify/api/notify/lineworks/users?x=1"),
      createMockEnv(),
    );
    expect(res.status).toBe(200);

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe(
      "https://alc-api.test.example/api/notify/lineworks/users?x=1",
    );
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBe("11111111-1111-1111-1111-111111111111");
    expect(h["X-User-Role"]).toBe("admin");
  });

  it("POST は method/body/Content-Type を forward する", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => new Response("{}", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await handleAdminNotifyApi(
      req("/admin/notify/api/notify/recipients/bulk", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ users: [] }),
      }),
      createMockEnv(),
    );
    const [, init] = fetchMock.mock.calls[0]!;
    expect((init as RequestInit).method).toBe("POST");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Content-Type"]).toBe("application/json");
    expect((init as RequestInit).body).toBe(JSON.stringify({ users: [] }));
  });

  it("rust が非 2xx を返したら status を透過する", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => new Response("nope", { status: 404 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleAdminNotifyApi(
      req("/admin/notify/api/notify/recipients"),
      createMockEnv(),
    );
    expect(res.status).toBe(404);
  });
});
