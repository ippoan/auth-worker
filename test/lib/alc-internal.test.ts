import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("../../src/lib/internal-jwt", () => ({
  signInternalJWT: vi.fn(async () => "hs256-internal-jwt"),
}));
vi.mock("../../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async (_saKey: unknown, aud: string) => `oidc-token:${aud}`),
}));

import {
  fetchRlsCheck,
  internalAuthToken,
  resolveActiveDeviceTenant,
} from "../../src/lib/alc-internal";
import { signInternalJWT } from "../../src/lib/internal-jwt";
import { mintGoogleIdToken } from "../../src/lib/oidc";
import type { Env } from "../../src/index";

function env(overrides: Record<string, unknown> = {}): Env {
  return { ALC_API_ORIGIN: "https://alc-api.test", ...overrides } as unknown as Env;
}

const originalFetch = globalThis.fetch;

describe("internalAuthToken (rust-alc-api#434 lockdown cutover)", () => {
  beforeEach(() => vi.clearAllMocks());

  it("flag 未設定は HS256 internal JWT (非破壊)", async () => {
    const tok = await internalAuthToken(env({ ALC_API_PROXY_SA_KEY: "{}" }));
    expect(tok).toBe("hs256-internal-jwt");
    expect(signInternalJWT).toHaveBeenCalledTimes(1);
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });

  it("INTERNAL_AUTH_OIDC=1 + SA key で Google OIDC (aud=alc-api-internal) を mint", async () => {
    const tok = await internalAuthToken(env({ INTERNAL_AUTH_OIDC: "1", ALC_API_PROXY_SA_KEY: "{}" }));
    expect(tok).toBe("oidc-token:alc-api-internal");
    expect(mintGoogleIdToken).toHaveBeenCalledTimes(1);
    expect(signInternalJWT).not.toHaveBeenCalled();
  });

  it("flag=1 でも SA key 無しは HS256 に fallback (fail-safe)", async () => {
    const tok = await internalAuthToken(env({ INTERNAL_AUTH_OIDC: "1" }));
    expect(tok).toBe("hs256-internal-jwt");
    expect(signInternalJWT).toHaveBeenCalledTimes(1);
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });
});

describe("resolveActiveDeviceTenant (Refs #544)", () => {
  beforeEach(() => vi.clearAllMocks());
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("200 + tenant_id で ok", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        expect(url).toBe("https://alc-api.test/api/internal/devices/dev-1/pairing-tenant");
        return new Response(JSON.stringify({ tenant_id: "tenant-9" }), { status: 200 });
      }),
    );
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: true, tenantId: "tenant-9" });
  });

  it("device_id を path に URL-encode する", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ tenant_id: "t" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await resolveActiveDeviceTenant(env(), "a/b c");
    expect(fetchMock).toHaveBeenCalledWith(
      "https://alc-api.test/api/internal/devices/a%2Fb%20c/pairing-tenant",
      expect.anything(),
    );
  });

  it("404 は not_found", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 404 })));
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: false, reason: "not_found" });
  });

  it("401 は unavailable (SA key 未設定で HS256 に落ちた場合の rust 401 を含む)", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 401 })));
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: false, reason: "unavailable" });
  });

  it("5xx は unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 500 })));
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: false, reason: "unavailable" });
  });

  it("200 だが JSON 不正は unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{not json", { status: 200 })));
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: false, reason: "unavailable" });
  });

  it("200 だが tenant_id 欠落は unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({}), { status: 200 })));
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: false, reason: "unavailable" });
  });

  it("200 だが tenant_id が空文字は unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ tenant_id: "" }), { status: 200 })),
    );
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: false, reason: "unavailable" });
  });

  it("fetch の例外は unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: false, reason: "unavailable" });
  });
});

describe("fetchRlsCheck (Refs #605)", () => {
  beforeEach(() => vi.clearAllMocks());
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  /** 契約どおりの応答。テストごとに作り直す (書き換えても他へ漏れないように)。 */
  function contract(): Record<string, any> {
    return {
      ok: true,
      migrations: {
        applied: 159,
        max_version: 160,
        binary_count: 159,
        binary_max_version: 160,
        matches_binary: true,
      },
      runtime_role: {
        current_user: "rt_role",
        is_runtime_role: true,
        rolsuper: false,
        rolbypassrls: false,
        rolinherit: false,
        member_of_table_owner: false,
      },
      connections: [{ usename: "rt_role", count: 3 }],
      owner_role_connected: false,
      invariants: {
        violation_count: 1,
        violations: [{ check_no: 1, object: "table x", detail: "d" }],
      },
    };
  }

  function stubJson(body: unknown, status = 200): ReturnType<typeof vi.fn> {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(body), { status }));
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("200 + 契約どおりは同じ値を返す", async () => {
    stubJson(contract());
    expect(await fetchRlsCheck(env())).toEqual(contract());
  });

  it("connections と violations は空配列でもよい", async () => {
    const body = contract();
    body.connections = [];
    body.invariants = { violation_count: 0, violations: [] };
    stubJson(body);
    expect(await fetchRlsCheck(env())).toEqual(body);
  });

  it("GET 1 回・path 固定・テナントのヘッダ無し・body 無しで呼ぶ", async () => {
    const fetchMock = stubJson(contract());
    await fetchRlsCheck(env());
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://alc-api.test/api/internal/rls-check");
    expect(init.method).toBe("GET");
    expect(init.body).toBeUndefined();
    const headers = init.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer hs256-internal-jwt");
    expect(headers.has("X-Tenant-ID")).toBe(false);
    expect(headers.has("Content-Type")).toBe(false);
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it("余分な key はどの深さでも出力に出ない", async () => {
    const body = contract();
    body.extra_top = "leak";
    body.migrations.extra = "leak";
    body.runtime_role.extra = "leak";
    body.connections[0].extra = "leak";
    body.invariants.extra = "leak";
    body.invariants.violations[0].extra = "leak";
    stubJson(body);
    const res = await fetchRlsCheck(env());
    expect(res).toEqual(contract());
    expect(JSON.stringify(res)).not.toContain("leak");
  });

  it.each<[string, (b: Record<string, any>) => void]>([
    ["ok が文字列", (b) => (b.ok = "true")],
    ["ok 欠け", (b) => delete b.ok],
    ["owner_role_connected が数値", (b) => (b.owner_role_connected = 0)],
    ["migrations 欠け", (b) => delete b.migrations],
    ["migrations が配列", (b) => (b.migrations = [])],
    ["migrations.applied が文字列", (b) => (b.migrations.applied = "159")],
    ["migrations.max_version 欠け", (b) => delete b.migrations.max_version],
    ["migrations.binary_count が null", (b) => (b.migrations.binary_count = null)],
    ["migrations.binary_max_version が文字列", (b) => (b.migrations.binary_max_version = "160")],
    ["migrations.matches_binary が文字列", (b) => (b.migrations.matches_binary = "true")],
    ["runtime_role が null", (b) => (b.runtime_role = null)],
    ["runtime_role.current_user が数値", (b) => (b.runtime_role.current_user = 1)],
    ["runtime_role.is_runtime_role が文字列", (b) => (b.runtime_role.is_runtime_role = "t")],
    ["runtime_role.rolsuper 欠け", (b) => delete b.runtime_role.rolsuper],
    ["runtime_role.rolbypassrls が数値", (b) => (b.runtime_role.rolbypassrls = 0)],
    ["runtime_role.rolinherit が文字列", (b) => (b.runtime_role.rolinherit = "f")],
    ["runtime_role.member_of_table_owner が null", (b) => (b.runtime_role.member_of_table_owner = null)],
    ["connections が object", (b) => (b.connections = {})],
    ["connections[] が文字列", (b) => (b.connections = ["rt_role"])],
    ["connections[].usename が数値", (b) => (b.connections[0].usename = 1)],
    ["connections[].count が文字列", (b) => (b.connections[0].count = "3")],
    ["invariants 欠け", (b) => delete b.invariants],
    ["invariants.violation_count が文字列", (b) => (b.invariants.violation_count = "0")],
    ["invariants.violations 欠け", (b) => delete b.invariants.violations],
    ["violations[] が null", (b) => (b.invariants.violations = [null])],
    ["violations[].check_no が文字列", (b) => (b.invariants.violations[0].check_no = "1")],
    ["violations[].object が数値", (b) => (b.invariants.violations[0].object = 1)],
    ["violations[].detail 欠け", (b) => delete b.invariants.violations[0].detail],
  ])("契約の型に合わない応答は null: %s", async (_label, mutate) => {
    const body = contract();
    mutate(body);
    stubJson(body);
    expect(await fetchRlsCheck(env())).toBeNull();
  });

  it.each([null, [], "text", 1])("最上位が object でない応答 (%j) は null", async (body) => {
    stubJson(body);
    expect(await fetchRlsCheck(env())).toBeNull();
  });

  it.each([201, 401, 403, 404, 500, 503])("非 200 (%i) は null", async (status) => {
    stubJson(contract(), status);
    expect(await fetchRlsCheck(env())).toBeNull();
  });

  it("200 だが JSON 不正は null", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{not json", { status: 200 })));
    expect(await fetchRlsCheck(env())).toBeNull();
  });

  it("fetch の例外は null", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );
    expect(await fetchRlsCheck(env())).toBeNull();
  });
});
