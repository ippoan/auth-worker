import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("../../src/lib/internal-jwt", () => ({
  signInternalJWT: vi.fn(async () => "hs256-internal-jwt"),
}));
vi.mock("../../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async (_saKey: unknown, aud: string) => `oidc-token:${aud}`),
}));

import {
  RLS_STATE_MAX_LENGTH,
  buildVerifyRlsResult,
  fetchRlsCheck,
  fetchVeinDbRole,
  internalAuthToken,
  resolveActiveDeviceTenant,
} from "../../src/lib/alc-internal";
import { signInternalJWT } from "../../src/lib/internal-jwt";
import { mintGoogleIdToken } from "../../src/lib/oidc";
import type { RlsCheckResult, VeinDbRole } from "../../src/lib/alc-internal";
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
        checks: [
          { check_no: 0, title: "t0", violations: 0 },
          { check_no: 1, title: "t1", violations: 1 },
        ],
        violations: [{ check_no: 1, object: "table x", detail: "d" }],
      },
      state: {
        tables: [{ count: 2, rls_enabled: true, policies: [{ using: "(x)" }], names: ["a", "b"] }],
        table_count: 2,
        views: [],
      },
      verdicts: { invariants: true, runtime_role: true, migrations: true, drift: true },
      drift: { matches_expected: false, tables: [{ name: "table x", expected: {}, actual: {} }] },
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
    body.invariants = { violation_count: 0, checks: [], violations: [] };
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
    body.invariants.checks[0].extra = "leak";
    body.invariants.violations[0].extra = "leak";
    body.verdicts.extra = "leak";
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
    ["invariants.checks 欠け", (b) => delete b.invariants.checks],
    ["invariants.checks が object", (b) => (b.invariants.checks = {})],
    ["checks[] が null", (b) => (b.invariants.checks = [null])],
    ["checks[].check_no が文字列", (b) => (b.invariants.checks[0].check_no = "0")],
    ["checks[].title 欠け", (b) => delete b.invariants.checks[0].title],
    ["checks[].violations が文字列", (b) => (b.invariants.checks[1].violations = "1")],
    ["violations[] が null", (b) => (b.invariants.violations = [null])],
    ["violations[].check_no が文字列", (b) => (b.invariants.violations[0].check_no = "1")],
    ["violations[].object が数値", (b) => (b.invariants.violations[0].object = 1)],
    ["violations[].detail 欠け", (b) => delete b.invariants.violations[0].detail],
    ["verdicts が null", (b) => (b.verdicts = null)],
    ["verdicts が配列", (b) => (b.verdicts = [true, true, true, true])],
    ["verdicts が文字列", (b) => (b.verdicts = "ok")],
    ["verdicts.invariants 欠け", (b) => delete b.verdicts.invariants],
    ["verdicts.runtime_role が文字列", (b) => (b.verdicts.runtime_role = "true")],
    ["verdicts.migrations が null", (b) => (b.verdicts.migrations = null)],
    ["verdicts.drift が数値", (b) => (b.verdicts.drift = 1)],
  ])("契約の型に合わない応答は null: %s", async (_label, mutate) => {
    const body = contract();
    mutate(body);
    stubJson(body);
    expect(await fetchRlsCheck(env())).toBeNull();
  });

  it("state は object ならそのまま返す (入れ子の未知の key も残る)", async () => {
    const body = contract();
    body.state = { tables: [{ future_key: { deep: [1, "x", null] } }], another: true };
    stubJson(body);
    const res = await fetchRlsCheck(env());
    expect(res?.state).toEqual({ tables: [{ future_key: { deep: [1, "x", null] } }], another: true });
  });

  it.each<[string, (b: Record<string, any>) => void]>([
    ["null", (b) => (b.state = null)],
    ["欠け", (b) => delete b.state],
    ["配列", (b) => (b.state = [{ tables: [] }])],
    ["文字列", (b) => (b.state = "{}")],
    ["数値", (b) => (b.state = 1)],
  ])("state が %s なら state: null にし、ほかの値は返す", async (_label, mutate) => {
    const body = contract();
    mutate(body);
    stubJson(body);
    expect(await fetchRlsCheck(env())).toEqual({ ...contract(), state: null });
  });

  it("state は上限ちょうどまで通し、超えたら state: null (ほかの値は返す)", async () => {
    // {"pad":"…"} の外枠は 10 文字。
    const atLimit = { pad: "x".repeat(RLS_STATE_MAX_LENGTH - 10) };
    expect(JSON.stringify(atLimit)).toHaveLength(RLS_STATE_MAX_LENGTH);
    stubJson({ ...contract(), state: atLimit });
    expect(await fetchRlsCheck(env())).toEqual({ ...contract(), state: atLimit });

    stubJson({ ...contract(), state: { pad: "x".repeat(RLS_STATE_MAX_LENGTH - 9) } });
    expect(await fetchRlsCheck(env())).toEqual({ ...contract(), state: null });
  });

  it("verdicts は 4 つとも boolean なら、その値を写す", async () => {
    const body = contract();
    body.verdicts = { invariants: true, runtime_role: false, migrations: true, drift: false };
    stubJson(body);
    const res = await fetchRlsCheck(env());
    expect(res?.verdicts).toEqual({
      invariants: true,
      runtime_role: false,
      migrations: true,
      drift: false,
    });
  });

  it("verdicts と drift を返さない backend (古い版) でも、verdicts: null・drift: null でほかの値を返す", async () => {
    const body = contract();
    delete body.verdicts;
    delete body.drift;
    stubJson(body);
    expect(await fetchRlsCheck(env())).toEqual({ ...contract(), verdicts: null, drift: null });
  });

  it("drift は object ならそのまま返す (入れ子の未知の key も残る)", async () => {
    const body = contract();
    body.drift = { matches_expected: false, future_key: { deep: [1, "x", null] } };
    stubJson(body);
    const res = await fetchRlsCheck(env());
    expect(res?.drift).toEqual({ matches_expected: false, future_key: { deep: [1, "x", null] } });
  });

  it.each<[string, (b: Record<string, any>) => void]>([
    ["null", (b) => (b.drift = null)],
    ["欠け", (b) => delete b.drift],
    ["配列", (b) => (b.drift = [{ tables: [] }])],
    ["文字列", (b) => (b.drift = "{}")],
    ["数値", (b) => (b.drift = 1)],
  ])("drift が %s なら drift: null にし、ほかの値は返す", async (_label, mutate) => {
    const body = contract();
    mutate(body);
    stubJson(body);
    expect(await fetchRlsCheck(env())).toEqual({ ...contract(), drift: null });
  });

  it("drift は state と同じ上限ちょうどまで通し、超えたら drift: null (ほかの値は返す)", async () => {
    const atLimit = { pad: "x".repeat(RLS_STATE_MAX_LENGTH - 10) };
    stubJson({ ...contract(), drift: atLimit });
    expect(await fetchRlsCheck(env())).toEqual({ ...contract(), drift: atLimit });

    stubJson({ ...contract(), drift: { pad: "x".repeat(RLS_STATE_MAX_LENGTH - 9) } });
    expect(await fetchRlsCheck(env())).toEqual({ ...contract(), drift: null });
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

describe("fetchVeinDbRole (Refs #605)", () => {
  const FAILED: VeinDbRole = { bound: true, current_user: null, is_runtime_role: null };

  function makeBinding(respond: () => Promise<Response> | Response) {
    return { fetch: vi.fn(async (_url: string, _init?: RequestInit) => respond()) };
  }

  function veinEnv(binding: ReturnType<typeof makeBinding>): Env {
    return env({ ALC_VEIN: binding as unknown as Fetcher });
  }

  function jsonBinding(body: unknown, status = 200) {
    return makeBinding(() => new Response(JSON.stringify(body), { status }));
  }

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("binding が無ければ bound: false (どこも呼ばない)", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect(await fetchVeinDbRole(env())).toEqual({
      bound: false,
      current_user: null,
      is_runtime_role: null,
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([true, false])("200 + 契約どおり (is_runtime_role: %s) は 2 値を返す", async (isRt) => {
    const binding = jsonBinding({ current_user: "some_role", is_runtime_role: isRt });
    expect(await fetchVeinDbRole(veinEnv(binding))).toEqual({
      bound: true,
      current_user: "some_role",
      is_runtime_role: isRt,
    });
  });

  it("余分な key は出力に出ない", async () => {
    const binding = jsonBinding({ current_user: "rt_role", is_runtime_role: true, extra: "leak" });
    const res = await fetchVeinDbRole(veinEnv(binding));
    expect(res).toEqual({ bound: true, current_user: "rt_role", is_runtime_role: true });
    expect(JSON.stringify(res)).not.toContain("leak");
  });

  it("binding へ GET 1 回・URL 固定・Authorization もテナントのヘッダも body も無しで呼ぶ", async () => {
    const globalFetch = vi.fn();
    vi.stubGlobal("fetch", globalFetch);
    const binding = jsonBinding({ current_user: "rt_role", is_runtime_role: true });
    await fetchVeinDbRole(veinEnv(binding));

    expect(globalFetch).not.toHaveBeenCalled();
    expect(binding.fetch).toHaveBeenCalledTimes(1);
    const [url, init] = binding.fetch.mock.calls[0]!;
    expect(url).toBe("https://alc-vein/internal/db-role");
    expect(init?.method).toBe("GET");
    expect(init?.body).toBeUndefined();
    const headers = new Headers(init?.headers);
    expect(headers.has("Authorization")).toBe(false);
    expect(headers.has("X-Tenant-ID")).toBe(false);
    expect([...headers.keys()]).toEqual([]);
    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it.each([201, 401, 403, 404, 500, 503])("非 200 (%i) は bound: true で値は null", async (status) => {
    const binding = jsonBinding({ current_user: "rt_role", is_runtime_role: true }, status);
    expect(await fetchVeinDbRole(veinEnv(binding))).toEqual(FAILED);
  });

  it("fetch の例外は bound: true で値は null", async () => {
    const binding = makeBinding(() => {
      throw new Error("binding down");
    });
    expect(await fetchVeinDbRole(veinEnv(binding))).toEqual(FAILED);
  });

  it("200 だが JSON 不正は bound: true で値は null", async () => {
    const binding = makeBinding(() => new Response("{not json", { status: 200 }));
    expect(await fetchVeinDbRole(veinEnv(binding))).toEqual(FAILED);
  });

  it.each<[string, unknown]>([
    ["null", null],
    ["配列", [{ current_user: "rt_role", is_runtime_role: true }]],
    ["文字列", "rt_role"],
    ["current_user 欠け", { is_runtime_role: true }],
    ["current_user が数値", { current_user: 1, is_runtime_role: true }],
    ["is_runtime_role 欠け", { current_user: "rt_role" }],
    ["is_runtime_role が文字列", { current_user: "rt_role", is_runtime_role: "true" }],
    ["is_runtime_role が null", { current_user: "rt_role", is_runtime_role: null }],
  ])("契約の型に合わない応答 (%s) は bound: true で値は null (片方だけ返さない)", async (_label, body) => {
    expect(await fetchVeinDbRole(veinEnv(jsonBinding(body)))).toEqual(FAILED);
  });
});

describe("buildVerifyRlsResult (Refs #605)", () => {
  type BackendVerdicts = NonNullable<RlsCheckResult["verdicts"]>;
  const ALL_TRUE: BackendVerdicts = { invariants: true, runtime_role: true, migrations: true, drift: true };
  const VEIN_UNBOUND: VeinDbRole = { bound: false, current_user: null, is_runtime_role: null };
  const VEIN_RT: VeinDbRole = { bound: true, current_user: "rt_role", is_runtime_role: true };
  const VEIN_OWNER: VeinDbRole = { bound: true, current_user: "owner_role", is_runtime_role: false };
  const VEIN_FAILED: VeinDbRole = { bound: true, current_user: null, is_runtime_role: null };

  function backend(ok: boolean, verdicts: BackendVerdicts | null): RlsCheckResult {
    return {
      ok,
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
      invariants: { violation_count: 0, checks: [], violations: [] },
      state: { table_count: 2 },
      verdicts,
      drift: { matches_expected: true },
    };
  }

  it("新しい backend で 5 つとも合格なら ok: true。backend の値はそのまま、workers.vein が足される", () => {
    const b = backend(true, ALL_TRUE);
    const { verdicts: _v, ...rest } = b;
    expect(buildVerifyRlsResult(b, VEIN_RT)).toEqual({
      ...rest,
      ok: true,
      verdicts: { ...ALL_TRUE, vein: true },
      workers: { vein: VEIN_RT },
    });
  });

  it("verdicts の key は 5 個ちょうど", () => {
    const res = buildVerifyRlsResult(backend(true, ALL_TRUE), VEIN_RT);
    expect(Object.keys(res.verdicts).sort()).toEqual(
      ["drift", "invariants", "migrations", "runtime_role", "vein"],
    );
    expect(Object.keys(res.workers.vein).sort()).toEqual(["bound", "current_user", "is_runtime_role"]);
  });

  it.each<keyof BackendVerdicts>(["invariants", "runtime_role", "migrations", "drift"])(
    "backend の %s だけ false なら ok: false で、verdicts のその項目だけが false",
    (key) => {
      const res = buildVerifyRlsResult(backend(false, { ...ALL_TRUE, [key]: false }), VEIN_RT);
      expect(res.ok).toBe(false);
      expect(res.verdicts).toEqual({ ...ALL_TRUE, [key]: false, vein: true });
    },
  );

  it("vein が実行用ロールでなければ、backend が全部合格でも ok: false (verdicts.vein だけ false)", () => {
    const res = buildVerifyRlsResult(backend(true, ALL_TRUE), VEIN_OWNER);
    expect(res.ok).toBe(false);
    expect(res.verdicts).toEqual({ ...ALL_TRUE, vein: false });
    expect(res.workers.vein).toEqual(VEIN_OWNER);
  });

  it("vein が bind されていなければ verdicts.vein: null で、ok に影響しない", () => {
    const res = buildVerifyRlsResult(backend(true, ALL_TRUE), VEIN_UNBOUND);
    expect(res.ok).toBe(true);
    expect(res.verdicts).toEqual({ ...ALL_TRUE, vein: null });
    expect(res.workers.vein).toEqual(VEIN_UNBOUND);

    const failing = buildVerifyRlsResult(backend(false, { ...ALL_TRUE, drift: false }), VEIN_UNBOUND);
    expect(failing.ok).toBe(false);
    expect(failing.verdicts.vein).toBeNull();
  });

  it("vein が bind されているのに呼べなければ verdicts.vein: false で ok: false (fail-closed)", () => {
    const res = buildVerifyRlsResult(backend(true, ALL_TRUE), VEIN_FAILED);
    expect(res.ok).toBe(false);
    expect(res.verdicts).toEqual({ ...ALL_TRUE, vein: false });
    expect(res.workers.vein).toEqual(VEIN_FAILED);
  });

  it("古い backend (verdicts 無し) で backend ok: true・vein 合格なら ok: true、4 つは null", () => {
    const res = buildVerifyRlsResult(backend(true, null), VEIN_RT);
    expect(res.ok).toBe(true);
    expect(res.verdicts).toEqual({
      invariants: null,
      runtime_role: null,
      migrations: null,
      drift: null,
      vein: true,
    });
  });

  it("古い backend で vein が bind されていなければ、backend の ok がそのまま ok になる", () => {
    expect(buildVerifyRlsResult(backend(true, null), VEIN_UNBOUND).ok).toBe(true);
    expect(buildVerifyRlsResult(backend(false, null), VEIN_UNBOUND).ok).toBe(false);
  });

  it("古い backend で backend ok: false なら、vein が合格でも ok: false", () => {
    expect(buildVerifyRlsResult(backend(false, null), VEIN_RT).ok).toBe(false);
  });

  it("古い backend で vein が不合格・呼べないなら ok: false", () => {
    expect(buildVerifyRlsResult(backend(true, null), VEIN_OWNER).ok).toBe(false);
    expect(buildVerifyRlsResult(backend(true, null), VEIN_FAILED).ok).toBe(false);
  });

  it("backend の ok が false なら、どの組み合わせでも tool の ok は true にならない", () => {
    const bools = [true, false];
    const verdictSets: Array<BackendVerdicts | null> = [null];
    for (const invariants of bools)
      for (const runtime_role of bools)
        for (const migrations of bools)
          for (const drift of bools) verdictSets.push({ invariants, runtime_role, migrations, drift });
    const veins = [VEIN_UNBOUND, VEIN_RT, VEIN_OWNER, VEIN_FAILED];

    let trueCount = 0;
    for (const v of verdictSets) {
      for (const vein of veins) {
        // 内訳が全部 true なのに ok: false という食い違った応答も含めて、true にならない。
        expect(buildVerifyRlsResult(backend(false, v), vein).ok).toBe(false);
        if (buildVerifyRlsResult(backend(true, v), vein).ok) trueCount++;
      }
    }
    // backend ok: true の側で true になるのは「内訳が無い or 全部 true」×「vein が未 bind or 合格」の 4 通りだけ。
    expect(trueCount).toBe(4);
  });
});
