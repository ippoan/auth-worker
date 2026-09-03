import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv } from "./helpers/mock-env";
import type { Env } from "../src/index";

// OIDC mint は別ユニットでテスト済み。ここでは RPC メソッドの flow
// (tenant guard → path allowlist → OIDC mint → forward) を固定する。
vi.mock("../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async () => "fake-oidc-token"),
}));

import { InternalEntrypoint } from "../src/internal-entrypoint";

const TENANT = "11111111-1111-1111-1111-111111111111";

const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

function env(overrides: Record<string, unknown> = {}): Env {
  return createMockEnv({
    ALC_API_PROXY_SA_KEY: "{}", // resolveSecret が非空を返せばよい (oidc は mock)
    ...overrides,
  });
}

/** `[[services]] entrypoint = "InternalEntrypoint"` 越しの呼び出しを再現する。 */
function rpc(overrides: Record<string, unknown> = {}): InternalEntrypoint {
  return new InternalEntrypoint(
    {} as unknown as ExecutionContext,
    env(overrides),
  );
}

function mockFetch(res: Response = new Response("ok", { status: 200 })) {
  const fetchMock = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => res,
  );
  globalThis.fetch = fetchMock as unknown as typeof fetch;
  return fetchMock;
}

describe("InternalEntrypoint#forwardAlcTenantData (issue #483)", () => {
  beforeEach(() => vi.restoreAllMocks());

  // ── ★ 受け入れ条件: allowlist 外は「転送されない」──────────────────────────
  it("allowlist 外の path は転送せず 403 (fetch を一切呼ばない)", async () => {
    const fetchMock = mockFetch();
    const out = await rpc().forwardAlcTenantData({
      tenantId: TENANT,
      path: "/api/employees",
      method: "GET",
    });
    expect(out.status).toBe(403);
    // ★ ここが肝 — status だけでなく **forward 先の fetch が呼ばれていないこと**まで見る
    // (OIDC mint も含めて 1 回も外に出ない)。
    expect(fetchMock).not.toHaveBeenCalled();
    // 上流 (rust-alc-api) の tenant 拒否も `403 {"error":"forbidden"}` なので、
    // allowlist が出した 403 は**本文だけで断定できる**固有語にする。
    expect(JSON.parse(out.body).error).toBe("path_not_forwardable");
  });

  it("path が空でも 403 (デフォルト拒否、転送しない)", async () => {
    const fetchMock = mockFetch();
    const out = await rpc().forwardAlcTenantData({
      tenantId: TENANT,
      path: "",
      method: "GET",
    });
    expect(out.status).toBe(403);
    expect(JSON.parse(out.body).error).toBe("path_not_forwardable");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("allowlist の prefix 一致では通さない (前方一致で穴を開けない)", async () => {
    const fetchMock = mockFetch();
    const out = await rpc().forwardAlcTenantData({
      tenantId: TENANT,
      path: "/api/scraper/history/../../api/employees",
      method: "GET",
    });
    expect(out.status).toBe(403);
    expect(JSON.parse(out.body).error).toBe("path_not_forwardable");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("allowlist の 403 は上流/device-data-proxy の 403 と本文で区別できる (#933 の診断で混ざった)", async () => {
    mockFetch();
    const out = await rpc().forwardAlcTenantData({
      tenantId: TENANT,
      path: "/api/employees",
      method: "GET",
    });
    // `device-data-proxy.ts` の role/path 拒否と rust-alc-api の tenant 拒否は
    // どちらも `{"error":"forbidden"}`。揃えると呼び手のログで
    // 「呼び手が path を間違えた」と「上流が tenant を拒否した」が区別できなくなる。
    expect(out.body).not.toContain("forbidden");
    expect(out.body).toBe(JSON.stringify({ error: "path_not_forwardable" }));
  });

  // ── ★ 受け入れ条件: tenantId 空 ────────────────────────────────────────────
  it("tenantId が空なら 400 (allowlist 内の path でも転送しない)", async () => {
    const fetchMock = mockFetch();
    const out = await rpc().forwardAlcTenantData({
      tenantId: "",
      path: "/api/scraper/history",
      method: "GET",
    });
    expect(out.status).toBe(400);
    expect(JSON.parse(out.body).error).toBe("tenant_id required");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  // ── ★ 受け入れ条件: allowlist 内は X-Tenant-ID 付きで forward ───────────────
  it("正常 (GET): OIDC Bearer + 引数の X-Tenant-ID を付けて forward し、search を引き継ぐ", async () => {
    const fetchMock = mockFetch(
      new Response(JSON.stringify([{ id: 1 }]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const out = await rpc().forwardAlcTenantData({
      tenantId: TENANT,
      path: "/api/scraper/history",
      method: "GET",
      search: "?limit=20",
    });

    expect(out.status).toBe(200);
    expect(out.body).toBe(JSON.stringify([{ id: 1 }]));
    expect(out.contentType).toBe("application/json");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/scraper/history?limit=20");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
    expect(h["X-Tenant-ID"]).toBe(TENANT);
    expect((init as RequestInit).method).toBe("GET");
    // GET は body を付けない (workerd が TypeError にする)。
    expect((init as RequestInit).body).toBeUndefined();
  });

  it("正常 (POST): body / contentType を引き継いで forward する (#931 の無人実行を履歴に載せる経路)", async () => {
    const fetchMock = mockFetch(new Response(null, { status: 201 }));

    const out = await rpc().forwardAlcTenantData({
      tenantId: TENANT,
      path: "/api/scraper/history",
      method: "POST",
      body: JSON.stringify({ status: "ok" }),
      contentType: "application/json",
    });

    expect(out.status).toBe(201);
    expect(out.body).toBe("");
    // content-type ヘッダーが無い応答は null をそのまま返す (捏造しない)。
    expect(out.contentType).toBeNull();

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/scraper/history");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBe(TENANT);
    expect(h["Content-Type"]).toBe("application/json");
    expect((init as RequestInit).method).toBe("POST");
    expect((init as RequestInit).body).toBe(JSON.stringify({ status: "ok" }));
  });

  it("もう 1 本の allowlist path (/api/dtako/events/etags) も通る", async () => {
    const fetchMock = mockFetch();
    const out = await rpc().forwardAlcTenantData({
      tenantId: TENANT,
      path: "/api/dtako/events/etags",
      method: "GET",
    });
    expect(out.status).toBe(200);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/dtako/events/etags");
    expect(((init as RequestInit).headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
  });

  it("乗務員マスタ同期の PUT (/api/employees/bulk-by-code) が body 付きで通る (alc-app-s3#125)", async () => {
    const fetchMock = mockFetch(
      new Response(JSON.stringify({ created: 3, updated: 500, skipped: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const body = JSON.stringify({ items: [{ code: "1078", name: "-", nfc_id: "2024010120290131" }] });

    const out = await rpc().forwardAlcTenantData({
      tenantId: TENANT,
      path: "/api/employees/bulk-by-code",
      method: "PUT",
      body,
      contentType: "application/json",
    });

    expect(out.status).toBe(200);
    expect(JSON.parse(out.body).updated).toBe(500);

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/employees/bulk-by-code");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBe(TENANT);
    expect((init as RequestInit).method).toBe("PUT");
    // ★ 書き込み経路なので body が落ちていないことまで見る (落ちると
    // rust-alc-api 側が 400 「items が不正です」になり、原因が allowlist から遠くなる)。
    expect((init as RequestInit).body).toBe(body);
  });

  it("車輌動態の POST (/api/dtako-logs/bulk) が body 付きで通る (nuxt-dtako-admin#1098)", async () => {
    const fetchMock = mockFetch(
      new Response(
        JSON.stringify({ success: true, records_added: 199, total_records: 199, message: "" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    // relay が送るのは theearth の生レコード配列 (DataDateTime だけ RFC3339 に直したもの)。
    const body = JSON.stringify([
      { VehicleCD: 2131, DataDateTime: "2026-09-03T07:20:00+09:00", GPSLatitude: 34733210 },
    ]);

    const out = await rpc().forwardAlcTenantData({
      tenantId: TENANT,
      path: "/api/dtako-logs/bulk",
      method: "POST",
      body,
      contentType: "application/json",
    });

    expect(out.status).toBe(200);
    expect(JSON.parse(out.body).records_added).toBe(199);

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/dtako-logs/bulk");
    const h = (init as RequestInit).headers as Record<string, string>;
    // 上流は `require_tenant_header` (data 経路) なので、注入した X-Tenant-ID が
    // 唯一の identity になる。
    expect(h["X-Tenant-ID"]).toBe(TENANT);
    expect((init as RequestInit).method).toBe("POST");
    // ★ 書き込み経路なので body が落ちていないことまで見る (落ちると上流が
    // 「No records provided」で 200 + records_added:0 を返し、**成功に見えたまま
    // 1 件も入らない**。原因が allowlist から遠くなる = bulk-by-code と同じ理由)。
    expect((init as RequestInit).body).toBe(body);
  });

  it("★ dtako-logs/bulk を足しても兄弟の path は通らない (完全一致のまま)", async () => {
    // ★ 陰性対照 — 1 行足したことで前方一致や近い名前まで開いていないこと。
    const fetchMock = mockFetch();
    for (const path of [
      "/api/dtako-logs",
      "/api/dtako-logs/bulk/",
      "/api/dtako-logs/current",
      "/api/dtako-logs/by-date",
      "/api/dtako-logs/bulk/../current",
    ]) {
      const out = await rpc().forwardAlcTenantData({ tenantId: TENANT, path, method: "POST" });
      expect(out.status).toBe(403);
      expect(JSON.parse(out.body).error).toBe("path_not_forwardable");
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("bulk-by-code を足しても親の /api/employees は通らない (完全一致のまま)", async () => {
    const fetchMock = mockFetch();
    for (const path of ["/api/employees", "/api/employees/bulk-by-code/", "/api/employees/1"]) {
      const out = await rpc().forwardAlcTenantData({ tenantId: TENANT, path, method: "PUT" });
      expect(out.status).toBe(403);
      expect(JSON.parse(out.body).error).toBe("path_not_forwardable");
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("search の先頭 `?` は有っても無くても良い / method は大文字化する", async () => {
    const fetchMock = mockFetch();
    await rpc().forwardAlcTenantData({
      tenantId: TENANT,
      path: "/api/scraper/history",
      method: "get",
      search: "limit=5",
    });
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/scraper/history?limit=5");
    expect((init as RequestInit).method).toBe("GET");
  });

  it("method 未指定は GET 扱い / ALC_API_ORIGIN 末尾の / は重複させない", async () => {
    const fetchMock = mockFetch();
    const ep = new InternalEntrypoint(
      {} as unknown as ExecutionContext,
      env({ ALC_API_ORIGIN: "https://alc-api.test.example/" }),
    );
    await ep.forwardAlcTenantData({
      tenantId: TENANT,
      path: "/api/scraper/history",
      method: "",
    });
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/scraper/history");
    expect((init as RequestInit).method).toBe("GET");
  });

  it("HEAD も body を付けない", async () => {
    const fetchMock = mockFetch();
    await rpc().forwardAlcTenantData({
      tenantId: TENANT,
      path: "/api/scraper/history",
      method: "HEAD",
      body: "ignored",
    });
    expect((fetchMock.mock.calls[0]![1] as RequestInit).body).toBeUndefined();
  });

  // ── env guard / upstream 失敗 ─────────────────────────────────────────────
  it("ALC_API_PROXY_SA_KEY 未設定は 503 (fail-closed、転送しない)", async () => {
    const fetchMock = mockFetch();
    const ep = new InternalEntrypoint(
      {} as unknown as ExecutionContext,
      env({ ALC_API_PROXY_SA_KEY: undefined }),
    );
    const out = await ep.forwardAlcTenantData({
      tenantId: TENANT,
      path: "/api/scraper/history",
      method: "GET",
    });
    expect(out.status).toBe(503);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("ALC_API_ORIGIN 未設定は 503 (fail-closed、転送しない)", async () => {
    const fetchMock = mockFetch();
    const ep = new InternalEntrypoint(
      {} as unknown as ExecutionContext,
      env({ ALC_API_ORIGIN: undefined }),
    );
    const out = await ep.forwardAlcTenantData({
      tenantId: TENANT,
      path: "/api/scraper/history",
      method: "GET",
    });
    expect(out.status).toBe(503);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("OIDC mint 失敗は 502 (詳細は出さない、転送もしない)", async () => {
    const fetchMock = mockFetch();
    const { mintGoogleIdToken } = await import("../src/lib/oidc");
    (mintGoogleIdToken as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("boom"),
    );
    const out = await rpc().forwardAlcTenantData({
      tenantId: TENANT,
      path: "/api/scraper/history",
      method: "GET",
    });
    expect(out.status).toBe(502);
    expect(out.body).not.toContain("boom");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("戻り値は Response ではなく素の serializable オブジェクト (RPC 越しに渡せる形)", async () => {
    mockFetch();
    const out = await rpc().forwardAlcTenantData({
      tenantId: TENANT,
      path: "/api/scraper/history",
      method: "GET",
    });
    expect(out).not.toBeInstanceOf(Response);
    expect(JSON.parse(JSON.stringify(out))).toEqual(out);
    expect(Object.keys(out).sort()).toEqual(["body", "contentType", "status"]);
  });
});
