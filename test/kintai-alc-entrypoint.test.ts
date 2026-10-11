import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv, createMockKV } from "./helpers/mock-env";
import type { Env } from "../src/index";

// OIDC の mint は別ユニットでテスト済み。ここでは RPC メソッドの flow
// (query の鍵検査 → KV 固定の tenant → 固定 path / GET で forward) を固定する。
vi.mock("../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async () => "fake-oidc-token"),
}));

import { KintaiAlcEntrypoint } from "../src/kintai-alc-entrypoint";
import { INTERNAL_ENTRYPOINT_FORWARDABLE_PATHS } from "../src/internal-entrypoint";
import { mintGoogleIdToken } from "../src/lib/oidc";

/** テスト固有のダミー UUID (本番の値ではない)。 */
const TENANT = "66666666-6666-6666-6666-666666666666";

const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

function env(kv: Record<string, string> = {}, overrides: Record<string, unknown> = {}): Env {
  return createMockEnv({
    ALC_API_PROXY_SA_KEY: "{}", // resolveSecret が非空を返せばよい (oidc は mock)
    AUTH_CONFIG: createMockKV({ "kintai-alc-tenant": TENANT, ...kv }),
    ...overrides,
  });
}

/** `[[services]] entrypoint = "KintaiAlcEntrypoint"` 越しの呼び出しを再現する。 */
function rpc(e: Env = env()): KintaiAlcEntrypoint {
  return new KintaiAlcEntrypoint({} as unknown as ExecutionContext, e);
}

function mockFetch(res: Response = new Response("{}", { status: 200 })) {
  const fetchMock = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => res,
  );
  globalThis.fetch = fetchMock as unknown as typeof fetch;
  return fetchMock;
}

type Method = "dtakoEtags" | "dtakoEvents";
const ORIGIN = "https://alc-api.test.example";

describe("KintaiAlcEntrypoint (ohishi-exp/rust-ichibanboshi#322)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.clearAllMocks(); // mock factory の vi.fn の呼び出し回数を毎回 0 に戻す
  });

  it("RPC で呼べるメソッドは dtakoEtags / dtakoEvents の 2 つだけ", () => {
    const own = Object.getOwnPropertyNames(KintaiAlcEntrypoint.prototype).filter(
      (n) => n !== "constructor",
    );
    // `forward` は TS の private (実行時は在る) — 公開の口として数えるのは 2 つ。
    expect(own.sort()).toEqual(["dtakoEtags", "dtakoEvents", "forward"]);
  });

  // ── 陽性: rust-ichibanboshi の kintai_http_repo.rs が今送っている query ──────────
  it.each<[string, Method, string, string]>([
    [
      "fetch_etags",
      "dtakoEtags",
      "date_from=2026-06-01&date_to=2026-06-30",
      "/api/dtako/events/etags",
    ],
    [
      "fetch_one (乗務員 1 人)",
      "dtakoEvents",
      "driver_cd=1234&date_from=2026-05-31&date_to=2026-07-01",
      "/api/dtako/events",
    ],
    [
      "fetch_all (1 頁目)",
      "dtakoEvents",
      "date_from=2026-05-31&date_to=2026-07-01&page_size=50",
      "/api/dtako/events",
    ],
    [
      "fetch_all (2 頁目以降)",
      "dtakoEvents",
      "date_from=2026-05-31&date_to=2026-07-01&page_size=50&after_driver_cd=1234",
      "/api/dtako/events",
    ],
  ])("%s の query は通り、固定 path を GET・KV の tenant で呼ぶ", async (_l, m, search, path) => {
    const fetchMock = mockFetch(
      new Response(JSON.stringify({ items: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const out = await rpc()[m](search);

    expect(out.status).toBe(200);
    expect(out.body).toBe(JSON.stringify({ items: [] }));
    expect(out.contentType).toBe("application/json");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe(`${ORIGIN}${path}?${search}`);
    expect((init as RequestInit).method).toBe("GET");
    expect((init as RequestInit).body).toBeUndefined();
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
    expect(h["X-Tenant-ID"]).toBe(TENANT);
  });

  it("先頭の `?` は有っても無くても同じ URL になる", async () => {
    const fetchMock = mockFetch();
    await rpc().dtakoEtags("?date_from=2026-06-01&date_to=2026-06-30");
    expect(String(fetchMock.mock.calls[0]![0])).toBe(
      `${ORIGIN}/api/dtako/events/etags?date_from=2026-06-01&date_to=2026-06-30`,
    );
  });

  it("空の query は鍵が無いので通す (必須かどうかは受け側が決める)", async () => {
    const fetchMock = mockFetch();
    await rpc().dtakoEvents("");
    expect(String(fetchMock.mock.calls[0]![0])).toBe(`${ORIGIN}/api/dtako/events`);
  });

  it("値の形は検査しない (受け側の serde に任せる)", async () => {
    const fetchMock = mockFetch();
    const out = await rpc().dtakoEvents("date_from=yesterday&page_size=99999");
    expect(out.status).toBe(200);
    expect(String(fetchMock.mock.calls[0]![0])).toBe(
      `${ORIGIN}/api/dtako/events?date_from=yesterday&page_size=99999`,
    );
  });

  it("KV の tenant 前後の空白は落とす", async () => {
    const fetchMock = mockFetch();
    await rpc(env({ "kintai-alc-tenant": `  ${TENANT}\n` })).dtakoEtags("");
    const [, init] = fetchMock.mock.calls[0]!;
    expect(((init as RequestInit).headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
  });

  // ── ★ 呼び手から path / method / tenant を変えられない ─────────────────────────
  it.each<[string, Method, string]>([
    ["query で tenant を渡す", "dtakoEvents", "tenant_id=55555555-5555-5555-5555-555555555555"],
    ["query で X-Tenant-ID を渡す", "dtakoEtags", "X-Tenant-ID=55555555-5555-5555-5555-555555555555"],
    ["path を混ぜる", "dtakoEvents", "date_from=2026-06-01&path=/api/employees"],
    ["method を混ぜる", "dtakoEvents", "method=DELETE"],
    // etags の allowlist は events より狭い
    ["etags に driver_cd", "dtakoEtags", "date_from=2026-06-01&driver_cd=1234"],
    ["etags に page_size", "dtakoEtags", "page_size=50"],
    ["値の無い鍵", "dtakoEvents", "date_from=2026-06-01&foo"],
    ["大文字違いの鍵", "dtakoEvents", "Date_From=2026-06-01"],
    ["鍵の重複", "dtakoEvents", "driver_cd=1&driver_cd=2"],
    ["鍵の重複 (etags)", "dtakoEtags", "date_from=2026-06-01&date_from=2026-07-01"],
  ])("%s → 400 で Cloud Run を呼ばない", async (_l, m, search) => {
    const fetchMock = mockFetch();
    const out = await rpc()[m](search);
    expect(out.status).toBe(400);
    expect(JSON.parse(out.body).error).toBe("query_not_allowed");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });

  it("search が文字列でなければ 400 (RPC 越しに何が来ても throw しない)", async () => {
    const fetchMock = mockFetch();
    const out = await rpc().dtakoEvents({ path: "/api/employees" } as unknown as string);
    expect(out.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("余分な引数 (tenant / path / method) を渡しても無視される (渡す手段が無い)", async () => {
    const fetchMock = mockFetch();
    const call = rpc().dtakoEtags as unknown as (...a: unknown[]) => Promise<unknown>;
    await call.call(rpc(), "date_from=2026-06-01", {
      tenantId: "55555555-5555-5555-5555-555555555555",
      path: "/api/employees",
      method: "DELETE",
    });
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe(`${ORIGIN}/api/dtako/events/etags?date_from=2026-06-01`);
    expect((init as RequestInit).method).toBe("GET");
    expect(((init as RequestInit).headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
  });

  // ── ★ fail-closed: tenant 未設定 / 不正 ───────────────────────────────────
  it.each<[string, string | undefined, Method]>([
    ["未設定", undefined, "dtakoEtags"],
    ["未設定", undefined, "dtakoEvents"],
    ["空", "", "dtakoEvents"],
    ["UUID でない", "not-a-uuid", "dtakoEvents"],
    ["UUID の前方一致", `${TENANT}x`, "dtakoEtags"],
  ])("KV の tenant が%sなら 503 で Cloud Run を呼ばない (%s / %s)", async (_l, value, m) => {
    const fetchMock = mockFetch();
    const kv = createMockKV(value === undefined ? {} : { "kintai-alc-tenant": value });
    const out = await rpc(env({}, { AUTH_CONFIG: kv }))[m]("date_from=2026-06-01");
    expect(out.status).toBe(503);
    expect(JSON.parse(out.body).error).toBe("kintai_alc_tenant_unset");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });

  it("上流のエラーはそのまま status / body を返す (throw しない)", async () => {
    mockFetch(new Response("bad date", { status: 400, headers: { "Content-Type": "text/plain" } }));
    const out = await rpc().dtakoEvents("date_from=x");
    expect(out).toEqual({ status: 400, body: "bad date", contentType: "text/plain" });
  });

  it("★ InternalEntrypoint の FORWARDABLE_PATHS は 6 本のまま、events 本体を含まない", () => {
    expect([...INTERNAL_ENTRYPOINT_FORWARDABLE_PATHS].sort()).toEqual(
      [
        "/api/scraper/history",
        "/api/dtako/events/etags",
        "/api/employees/bulk-by-code",
        "/api/dtako-logs/bulk",
        "/api/timecard/cards/bulk-by-code",
        "/api/timecard/cards/delete-by-card",
      ].sort(),
    );
    expect(INTERNAL_ENTRYPOINT_FORWARDABLE_PATHS.has("/api/dtako/events")).toBe(false);
  });
});
