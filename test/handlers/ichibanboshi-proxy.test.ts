import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

// OIDC mint は別ユニットでテスト済み。ここでは handler の flow
// (consumer proof → path/method allowlist → tenant 必須 → OIDC mint → forward) を固定する。
vi.mock("../../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async () => "fake-oidc-token"),
}));

import { handleIchibanboshiProxy } from "../../src/handlers/ichibanboshi-proxy";

const PROXY_SECRET = "test-internal-shared-secret-32!!";
const TENANT = "11111111-1111-1111-1111-111111111111";
const ORIGIN = "https://rust-ichibanboshi.test.example";
const TIMECARD = "/ichibanboshi-proxy/api/kintai/timecard";
const SIGNATURES = "/ichibanboshi-proxy/api/kintai/timecard/signatures";
const WINDOW = "/ichibanboshi-proxy/api/kintai/timecard/window";
const RECALC = "/ichibanboshi-proxy/api/kintai/recalc";

const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

function env(overrides: Record<string, unknown> = {}) {
  return createMockEnv({
    ICHIBANBOSHI_ORIGIN: ORIGIN,
    ICHIBANBOSHI_PROXY_SA_KEY: "{}", // resolveSecret が非空を返せばよい (oidc は mock)
    INTERNAL_SHARED_SECRET: PROXY_SECRET,
    ...overrides,
  });
}

function req(
  path: string,
  init: RequestInit & { proxySecret?: string | null; tenant?: string | null } = {},
) {
  const headers: Record<string, string> = {};
  if (init.proxySecret !== null) headers["X-Alc-Proxy-Secret"] = init.proxySecret ?? PROXY_SECRET;
  if (init.tenant !== null) headers["X-Tenant-ID"] = init.tenant ?? TENANT;
  return new Request(`https://auth.test.example${path}`, {
    method: init.method ?? "GET",
    headers: { ...headers, ...(init.headers as Record<string, string>) },
    body: init.body,
  });
}

/** forward 先を捕まえるための fetch stub。 */
function captureFetch() {
  const seen: { url: string; init: RequestInit }[] = [];
  globalThis.fetch = vi.fn(async (url: unknown, init: unknown) => {
    seen.push({ url: String(url), init: (init ?? {}) as RequestInit });
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;
  return seen;
}

describe("handleIchibanboshiProxy (ohishi-exp/rust-ichibanboshi#205 の 04b)", () => {
  beforeEach(() => vi.restoreAllMocks());

  // ── ① consumer worker proof ──────────────────────────────────────────────
  it("X-Alc-Proxy-Secret が無ければ 401", async () => {
    const res = await handleIchibanboshiProxy(req(SIGNATURES, { proxySecret: null }), env());
    expect(res.status).toBe(401);
  });

  it("X-Alc-Proxy-Secret が違えば 401", async () => {
    const res = await handleIchibanboshiProxy(req(SIGNATURES, { proxySecret: "nope" }), env());
    expect(res.status).toBe(401);
  });

  // ── env guard (fail-closed) ───────────────────────────────────────────────
  it("SA key / origin が未設定なら 503", async () => {
    const noKey = await handleIchibanboshiProxy(
      req(SIGNATURES),
      env({ ICHIBANBOSHI_PROXY_SA_KEY: undefined }),
    );
    expect(noKey.status).toBe(503);

    const noOrigin = await handleIchibanboshiProxy(
      req(SIGNATURES),
      env({ ICHIBANBOSHI_ORIGIN: undefined }),
    );
    expect(noOrigin.status).toBe(503);
  });

  // ── ② path + method allowlist ─────────────────────────────────────────────
  it("**読み出し経路は通さない。** 打刻の口以外は 403", async () => {
    for (const p of [
      "/ichibanboshi-proxy/api/kintai/daily",
      "/ichibanboshi-proxy/api/kintai/kosoku-daily",
      "/ichibanboshi-proxy/api/uriage/by-person",
      "/ichibanboshi-proxy/health",
      "/ichibanboshi-proxy/",
    ]) {
      const res = await handleIchibanboshiProxy(req(p), env());
      expect(res.status, p).toBe(403);
    }
  });

  it("**窓ぶんの受け口 (POST) を通す。** GCP への往復はこれ 1 本", async () => {
    const seen = captureFetch();
    const body = JSON.stringify({ months: ["2026-05", "2026-06"], drivers: [1130], events: [] });
    const res = await handleIchibanboshiProxy(
      req(WINDOW, { method: "POST", body, headers: { "content-type": "application/json" } }),
      env(),
    );
    expect(res.status).toBe(200);
    expect(seen[0]!.url).toBe(`${ORIGIN}/api/kintai/timecard/window`);
    expect(new TextDecoder().decode(seen[0]!.init.body as ArrayBuffer)).toBe(body);

    // 読み出しに化けさせない — GET は通さない
    const asGet = await handleIchibanboshiProxy(req(WINDOW, { method: "GET" }), env());
    expect(asGet.status).toBe(403);
  });

  it("**全量再計算は GET (preview) と POST (書ける方) の両方を通す**", async () => {
    const seen = captureFetch();
    const preview = await handleIchibanboshiProxy(
      req(`${RECALC}?month=2026-07&after_driver_cd=1130&stale_only=true`),
      env(),
    );
    expect(preview.status).toBe(200);
    expect(seen[0]!.url).toBe(
      `${ORIGIN}/api/kintai/recalc?month=2026-07&after_driver_cd=1130&stale_only=true`,
    );

    const body = JSON.stringify({ month: "2026-07", apply: true });
    const applied = await handleIchibanboshiProxy(
      req(RECALC, { method: "POST", body, headers: { "content-type": "application/json" } }),
      env(),
    );
    expect(applied.status).toBe(200);
    expect(seen[1]!.url).toBe(`${ORIGIN}/api/kintai/recalc`);
    expect(seen[1]!.init.method).toBe("POST");
    // `apply` は body にしか無い — 素通しできていないと全量再計算が起動しない
    expect(new TextDecoder().decode(seen[1]!.init.body as ArrayBuffer)).toBe(body);
  });

  it("全量再計算も登録した 2 method 以外は 403 (PUT / DELETE)", async () => {
    for (const method of ["PUT", "DELETE", "PATCH"]) {
      const res = await handleIchibanboshiProxy(req(RECALC, { method }), env());
      expect(res.status, method).toBe(403);
    }
  });

  it("prefix 一致では通さない (allowlist は完全一致)", async () => {
    for (const p of [
      "/ichibanboshi-proxy/api/kintai/timecard/other",
      // 未登録。`recalc` が通るからといって下位 path が開くわけではない
      "/ichibanboshi-proxy/api/kintai/recalc/apply",
      "/ichibanboshi-proxy/api/kintai/recalc2",
    ]) {
      const res = await handleIchibanboshiProxy(req(p), env());
      expect(res.status, p).toBe(403);
    }
  });

  it("method が違えば 403 (受け口は POST、署名は GET)", async () => {
    const getTimecard = await handleIchibanboshiProxy(req(TIMECARD, { method: "GET" }), env());
    expect(getTimecard.status).toBe(403);

    const postSignatures = await handleIchibanboshiProxy(
      req(SIGNATURES, { method: "POST" }),
      env(),
    );
    expect(postSignatures.status).toBe(403);
  });

  it("percent-encoding / .. / バックスラッシュを含む path は 403", async () => {
    for (const p of [
      "/ichibanboshi-proxy/api/kintai/%2e%2e/uriage",
      "/ichibanboshi-proxy/api/kintai/../uriage",
      "/ichibanboshi-proxy/api\\kintai",
    ]) {
      const res = await handleIchibanboshiProxy(req(p), env());
      expect(res.status, p).toBe(403);
    }
  });

  // ── ③ tenant ──────────────────────────────────────────────────────────────
  it("X-Tenant-ID が無ければ 400 — 名乗らないまま Cloud Run を叩かせない", async () => {
    const seen = captureFetch();
    const res = await handleIchibanboshiProxy(req(SIGNATURES, { tenant: null }), env());
    expect(res.status).toBe(400);
    expect(seen).toHaveLength(0);
  });

  it("空白だけの X-Tenant-ID も「名乗っていない」扱い", async () => {
    const res = await handleIchibanboshiProxy(req(SIGNATURES, { tenant: "   " }), env());
    expect(res.status).toBe(400);
  });

  // ── ④⑤ mint + forward ────────────────────────────────────────────────────
  it("署名の GET は query ごと forward され、OIDC と tenant が乗る", async () => {
    const seen = captureFetch();
    const res = await handleIchibanboshiProxy(
      req(`${SIGNATURES}?month=2026-07&driver_cd=1130`),
      env(),
    );
    expect(res.status).toBe(200);
    expect(seen).toHaveLength(1);
    expect(seen[0]!.url).toBe(
      `${ORIGIN}/api/kintai/timecard/signatures?month=2026-07&driver_cd=1130`,
    );
    const h = seen[0]!.init.headers as Record<string, string>;
    expect(h.Authorization).toBe("Bearer fake-oidc-token");
    expect(h["X-Tenant-ID"]).toBe(TENANT);
  });

  it("打刻の POST は body ごと forward される", async () => {
    const seen = captureFetch();
    const body = JSON.stringify({ month: "2026-07", driver_cd: 1130 });
    const res = await handleIchibanboshiProxy(
      req(TIMECARD, {
        method: "POST",
        body,
        headers: { "content-type": "application/json" },
      }),
      env(),
    );
    expect(res.status).toBe(200);
    expect(seen).toHaveLength(1);
    expect(seen[0]!.url).toBe(`${ORIGIN}/api/kintai/timecard`);
    expect(seen[0]!.init.method).toBe("POST");
    const h = seen[0]!.init.headers as Record<string, string>;
    expect(h["Content-Type"]).toBe("application/json");
    expect(new TextDecoder().decode(seen[0]!.init.body as ArrayBuffer)).toBe(body);
  });

  it("**caller の Authorization は forward しない** — transport は OIDC に差し替える", async () => {
    const seen = captureFetch();
    await handleIchibanboshiProxy(
      req(SIGNATURES, { headers: { Authorization: "Bearer caller-token" } }),
      env(),
    );
    const h = seen[0]!.init.headers as Record<string, string>;
    expect(h.Authorization).toBe("Bearer fake-oidc-token");
  });

  it("origin の末尾スラッシュは二重にならない", async () => {
    const seen = captureFetch();
    await handleIchibanboshiProxy(req(SIGNATURES), env({ ICHIBANBOSHI_ORIGIN: `${ORIGIN}/` }));
    expect(seen[0]!.url).toBe(`${ORIGIN}/api/kintai/timecard/signatures`);
  });

  it("OIDC mint に失敗したら 502 (呼び出し側の 4xx と混ぜない)", async () => {
    const oidc = await import("../../src/lib/oidc");
    vi.mocked(oidc.mintGoogleIdToken).mockRejectedValueOnce(new Error("boom"));
    const seen = captureFetch();
    const res = await handleIchibanboshiProxy(req(SIGNATURES), env());
    expect(res.status).toBe(502);
    expect(seen).toHaveLength(0);
  });
});
