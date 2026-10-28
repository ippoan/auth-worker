import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv } from "./helpers/mock-env";
import type { Env } from "../src/index";

// OIDC の mint は別ユニットでテスト済み。ここでは RPC メソッドの flow
// (入力の検査 → env guard → aud = ALC_REDACT_ORIGIN で mint → 固定 path に POST → 応答の詰め替え) を固定する。
vi.mock("../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async () => "fake-oidc-token"),
}));

import { AlcRedactEntrypoint } from "../src/alc-redact-entrypoint";
import { mintGoogleIdToken } from "../src/lib/oidc";

const ORIGIN = "https://alc-redact.test.example";
const PDF = new TextEncoder().encode("%PDF-1.5 fake").buffer as ArrayBuffer;

const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

function env(overrides: Record<string, unknown> = {}): Env {
  return createMockEnv({
    ALC_API_PROXY_SA_KEY: "{}", // resolveSecret が非空を返せばよい (oidc は mock)
    ALC_REDACT_ORIGIN: ORIGIN,
    ...overrides,
  });
}

/** `[[services]] entrypoint = "AlcRedactEntrypoint"` 越しの呼び出しを再現する。 */
function rpc(e: Env = env()): AlcRedactEntrypoint {
  return new AlcRedactEntrypoint({} as unknown as ExecutionContext, e);
}

function mockFetch(res: Response | Error = new Response("{}", { status: 200 })) {
  const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => {
    if (res instanceof Error) throw res;
    return res;
  });
  globalThis.fetch = fetchMock as unknown as typeof fetch;
  return fetchMock;
}

function text(buf: ArrayBuffer): string {
  return new TextDecoder().decode(buf);
}

describe("AlcRedactEntrypoint (ippoan/rust-alc-api#680 W8c-2)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.clearAllMocks();
  });

  it("RPC で呼べるメソッドは redact / extract の 2 つだけ", () => {
    const own = Object.getOwnPropertyNames(AlcRedactEntrypoint.prototype).filter(
      (n) => n !== "constructor",
    );
    // `post` は TS の private (実行時は在る) — 公開の口として数えるのは 2 つ。
    expect(own.sort()).toEqual(["extract", "post", "redact"]);
  });

  it("redact: aud = ALC_REDACT_ORIGIN で mint し、/redact に PDF を POST、JPEG と計測のヘッダーを返す", async () => {
    const jpeg = new Uint8Array([0xff, 0xd8, 0xff, 0x00]);
    const fetchMock = mockFetch(
      new Response(jpeg, {
        status: 200,
        headers: {
          "Content-Type": "image/jpeg",
          "X-Redactions-Applied": "2",
          "X-Redact-Llm-Ms": "10",
          "X-Redact-Render-Ms": "20",
          "X-Redact-Total-Ms": "35",
          "X-Other": "dropped",
        },
      }),
    );
    const r = await rpc(env({ ALC_REDACT_ORIGIN: `${ORIGIN}/` })).redact(PDF);

    expect(mintGoogleIdToken).toHaveBeenCalledWith("{}", `${ORIGIN}/`);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`${ORIGIN}/redact`);
    expect(init?.method).toBe("POST");
    const h = init?.headers as Record<string, string>;
    expect(h.Authorization).toBe("Bearer fake-oidc-token");
    expect(h["Content-Type"]).toBe("application/pdf");
    expect(h["X-Self-Company"]).toBeUndefined();
    expect(init?.body).toBe(PDF);

    expect(r.status).toBe(200);
    expect(r.contentType).toBe("image/jpeg");
    expect(new Uint8Array(r.body)).toEqual(jpeg);
    expect(r.headers).toEqual({
      "x-redactions-applied": "2",
      "x-redact-llm-ms": "10",
      "x-redact-render-ms": "20",
      "x-redact-total-ms": "35",
    });
  });

  it("extract: 自社名を percent-encode して X-Self-Company に載せ、/extract の JSON をそのまま返す", async () => {
    const fetchMock = mockFetch(
      new Response(JSON.stringify({ logistics: { loading_place: "A" } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const r = await rpc().extract(PDF, " テスト運輸 ");

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`${ORIGIN}/extract`);
    const h = init?.headers as Record<string, string>;
    expect(h["X-Self-Company"]).toBe(encodeURIComponent("テスト運輸"));
    expect(r.status).toBe(200);
    expect(JSON.parse(text(r.body))).toEqual({ logistics: { loading_place: "A" } });
    expect(r.headers).toEqual({});
  });

  it.each([
    ["空", ""],
    ["空白だけ", "   "],
    ["文字列でない", 123 as unknown as string],
  ])("extract: 自社名が %s ならヘッダーを付けない", async (_label, selfCompany) => {
    const fetchMock = mockFetch();
    await rpc().extract(PDF, selfCompany);
    const h = fetchMock.mock.calls[0]![1]?.headers as Record<string, string>;
    expect(h["X-Self-Company"]).toBeUndefined();
  });

  it("Uint8Array も受け、view の範囲だけ送る", async () => {
    const fetchMock = mockFetch();
    const whole = new TextEncoder().encode("xx%PDF-1.5yy");
    await rpc().redact(whole.subarray(2, 10) as unknown as ArrayBuffer);
    expect(text(fetchMock.mock.calls[0]![1]?.body as ArrayBuffer)).toBe("%PDF-1.5");
  });

  it("PDF が ArrayBuffer でない → 400 bad_request (Cloud Run を呼ばない)", async () => {
    const fetchMock = mockFetch();
    const r = await rpc().redact("not a buffer" as unknown as ArrayBuffer);
    expect(r.status).toBe(400);
    expect(JSON.parse(text(r.body))).toEqual({ error: "bad_request" });
    expect(r.contentType).toBe("application/json");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ["SA key が無い", { ALC_API_PROXY_SA_KEY: undefined }],
    ["ALC_REDACT_ORIGIN が無い", { ALC_REDACT_ORIGIN: undefined }],
  ])("%s → 503 redact_unconfigured (fail-closed)", async (_label, overrides) => {
    const fetchMock = mockFetch();
    const r = await rpc(env(overrides)).extract(PDF, "x");
    expect(r.status).toBe(503);
    expect(JSON.parse(text(r.body))).toEqual({ error: "redact_unconfigured" });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });

  it("mint の失敗 → 502 upstream_auth", async () => {
    vi.mocked(mintGoogleIdToken).mockRejectedValueOnce(new Error("secret detail"));
    const fetchMock = mockFetch();
    const r = await rpc().redact(PDF);
    expect(r.status).toBe(502);
    expect(text(r.body)).toBe(JSON.stringify({ error: "upstream_auth" }));
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("fetch の例外 → 502 upstream_unreachable", async () => {
    mockFetch(new Error("network"));
    const r = await rpc().redact(PDF);
    expect(r.status).toBe(502);
    expect(JSON.parse(text(r.body))).toEqual({ error: "upstream_unreachable" });
  });

  it("alc-redact のエラーは status と body をそのまま返す (呼び手がコードで見分ける)", async () => {
    const body = JSON.stringify({ error: "not_pdf", detail: "body does not start with %PDF-" });
    mockFetch(new Response(body, { status: 415, headers: { "Content-Type": "application/json" } }));
    const r = await rpc().extract(PDF, "");
    expect(r.status).toBe(415);
    expect(text(r.body)).toBe(body);
    expect(r.contentType).toBe("application/json");
  });
});
