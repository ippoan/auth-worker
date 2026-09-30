import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv, createMockKV } from "./helpers/mock-env";
import type { Env } from "../src/index";

// OIDC / internal JWT の mint は別ユニットでテスト済み。ここでは RPC メソッドの flow
// (入力検査 → KV 固定の tenant / 宛先 → forward) を固定する。
vi.mock("../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async () => "fake-oidc-token"),
}));
vi.mock("../src/lib/alc-internal", () => ({
  internalAuthToken: vi.fn(async () => "fake-internal-jwt"),
}));

import { SmbIngestEntrypoint } from "../src/smb-ingest-entrypoint";
import { mintGoogleIdToken } from "../src/lib/oidc";
import { internalAuthToken } from "../src/lib/alc-internal";

/** テスト固有のダミー UUID (本番の値ではない)。 */
const TENANT = "33333333-3333-3333-3333-333333333333";
const RECIPIENT = "44444444-4444-4444-4444-444444444444";

const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

function env(kv: Record<string, string> = {}, overrides: Record<string, unknown> = {}): Env {
  return createMockEnv({
    ALC_API_PROXY_SA_KEY: "{}", // resolveSecret が非空を返せばよい (oidc は mock)
    AUTH_CONFIG: createMockKV({
      "smb-ingest-tenant": TENANT,
      "device-notify-targets": JSON.stringify({ "smb-ingest": RECIPIENT }),
      ...kv,
    }),
    ...overrides,
  });
}

/** `[[services]] entrypoint = "SmbIngestEntrypoint"` 越しの呼び出しを再現する。 */
function rpc(e: Env = env()): SmbIngestEntrypoint {
  return new SmbIngestEntrypoint({} as unknown as ExecutionContext, e);
}

function mockFetch(res: Response = new Response("ok", { status: 200 })) {
  const fetchMock = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => res,
  );
  globalThis.fetch = fetchMock as unknown as typeof fetch;
  return fetchMock;
}

const FILE = { filename: "shaken.pdf", contentType: "application/pdf", contentBase64: "JVBERi0=" };

describe("SmbIngestEntrypoint#ingestFile (ohishi-exp/smb-watch#14)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.clearAllMocks(); // mock factory の vi.fn の呼び出し回数を毎回 0 に戻す
  });

  it("正常: 常に POST <origin>/api/files を KV の X-Tenant-ID と OIDC Bearer 付きで呼ぶ", async () => {
    const fetchMock = mockFetch(
      new Response(JSON.stringify({ uuid: "f" }), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const out = await rpc().ingestFile(FILE);

    expect(out.status).toBe(201);
    expect(JSON.parse(out.body).uuid).toBe("f");
    expect(out.contentType).toBe("application/json");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/files");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-oidc-token");
    expect(h["X-Tenant-ID"]).toBe(TENANT);
    expect(h["Content-Type"]).toBe("application/json");
    expect((init as RequestInit).method).toBe("POST");
    // rust 側 `CreateFileRequest` の形 (`type` / `content` は rename 済みの名前)。
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      filename: "shaken.pdf",
      type: "application/pdf",
      content: "JVBERi0=",
    });
  });

  it("★ 呼び手が tenant / path / method を紛れ込ませても無視される (渡す手段が無い)", async () => {
    const fetchMock = mockFetch();
    await rpc().ingestFile({
      ...FILE,
      tenantId: "55555555-5555-5555-5555-555555555555",
      path: "/api/employees",
      method: "DELETE",
    } as unknown as typeof FILE);

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/files");
    expect((init as RequestInit).method).toBe("POST");
    expect(((init as RequestInit).headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
  });

  it("KV の tenant 前後の空白は落とす", async () => {
    const fetchMock = mockFetch();
    await rpc(env({ "smb-ingest-tenant": `  ${TENANT}\n` })).ingestFile(FILE);
    const [, init] = fetchMock.mock.calls[0]!;
    expect(((init as RequestInit).headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT);
  });

  // ── ★ fail-closed: tenant 未設定 / 不正 ───────────────────────────────────
  it.each([
    ["未設定", undefined],
    ["空", ""],
    ["UUID でない", "not-a-uuid"],
    ["UUID の前方一致", `${TENANT}x`],
  ])("KV の tenant が%sなら 503 で Cloud Run を呼ばない", async (_label, value) => {
    const fetchMock = mockFetch();
    const kv = createMockKV({
      "device-notify-targets": JSON.stringify({ "smb-ingest": RECIPIENT }),
      ...(value === undefined ? {} : { "smb-ingest-tenant": value }),
    });
    const out = await rpc(env({}, { AUTH_CONFIG: kv })).ingestFile(FILE);
    expect(out.status).toBe(503);
    expect(JSON.parse(out.body).error).toBe("smb_ingest_tenant_unset");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });

  // ── ★ サイズ上限 ───────────────────────────────────────────────────────────
  it("contentBase64 が 16 MiB 超なら 413 で Cloud Run を呼ばない", async () => {
    const fetchMock = mockFetch();
    const out = await rpc().ingestFile({
      ...FILE,
      contentBase64: "A".repeat(16 * 1024 * 1024 + 1),
    });
    expect(out.status).toBe(413);
    expect(JSON.parse(out.body).error).toBe("payload_too_large");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("ちょうど 16 MiB は通す (境界)", async () => {
    const fetchMock = mockFetch();
    const out = await rpc().ingestFile({ ...FILE, contentBase64: "A".repeat(16 * 1024 * 1024) });
    expect(out.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["filename", { ...FILE, filename: "" }, "filename required"],
    ["contentType", { ...FILE, contentType: "" }, "contentType required"],
    ["contentBase64", { ...FILE, contentBase64: "" }, "contentBase64 required"],
    ["contentBase64 (非文字列)", { ...FILE, contentBase64: 1 }, "contentBase64 required"],
  ])("%s が欠けていたら 400 で呼ばない", async (_label, input, error) => {
    const fetchMock = mockFetch();
    const out = await rpc().ingestFile(input as unknown as typeof FILE);
    expect(out.status).toBe(400);
    expect(JSON.parse(out.body).error).toBe(error);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("引数自体が無くても throw せず 400", async () => {
    const out = await rpc().ingestFile(undefined as unknown as typeof FILE);
    expect(out.status).toBe(400);
  });

  // ── 共有 forward (lib/alc-tenant-forward.ts) の env guard / mint 失敗 ──────
  it("ALC_API_PROXY_SA_KEY が無ければ 503 (呼ばない)", async () => {
    const fetchMock = mockFetch();
    const out = await rpc(env({}, { ALC_API_PROXY_SA_KEY: undefined })).ingestFile(FILE);
    expect(out.status).toBe(503);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("ALC_API_ORIGIN が無ければ 503 (呼ばない)", async () => {
    const fetchMock = mockFetch();
    const out = await rpc(env({}, { ALC_API_ORIGIN: "" })).ingestFile(FILE);
    expect(out.status).toBe(503);
    expect(JSON.parse(out.body).error).toBe("server_error");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("OIDC mint 失敗は 502 (呼ばない)", async () => {
    vi.mocked(mintGoogleIdToken).mockRejectedValueOnce(new Error("boom"));
    const fetchMock = mockFetch();
    const out = await rpc().ingestFile(FILE);
    expect(out.status).toBe(502);
    expect(JSON.parse(out.body).error).toBe("upstream auth error");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("上流のエラーはそのまま status / body を返す (throw しない)", async () => {
    mockFetch(new Response("bad", { status: 400 }));
    const out = await rpc().ingestFile(FILE);
    expect(out.status).toBe(400);
    expect(out.body).toBe("bad");
  });
});

describe("SmbIngestEntrypoint#notify (ohishi-exp/smb-watch#14)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.clearAllMocks(); // mock factory の vi.fn の呼び出し回数を毎回 0 に戻す
  });

  it("正常: KV の smb-ingest 宛てに internal token 付きで /api/internal/lineworks/send へ POST", async () => {
    const fetchMock = mockFetch(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const out = await rpc().notify("found=3 uploaded=3 failed=0");

    expect(out.status).toBe(200);
    expect(JSON.parse(out.body)).toEqual({ ok: true });
    expect(out.contentType).toBe("application/json");

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://alc-api.test.example/api/internal/lineworks/send");
    expect((init as RequestInit).method).toBe("POST");
    const h = (init as RequestInit).headers as Record<string, string>;
    expect(h["Authorization"]).toBe("Bearer fake-internal-jwt");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      recipient_id: RECIPIENT,
      text: "found=3 uploaded=3 failed=0",
    });
  });

  it.each([
    ["targets 未設定", undefined],
    ["smb-ingest の key が無い", JSON.stringify({ "device-carins": RECIPIENT })],
    ["壊れた JSON", "{"],
  ])("宛先が %s なら 503 で送らない", async (_label, targets) => {
    const fetchMock = mockFetch();
    const kv = createMockKV({
      "smb-ingest-tenant": TENANT,
      ...(targets === undefined ? {} : { "device-notify-targets": targets }),
    });
    const out = await rpc(env({}, { AUTH_CONFIG: kv })).notify("hi");
    expect(out.status).toBe(503);
    expect(JSON.parse(out.body).error).toBe("recipient_unset");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("text が 1000 文字超なら 400 (送らない)。1000 ちょうどは通す", async () => {
    const fetchMock = mockFetch();
    const over = await rpc().notify("a".repeat(1001));
    expect(over.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();

    const ok = await rpc().notify("a".repeat(1000));
    expect(ok.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["空文字", ""],
    ["非文字列", 1],
  ])("text が%sなら 400 (送らない)", async (_label, text) => {
    const fetchMock = mockFetch();
    const out = await rpc().notify(text as unknown as string);
    expect(out.status).toBe(400);
    expect(JSON.parse(out.body).error).toBe("text required");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("ALC_API_ORIGIN が無ければ 503 (送らない)", async () => {
    const fetchMock = mockFetch();
    const out = await rpc(env({}, { ALC_API_ORIGIN: "" })).notify("hi");
    expect(out.status).toBe(503);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("internal token の mint 失敗は 502 (送らない)", async () => {
    vi.mocked(internalAuthToken).mockRejectedValueOnce(new Error("boom"));
    const fetchMock = mockFetch();
    const out = await rpc().notify("hi");
    expect(out.status).toBe(502);
    expect(JSON.parse(out.body).error).toBe("upstream auth error");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("上流の失敗は 502 にし、上流の本文は返さない (log にだけ出す)", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    mockFetch(new Response("secret-ish detail", { status: 500 }));
    const out = await rpc().notify("hi");
    expect(out.status).toBe(502);
    expect(out.body).not.toContain("secret-ish");
    expect(JSON.parse(out.body).error).toBe("upstream error");
    const logged = JSON.parse(errSpy.mock.calls[0]![0] as string);
    expect(logged.event).toBe("smb_ingest_notify_upstream_failed");
    expect(logged.status).toBe(500);
  });
});
