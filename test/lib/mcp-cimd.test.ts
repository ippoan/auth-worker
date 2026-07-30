/**
 * `lib/mcp-cimd.ts` (CIMD / SEP-991、issue #449 PR-B) unit test。
 *
 * fetch は `fetchImpl` 注入 (binding-jwt の introspectFetch と同じ流儀) で stub。
 *
 * stub は `workerdFetch` で包む — 本 repo は vanilla vitest (node/undici) で走るが、
 * undici は workerd が拒否する RequestInit を受け付けてしまう。CIMD (#449 PR-B) の事故は
 * `redirect: "error"` が workerd で TypeError になるのを node の stub が
 * 見逃したまま prod に出た事故なので、stub 側で runtime の検証を再現する。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  CIMD_MAX_BODY_BYTES,
  cacheTtlSecFromHeader,
  fetchCimdClient,
  isCimdClientId,
} from "../../src/lib/mcp-cimd";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import { workerdFetch } from "../helpers/workerd-fetch";
import type { Env } from "../../src/index";

const CID = "https://app.example.com/oauth/client-metadata.json";

function validDoc(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    client_id: CID,
    client_name: "Example MCP Client",
    redirect_uris: ["https://app.example.com/cb"],
    token_endpoint_auth_method: "none",
    ...overrides,
  };
}

function docResp(
  body: unknown,
  init: { status?: number; headers?: Record<string, string> } = {},
): Response {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
}

function envWithKv(): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({ MCP_OAUTH_KV: kv });
  return { env, kv };
}

/** `mcp-cimd-reject` ログの reason を集める。 */
let rejectLog: string[];
let warnSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  rejectLog = [];
  warnSpy = vi.spyOn(console, "warn").mockImplementation((line: unknown) => {
    const parsed = JSON.parse(String(line)) as { msg: string; reason: string };
    if (parsed.msg === "mcp-cimd-reject") rejectLog.push(parsed.reason);
  });
});

afterEach(() => {
  warnSpy.mockRestore();
});

describe("isCimdClientId", () => {
  it("accepts an https URL with a path component", () => {
    expect(isCimdClientId(CID)).toBe(true);
  });

  it.each([
    ["UUID (DCR client)", "0f9adf9e-2f43-4d54-a1a1-000000000000"],
    ["http scheme", "http://app.example.com/client.json"],
    ["unparseable", "https://"],
    ["userinfo", "https://user:pass@app.example.com/client.json"],
    ["fragment", "https://app.example.com/client.json#frag"],
    ["no path component", "https://app.example.com"],
    ["localhost", "https://localhost/client.json"],
    ["*.localhost", "https://foo.localhost/client.json"],
    [".local suffix", "https://printer.local/client.json"],
    [".internal suffix", "https://svc.internal/client.json"],
    ["IPv6 literal", "https://[::1]/client.json"],
    ["0.0.0.0", "https://0.0.0.0/client.json"],
    ["10.x private", "https://10.1.2.3/client.json"],
    ["127.x loopback", "https://127.0.0.1/client.json"],
    ["link-local", "https://169.254.1.1/client.json"],
    ["172.16-31 private", "https://172.20.0.1/client.json"],
    ["192.168 private", "https://192.168.1.1/client.json"],
  ])("rejects %s", (_label, cid) => {
    expect(isCimdClientId(cid)).toBe(false);
  });

  it("accepts a public IPv4 host and a 172.x host outside the private range", () => {
    expect(isCimdClientId("https://203.0.113.10/client.json")).toBe(true);
    expect(isCimdClientId("https://172.32.0.1/client.json")).toBe(true);
    expect(isCimdClientId("https://172.15.0.1/client.json")).toBe(true);
  });
});

describe("cacheTtlSecFromHeader", () => {
  it("defaults to 300s when header is absent or has no max-age", () => {
    expect(cacheTtlSecFromHeader(null)).toBe(300);
    expect(cacheTtlSecFromHeader("no-store")).toBe(300);
  });

  it("clamps max-age into [60s, 24h]", () => {
    expect(cacheTtlSecFromHeader("max-age=10")).toBe(60);
    expect(cacheTtlSecFromHeader("public, max-age=600")).toBe(600);
    expect(cacheTtlSecFromHeader("max-age=9999999")).toBe(60 * 60 * 24);
  });
});

describe("fetchCimdClient — fetch + validation", () => {
  it("fetches, validates, caches, and returns the client", async () => {
    const { env, kv } = envWithKv();
    const fetchImpl = workerdFetch(() =>
      Promise.resolve(
        docResp(validDoc({ scope: "mcp.read" }), { headers: { "Cache-Control": "max-age=600" } }),
      ),
    );
    const client = await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch);
    expect(client).toEqual({
      client_id: CID,
      client_name: "Example MCP Client",
      redirect_uris: ["https://app.example.com/cb"],
      scope: "mcp.read",
    });
    // redirect 追跡なし。workerd が受け付ける値は "follow" / "manual" だけなので
    // "manual" + 3xx 拒否で実装する (Refs #449 — "error" は fetch 前に TypeError)
    expect(fetchImpl).toHaveBeenCalledWith(CID, expect.objectContaining({ redirect: "manual" }));
    // 成功経路では reject ログを出さない
    expect(rejectLog).toEqual([]);
    // KV に生 JSON がキャッシュされる
    expect(kv._data[`cimd:client:${CID}`]).toBeDefined();
  });

  it("serves from KV cache without fetching", async () => {
    const { env, kv } = envWithKv();
    kv._data[`cimd:client:${CID}`] = JSON.stringify(validDoc());
    const fetchImpl = vi.fn();
    const client = await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch);
    expect(client?.client_id).toBe(CID);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("deletes the broken cache entry and refetches when it no longer validates", async () => {
    const { env, kv } = envWithKv();
    kv._data[`cimd:client:${CID}`] = "broken{{{";
    const fetchImpl = workerdFetch(() => Promise.resolve(docResp(validDoc())));
    const client = await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch);
    expect(client?.client_id).toBe(CID);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(rejectLog).toEqual(["cache_json_parse_failed"]);
    // 壊れた値を残すと TTL 切れまで同じ失敗を繰り返す — 上書きされていること
    expect(kv._data[`cimd:client:${CID}`]).toBe(JSON.stringify(validDoc()));
  });

  it("deletes a cached document whose client_id no longer matches", async () => {
    const { env, kv } = envWithKv();
    kv._data[`cimd:client:${CID}`] = JSON.stringify(
      validDoc({ client_id: "https://evil.example/other.json" }),
    );
    const fetchImpl = workerdFetch(() => Promise.resolve(docResp(validDoc())));
    const client = await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch);
    expect(client?.client_id).toBe(CID);
    expect(rejectLog).toEqual(["cache_client_id_mismatch"]);
  });

  it("deletes the broken cache entry even when the refetch also fails", async () => {
    const { env, kv } = envWithKv();
    kv._data[`cimd:client:${CID}`] = "broken{{{";
    const fetchImpl = workerdFetch(() => Promise.resolve(docResp(validDoc(), { status: 500 })));
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
    expect(kv._data[`cimd:client:${CID}`]).toBeUndefined();
    expect(rejectLog).toEqual(["cache_json_parse_failed", "http_error"]);
  });

  it("works without MCP_OAUTH_KV (no cache read/write)", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    const fetchImpl = workerdFetch(() => Promise.resolve(docResp(validDoc())));
    const client = await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch);
    expect(client?.client_id).toBe(CID);
  });

  it("returns null and logs fetch_threw when fetch throws (network error / timeout)", async () => {
    const { env } = envWithKv();
    const fetchImpl = vi.fn().mockRejectedValue(new TypeError("Network connection lost."));
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
    expect(rejectLog).toEqual(["fetch_threw"]);
  });

  it("logs fetch_threw for a non-Error rejection", async () => {
    const { env } = envWithKv();
    const fetchImpl = vi.fn().mockRejectedValue("boom");
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
    expect(rejectLog).toEqual(["fetch_threw"]);
  });

  // 回帰 (Refs #449): workerd は `redirect: "error"` を fetch 前に TypeError で拒否する。
  // それを catch で潰していたため全 CIMD client が invalid_client になっていた。
  it("does not pass a redirect mode that the Workers runtime rejects", async () => {
    const { env } = envWithKv();
    const fetchImpl = workerdFetch(() => Promise.resolve(docResp(validDoc())));
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).not.toBeNull();
    const init = fetchImpl.mock.calls[0]?.[1] as RequestInit;
    expect(["follow", "manual"]).toContain(init.redirect);
  });

  it.each([301, 302, 307, 308])(
    "returns null and logs redirect_not_followed on %i",
    async (status) => {
      const { env } = envWithKv();
      const fetchImpl = workerdFetch(() =>
        Promise.resolve(
          new Response(null, { status, headers: { location: "https://app.example.com/moved" } }),
        ),
      );
      expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
      expect(rejectLog).toEqual(["redirect_not_followed"]);
    },
  );

  it("logs redirect_not_followed with a null location when the header is absent", async () => {
    const { env } = envWithKv();
    const fetchImpl = workerdFetch(() => Promise.resolve(new Response(null, { status: 304 })));
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
    expect(rejectLog).toEqual(["redirect_not_followed"]);
  });

  it("returns null and logs http_error on non-2xx status", async () => {
    const { env } = envWithKv();
    const fetchImpl = workerdFetch(() => Promise.resolve(docResp(validDoc(), { status: 404 })));
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
    expect(rejectLog).toEqual(["http_error"]);
  });

  it("returns null when content-length exceeds the cap", async () => {
    const { env } = envWithKv();
    const fetchImpl = workerdFetch(() =>
      Promise.resolve(
        docResp(validDoc(), { headers: { "content-length": String(CIMD_MAX_BODY_BYTES + 1) } }),
      ),
    );
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
    expect(rejectLog).toEqual(["content_length_too_large"]);
  });

  it("returns null when the body itself exceeds the cap (no content-length)", async () => {
    const { env } = envWithKv();
    const huge = `{"pad":"${"x".repeat(CIMD_MAX_BODY_BYTES)}"}`;
    const fetchImpl = workerdFetch(() => Promise.resolve(docResp(huge)));
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
    expect(rejectLog).toEqual(["body_too_large"]);
  });

  it("returns null when reading the body throws", async () => {
    const { env } = envWithKv();
    const resp = docResp(validDoc());
    vi.spyOn(resp, "text").mockRejectedValue(new Error("stream error"));
    const fetchImpl = workerdFetch(() => Promise.resolve(resp));
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
    expect(rejectLog).toEqual(["body_read_threw"]);
  });

  it("logs body_read_threw for a non-Error rejection", async () => {
    const { env } = envWithKv();
    const resp = docResp(validDoc());
    vi.spyOn(resp, "text").mockRejectedValue("boom");
    const fetchImpl = workerdFetch(() => Promise.resolve(resp));
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
    expect(rejectLog).toEqual(["body_read_threw"]);
  });

  it.each([
    ["malformed JSON", "not-json{{{", "json_parse_failed"],
    ["non-object JSON", JSON.stringify("a string"), "not_json_object"],
    ["null JSON", JSON.stringify(null), "not_json_object"],
    ["array JSON", JSON.stringify([1, 2]), "not_json_object"],
    ["client_id mismatch", JSON.stringify(validDoc({ client_id: "https://evil.example/other.json" })), "client_id_mismatch"],
    ["client_name missing", JSON.stringify((() => { const d = validDoc(); delete d["client_name"]; return d; })()), "client_name_invalid"],
    ["client_name empty", JSON.stringify(validDoc({ client_name: "" })), "client_name_invalid"],
    ["redirect_uris missing", JSON.stringify((() => { const d = validDoc(); delete d["redirect_uris"]; return d; })()), "redirect_uris_invalid"],
    ["redirect_uris empty", JSON.stringify(validDoc({ redirect_uris: [] })), "redirect_uris_invalid"],
    ["redirect_uris non-string member", JSON.stringify(validDoc({ redirect_uris: ["https://a.example/cb", 42] })), "redirect_uris_invalid"],
    ["token_endpoint_auth_method not 'none'", JSON.stringify(validDoc({ token_endpoint_auth_method: "private_key_jwt" })), "auth_method_unsupported"],
  ])("returns null for %s and logs the reason", async (_label, body, reason) => {
    const { env } = envWithKv();
    const fetchImpl = workerdFetch(() => Promise.resolve(docResp(body as string)));
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
    expect(rejectLog).toEqual([reason]);
  });

  it("never puts the document body into the reject log", async () => {
    const { env } = envWithKv();
    const fetchImpl = workerdFetch(() =>
      Promise.resolve(docResp(JSON.stringify(validDoc({ client_id: "https://evil.example/x" })))),
    );
    await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch);
    const lines = warnSpy.mock.calls.map((c) => String(c[0]));
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toContain("evil.example");
    expect(lines[0]).not.toContain("Example MCP Client");
    expect(JSON.parse(lines[0]!)).toEqual({
      msg: "mcp-cimd-reject",
      reason: "client_id_mismatch",
      client_id: CID,
    });
  });

  it("omits scope when the document does not carry a string scope", async () => {
    const { env } = envWithKv();
    const fetchImpl = workerdFetch(() => Promise.resolve(docResp(validDoc({ scope: 123 }))));
    const client = await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch);
    expect(client).not.toBeNull();
    expect("scope" in client!).toBe(false);
  });
});
