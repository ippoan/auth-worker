/**
 * `lib/mcp-cimd.ts` (CIMD / SEP-991、issue #449 PR-B) unit test。
 *
 * fetch は `fetchImpl` 注入 (binding-jwt の introspectFetch と同じ流儀) で stub。
 */

import { describe, it, expect, vi } from "vitest";
import {
  CIMD_MAX_BODY_BYTES,
  cacheTtlSecFromHeader,
  fetchCimdClient,
  isCimdClientId,
} from "../../src/lib/mcp-cimd";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
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
    const fetchImpl = vi.fn().mockResolvedValue(
      docResp(validDoc({ scope: "mcp.read" }), { headers: { "Cache-Control": "max-age=600" } }),
    );
    const client = await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch);
    expect(client).toEqual({
      client_id: CID,
      client_name: "Example MCP Client",
      redirect_uris: ["https://app.example.com/cb"],
      scope: "mcp.read",
    });
    // redirect 追跡なしで呼んでいる
    expect(fetchImpl).toHaveBeenCalledWith(CID, expect.objectContaining({ redirect: "error" }));
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

  it("refetches when the cached document no longer validates", async () => {
    const { env, kv } = envWithKv();
    kv._data[`cimd:client:${CID}`] = "broken{{{";
    const fetchImpl = vi.fn().mockResolvedValue(docResp(validDoc()));
    const client = await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch);
    expect(client?.client_id).toBe(CID);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("works without MCP_OAUTH_KV (no cache read/write)", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    const fetchImpl = vi.fn().mockResolvedValue(docResp(validDoc()));
    const client = await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch);
    expect(client?.client_id).toBe(CID);
  });

  it("returns null when fetch throws (network error / redirect: error / timeout)", async () => {
    const { env } = envWithKv();
    const fetchImpl = vi.fn().mockRejectedValue(new TypeError("redirected"));
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
  });

  it("returns null on non-2xx status", async () => {
    const { env } = envWithKv();
    const fetchImpl = vi.fn().mockResolvedValue(docResp(validDoc(), { status: 404 }));
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
  });

  it("returns null when content-length exceeds the cap", async () => {
    const { env } = envWithKv();
    const fetchImpl = vi.fn().mockResolvedValue(
      docResp(validDoc(), { headers: { "content-length": String(CIMD_MAX_BODY_BYTES + 1) } }),
    );
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
  });

  it("returns null when the body itself exceeds the cap (no content-length)", async () => {
    const { env } = envWithKv();
    const huge = `{"pad":"${"x".repeat(CIMD_MAX_BODY_BYTES)}"}`;
    const fetchImpl = vi.fn().mockResolvedValue(docResp(huge));
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
  });

  it("returns null when reading the body throws", async () => {
    const { env } = envWithKv();
    const resp = docResp(validDoc());
    vi.spyOn(resp, "text").mockRejectedValue(new Error("stream error"));
    const fetchImpl = vi.fn().mockResolvedValue(resp);
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
  });

  it.each([
    ["malformed JSON", "not-json{{{"],
    ["non-object JSON", JSON.stringify("a string")],
    ["null JSON", JSON.stringify(null)],
    ["array JSON", JSON.stringify([1, 2])],
    ["client_id mismatch", JSON.stringify(validDoc({ client_id: "https://evil.example/other.json" }))],
    ["client_name missing", JSON.stringify((() => { const d = validDoc(); delete d["client_name"]; return d; })())],
    ["client_name empty", JSON.stringify(validDoc({ client_name: "" }))],
    ["redirect_uris missing", JSON.stringify((() => { const d = validDoc(); delete d["redirect_uris"]; return d; })())],
    ["redirect_uris empty", JSON.stringify(validDoc({ redirect_uris: [] }))],
    ["redirect_uris non-string member", JSON.stringify(validDoc({ redirect_uris: ["https://a.example/cb", 42] }))],
    ["token_endpoint_auth_method not 'none'", JSON.stringify(validDoc({ token_endpoint_auth_method: "private_key_jwt" }))],
  ])("returns null for %s", async (_label, body) => {
    const { env } = envWithKv();
    const fetchImpl = vi.fn().mockResolvedValue(docResp(body as string));
    expect(await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch)).toBeNull();
  });

  it("omits scope when the document does not carry a string scope", async () => {
    const { env } = envWithKv();
    const fetchImpl = vi.fn().mockResolvedValue(docResp(validDoc({ scope: 123 })));
    const client = await fetchCimdClient(env, CID, fetchImpl as unknown as typeof fetch);
    expect(client).not.toBeNull();
    expect("scope" in client!).toBe(false);
  });
});
