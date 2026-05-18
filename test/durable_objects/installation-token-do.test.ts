/**
 * `InstallationTokenStore` DO — App JWT + installation token refresh / cache 検証。
 * `crypto.subtle.importKey` / `sign` を mock し、`globalThis.fetch` は vi.stubGlobal で
 * GitHub `/app/installations/{id}/access_tokens` を模擬する。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock crypto.subtle to bypass RSA key ops — same pattern as lineworks-bot-api.test.ts
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const g = globalThis as any;
const originalSubtle = g.crypto?.subtle;
const mockImportKey = vi.fn().mockResolvedValue({ type: "private" });
const mockSign = vi.fn().mockResolvedValue(new ArrayBuffer(32));

import { InstallationTokenStore } from "../../src/durable_objects/installation-token-do";

const FAKE_PEM = `-----BEGIN PRIVATE KEY-----
MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA0Z3VS5JJcds3xf0G
PGdqwYx0KVT5ePCMNkjaWOL0tEJhvsud4JL7dMtXEfehfslDrV5Rcqeqr3rSDGOu
cQIDAQABAkEAhZ3MsMYTs1Eiiekn8bfGd2sdU86WnKpynHjN+SWM3ePaiT6vK7sn
rDWCa3FG9vSzaxmQzSgMxlu5/5BffMVwwQIhAPe9lON+rnTiAhgKn3CKaaLz9Ave
eJR5k0VhTCGo/xThAiEA2S7qcIFrPZsT3F0T0G03JaKwrp4pCCe9xAvHtEVqxOkC
IEIuexLVNq3sCQ1DQ3TiRkZI2U7ChC4FaLzfhJKdLPIhAiEAgYLnkBbQfbvUDJYV
cRaQMwCdV7KNfJi7Llgwdmn+Y/kCIQDW5ndbYcIktYeKJC2qX20V8CeBVw+Yq5pJ
WJnH2j3VAw==
-----END PRIVATE KEY-----`;

function makeState(installationId: string = "111222"): {
  state: DurableObjectState;
  storageMap: Map<string, unknown>;
} {
  const storageMap = new Map<string, unknown>();
  const storage = {
    get: async <T>(key: string) => storageMap.get(key) as T | undefined,
    put: async (key: string, value: unknown) => { storageMap.set(key, value); },
    delete: async (key: string) => { storageMap.delete(key); },
  };
  const state = {
    id: { name: installationId },
    storage,
  } as unknown as DurableObjectState;
  return { state, storageMap };
}

function isoFromNow(secOffset: number): string {
  return new Date(Date.now() + secOffset * 1000).toISOString();
}

describe("InstallationTokenStore", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => {
    originalFetch = globalThis.fetch;
    mockImportKey.mockResolvedValue({ type: "private" });
    mockSign.mockResolvedValue(new ArrayBuffer(32));
    Object.defineProperty(g.crypto, "subtle", {
      value: { importKey: mockImportKey, sign: mockSign },
      configurable: true,
    });
  });
  afterEach(() => {
    globalThis.fetch = originalFetch;
    if (originalSubtle) {
      Object.defineProperty(g.crypto, "subtle", {
        value: originalSubtle,
        configurable: true,
      });
    }
    vi.clearAllMocks();
  });

  it("returns 503 when GITHUB_APP_ID missing", async () => {
    const { state } = makeState();
    const do_ = new InstallationTokenStore(state, { GITHUB_APP_PRIVATE_KEY: FAKE_PEM });
    const res = await do_.fetch(new Request("https://do.internal/get"));
    expect(res.status).toBe(503);
  });

  it("returns 503 when GITHUB_APP_PRIVATE_KEY missing", async () => {
    const { state } = makeState();
    const do_ = new InstallationTokenStore(state, { GITHUB_APP_ID: "999" });
    const res = await do_.fetch(new Request("https://do.internal/get"));
    expect(res.status).toBe(503);
  });

  it("returns 500 when installation_id (state.id.name) is missing", async () => {
    const state = {
      id: { name: "" },
      storage: {
        get: async () => undefined,
        put: async () => {},
        delete: async () => {},
      },
    } as unknown as DurableObjectState;
    const do_ = new InstallationTokenStore(state, {
      GITHUB_APP_ID: "999",
      GITHUB_APP_PRIVATE_KEY: FAKE_PEM,
    });
    const res = await do_.fetch(new Request("https://do.internal/get"));
    expect(res.status).toBe(500);
  });

  it("fetches and caches a fresh token on first call", async () => {
    const expiresAt = isoFromNow(3600);
    const fetchSpy = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ token: "ghs_fresh", expires_at: expiresAt }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchSpy);
    const { state, storageMap } = makeState("111222");
    const do_ = new InstallationTokenStore(state, {
      GITHUB_APP_ID: "999",
      GITHUB_APP_PRIVATE_KEY: FAKE_PEM,
    });
    const res = await do_.fetch(new Request("https://do.internal/get"));
    expect(res.status).toBe(200);
    const body = await res.json() as { token: string; expires_at_epoch_sec: number };
    expect(body.token).toBe("ghs_fresh");
    expect(body.expires_at_epoch_sec).toBe(Math.floor(Date.parse(expiresAt) / 1000));
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    // GitHub URL must include the installation id
    expect(fetchSpy.mock.calls[0]![0]).toBe(
      "https://api.github.com/app/installations/111222/access_tokens",
    );
    // Authorization header must be a 3-segment Bearer JWT
    const init = fetchSpy.mock.calls[0]![1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toMatch(/^Bearer [^.]+\.[^.]+\.[^.]+$/);
    expect(headers["Accept"]).toBe("application/vnd.github+json");
    expect(headers["User-Agent"]).toBe("ippoan-auth-worker");
    // storage now contains the cached token
    expect(storageMap.get("cached_token")).toEqual(body);
  });

  it("returns cached token without re-fetching when TTL > 5min", async () => {
    const expiresAt = isoFromNow(3600);
    const fetchSpy = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ token: "ghs_fresh", expires_at: expiresAt }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchSpy);
    const { state } = makeState("111222");
    const do_ = new InstallationTokenStore(state, {
      GITHUB_APP_ID: "999",
      GITHUB_APP_PRIVATE_KEY: FAKE_PEM,
    });
    await do_.fetch(new Request("https://do.internal/get"));
    await do_.fetch(new Request("https://do.internal/get"));
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("refreshes when cached token has less than 5min TTL remaining", async () => {
    // First fetch returns a token that's only 60s away from expiry — under the
    // 5min refresh buffer, so the next call must re-fetch.
    const nearExpiry = isoFromNow(60);
    const farExpiry = isoFromNow(3600);
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ token: "ghs_near_exp", expires_at: nearExpiry }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ token: "ghs_refreshed", expires_at: farExpiry }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetchSpy);
    const { state } = makeState("111222");
    const do_ = new InstallationTokenStore(state, {
      GITHUB_APP_ID: "999",
      GITHUB_APP_PRIVATE_KEY: FAKE_PEM,
    });
    await do_.fetch(new Request("https://do.internal/get"));
    const r2 = await do_.fetch(new Request("https://do.internal/get"));
    const body = await r2.json() as { token: string };
    expect(body.token).toBe("ghs_refreshed");
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("loads cached token from storage on cold start", async () => {
    const expiresEpoch = Math.floor(Date.now() / 1000) + 3600;
    const { state, storageMap } = makeState("111222");
    storageMap.set("cached_token", {
      token: "ghs_from_storage",
      expires_at_epoch_sec: expiresEpoch,
    });
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const do_ = new InstallationTokenStore(state, {
      GITHUB_APP_ID: "999",
      GITHUB_APP_PRIVATE_KEY: FAKE_PEM,
    });
    const res = await do_.fetch(new Request("https://do.internal/get"));
    const body = await res.json() as { token: string };
    expect(body.token).toBe("ghs_from_storage");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("returns 502 and does not cache when GitHub returns non-2xx", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("forbidden", { status: 403 })),
    );
    const { state, storageMap } = makeState("111222");
    const do_ = new InstallationTokenStore(state, {
      GITHUB_APP_ID: "999",
      GITHUB_APP_PRIVATE_KEY: FAKE_PEM,
    });
    const res = await do_.fetch(new Request("https://do.internal/get"));
    expect(res.status).toBe(502);
    expect(storageMap.has("cached_token")).toBe(false);
  });

  it("returns 502 when GitHub response is missing token field", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify({ expires_at: isoFromNow(3600) }), { status: 200 }),
      ),
    );
    const { state } = makeState("111222");
    const do_ = new InstallationTokenStore(state, {
      GITHUB_APP_ID: "999",
      GITHUB_APP_PRIVATE_KEY: FAKE_PEM,
    });
    const res = await do_.fetch(new Request("https://do.internal/get"));
    expect(res.status).toBe(502);
  });

  it("returns 502 when GitHub expires_at is unparseable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify({ token: "x", expires_at: "not-a-date" }), { status: 200 }),
      ),
    );
    const { state } = makeState("111222");
    const do_ = new InstallationTokenStore(state, {
      GITHUB_APP_ID: "999",
      GITHUB_APP_PRIVATE_KEY: FAKE_PEM,
    });
    const res = await do_.fetch(new Request("https://do.internal/get"));
    expect(res.status).toBe(502);
  });
});
