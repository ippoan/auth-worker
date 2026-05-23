import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  storeTokens,
  readStoredTokens,
  getValidAccessToken,
  refreshAccessToken,
  exchangeAuthorizationCode,
  type StoredTokens,
} from "../src/tokens";
import { makeKv } from "./_helpers";

const BASE_OPTS = {
  authWorkerOrigin: "https://auth.ippoan.org",
  clientId: "dcr-uuid",
  redirectUri: "https://ci-dashboard.ippoan.org/oauth/callback",
};

describe("storeTokens / readStoredTokens", () => {
  let kv: KVNamespace;
  beforeEach(() => { kv = makeKv(); });

  it("round-trips a StoredTokens record through KV", async () => {
    const t: StoredTokens = {
      access_token: "eyJ.access",
      refresh_token: "rt-abc",
      access_expires_at_ms: 1_800_000_000_000,
      scope: "mcp.write",
    };
    await storeTokens(kv, t);
    expect(await readStoredTokens(kv)).toEqual(t);
  });

  it("returns null when no tokens are stored", async () => {
    expect(await readStoredTokens(kv)).toBeNull();
  });
});

describe("getValidAccessToken", () => {
  let kv: KVNamespace;
  beforeEach(() => { kv = makeKv(); });
  afterEach(() => { vi.restoreAllMocks(); });

  it("throws clearly when no tokens have been stored yet", async () => {
    await expect(getValidAccessToken({ ...BASE_OPTS, kv }))
      .rejects.toThrow(/No OAuth tokens stored.*\/oauth\/login/);
  });

  it("returns the cached access_token when it has > 60s left", async () => {
    await storeTokens(kv, {
      access_token: "still-fresh",
      refresh_token: "rt-1",
      access_expires_at_ms: Date.now() + 30 * 60_000,
    });
    const spy = vi.spyOn(globalThis, "fetch");
    expect(await getValidAccessToken({ ...BASE_OPTS, kv })).toBe("still-fresh");
    expect(spy).not.toHaveBeenCalled();
  });

  it("refreshes when access_token is within 60s of expiry and persists the new pair", async () => {
    await storeTokens(kv, {
      access_token: "about-to-expire",
      refresh_token: "rt-old",
      access_expires_at_ms: Date.now() + 30_000,
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({
        access_token: "fresh-access",
        refresh_token: "rt-new",
        expires_in: 3600,
        scope: "mcp.write",
      }),
    );

    expect(await getValidAccessToken({ ...BASE_OPTS, kv })).toBe("fresh-access");

    const stored = await readStoredTokens(kv);
    expect(stored!.access_token).toBe("fresh-access");
    expect(stored!.refresh_token).toBe("rt-new");
  });
});

describe("refreshAccessToken", () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it("POSTs grant_type=refresh_token to /mcp/token and returns the new pair", async () => {
    const kv = makeKv();
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({
        access_token: "new-access",
        refresh_token: "new-refresh",
        expires_in: 1800,
      }),
    );

    const out = await refreshAccessToken("old-refresh", { ...BASE_OPTS, kv });
    expect(out.access_token).toBe("new-access");
    expect(out.refresh_token).toBe("new-refresh");
    expect(out.access_expires_at_ms).toBeGreaterThan(Date.now() + 1_700_000);

    const call = spy.mock.calls[0]!;
    expect(call[0]).toBe("https://auth.ippoan.org/mcp/token");
    const body = call[1]!.body as string;
    expect(body).toContain("grant_type=refresh_token");
    expect(body).toContain("refresh_token=old-refresh");
  });

  it("surfaces auth-worker errors verbosely", async () => {
    const kv = makeKv();
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response('{"error":"invalid_grant"}', { status: 400 }),
    );
    await expect(refreshAccessToken("dead-token", { ...BASE_OPTS, kv }))
      .rejects.toThrow(/\/mcp\/token \(refresh\) failed \(400\).*invalid_grant/);
  });
});

describe("exchangeAuthorizationCode", () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it("POSTs grant_type=authorization_code with code_verifier + client_id + redirect_uri", async () => {
    const kv = makeKv();
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({
        access_token: "initial-access",
        refresh_token: "initial-refresh",
        expires_in: 3600,
      }),
    );

    const out = await exchangeAuthorizationCode(
      "auth-code-xyz",
      "code-verifier-43chars-or-more-padded-padded-padded",
      { ...BASE_OPTS, kv },
    );
    expect(out.access_token).toBe("initial-access");

    const body = spy.mock.calls[0]![1]!.body as string;
    expect(body).toContain("grant_type=authorization_code");
    expect(body).toContain("code=auth-code-xyz");
    expect(body).toContain("code_verifier=code-verifier-43chars");
    expect(body).toContain("client_id=dcr-uuid");
    expect(body).toContain("redirect_uri=https");
  });
});
