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

  // Refs #270: 単一 isolate 内の並列 fan-out が同じ refresh_token で N 回 refresh を
  // 撃つと invalid_grant: already used で session が死ぬ。single-flight で /mcp/token
  // 呼び出しを 1 回に収束させる。
  it("collapses concurrent stale-token callers into a single /mcp/token refresh (single-flight)", async () => {
    await storeTokens(kv, {
      access_token: "about-to-expire",
      refresh_token: "rt-old",
      access_expires_at_ms: Date.now() + 30_000,
    });
    // mockImplementation で呼び出しごとに新しい Response を返す (Response body は
    // 一度しか読めないため、後段の 2 回目 fetch で再利用すると "Body unusable" になる)。
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
      Response.json({ access_token: "fresh-access", refresh_token: "rt-new", expires_in: 3600 }),
    );

    const results = await Promise.all(
      Array.from({ length: 5 }, () => getValidAccessToken({ ...BASE_OPTS, kv })),
    );

    expect(results).toEqual(Array(5).fill("fresh-access"));
    // 並列 5 本でも /mcp/token は 1 回だけ。
    expect(spy).toHaveBeenCalledTimes(1);
    // single-flight が解放され、次回の stale 呼び出しは再び refresh できる。
    await storeTokens(kv, {
      access_token: "stale-again", refresh_token: "rt-new", access_expires_at_ms: Date.now() + 30_000,
    });
    await getValidAccessToken({ ...BASE_OPTS, kv });
    expect(spy).toHaveBeenCalledTimes(2);
  });

  // Refs #270: single-flight をすり抜けた cross-isolate 敗者の救済。refresh が
  // invalid_grant で落ちても、別経路が KV に書いた fresh な新 pair があればそれを使う。
  it("falls back to a freshly-written KV pair when the refresh hits invalid_grant", async () => {
    await storeTokens(kv, {
      access_token: "about-to-expire", refresh_token: "rt-old", access_expires_at_ms: Date.now() + 30_000,
    });
    // fetch は invalid_grant を返すが、その裏で「別 isolate が rotate 済み」を模して
    // KV に fresh な新 pair を書いておく。
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      await storeTokens(kv, {
        access_token: "fresh-from-other-isolate", refresh_token: "rt-winner",
        access_expires_at_ms: Date.now() + 3_600_000,
      });
      return new Response('{"error":"invalid_grant"}', { status: 400 });
    });

    expect(await getValidAccessToken({ ...BASE_OPTS, kv })).toBe("fresh-from-other-isolate");
  });

  it("rethrows invalid_grant when KV still holds the same (dead) refresh_token", async () => {
    await storeTokens(kv, {
      access_token: "about-to-expire", refresh_token: "rt-old", access_expires_at_ms: Date.now() + 30_000,
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response('{"error":"invalid_grant"}', { status: 400 }),
    );
    await expect(getValidAccessToken({ ...BASE_OPTS, kv }))
      .rejects.toThrow(/invalid_grant/);
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
