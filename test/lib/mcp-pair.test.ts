/**
 * `mcp-pair.ts` (issue #144) — KV schema + helpers のテスト。
 * KV mock を介して put/get/approve/delete/rate-limit を網羅する。
 */

import { describe, it, expect } from "vitest";
import {
  PAIR_CODE_TTL_SEC,
  PAIR_REFRESH_TTL_SEC,
  approvePair,
  checkAndBumpGrantRateLimit,
  checkAndBumpRateLimit,
  deletePair,
  generatePairRefreshToken,
  getPair,
  getPairRefresh,
  hashRefreshToken,
  putPair,
  putPairRefresh,
  touchPairRefresh,
  type PairRecord,
  type PairRefreshRecord,
} from "../../src/lib/mcp-pair";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";

function envWithKv(): { env: ReturnType<typeof createMockEnv>; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({ MCP_OAUTH_KV: kv });
  return { env, kv };
}

function rec(overrides: Partial<PairRecord> = {}): PairRecord {
  const now = Date.now();
  return {
    pair_code: "PC-test-1",
    claim_login: "alice",
    binary_version: "v0.0.13",
    created_at: now,
    expires_at: now + PAIR_CODE_TTL_SEC * 1000,
    status: "pending",
    binding_jwt: null,
    ...overrides,
  };
}

describe("putPair / getPair", () => {
  it("round-trips a PairRecord through KV with 300s TTL", async () => {
    const { env, kv } = envWithKv();
    const r = rec();
    await putPair(env, r);
    expect(kv._data["mcp/pair/PC-test-1"]).toBe(JSON.stringify(r));
    expect(kv._ttls["mcp/pair/PC-test-1"]).toBe(PAIR_CODE_TTL_SEC);

    const got = await getPair(env, "PC-test-1");
    expect(got).toEqual(r);
  });

  it("getPair returns null when key missing", async () => {
    const { env } = envWithKv();
    expect(await getPair(env, "no-such")).toBeNull();
  });

  it("getPair returns null when KV not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    expect(await getPair(env, "any")).toBeNull();
  });

  it("getPair returns null when value is not valid JSON", async () => {
    const { env, kv } = envWithKv();
    kv._data["mcp/pair/bad"] = "{not json";
    expect(await getPair(env, "bad")).toBeNull();
  });

  it("putPair throws when KV not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    await expect(putPair(env, rec())).rejects.toThrow(/MCP_OAUTH_KV not bound/);
  });
});

describe("approvePair", () => {
  it("updates status=approved + binding_jwt, preserves other fields", async () => {
    const { env, kv } = envWithKv();
    const r = rec();
    await putPair(env, r);
    const updated = await approvePair(env, r.pair_code, "JWT-AAA");
    expect(updated).not.toBeNull();
    expect(updated?.status).toBe("approved");
    expect(updated?.binding_jwt).toBe("JWT-AAA");
    expect(updated?.claim_login).toBe("alice");
    // KV にも反映済
    const re = JSON.parse(kv._data["mcp/pair/PC-test-1"]!) as PairRecord;
    expect(re.status).toBe("approved");
    expect(re.binding_jwt).toBe("JWT-AAA");
  });

  it("uses remaining TTL (clamped to 60s minimum)", async () => {
    const { env, kv } = envWithKv();
    // expires_at を「ほぼ満了 (1s 後)」に偽装
    const r = rec({ expires_at: Date.now() + 1_000 });
    await putPair(env, r);
    await approvePair(env, r.pair_code, "JWT");
    expect(kv._ttls["mcp/pair/PC-test-1"]).toBe(60);
  });

  it("uses Math.floor of remaining TTL when comfortably above 60s", async () => {
    const { env, kv } = envWithKv();
    const r = rec({ expires_at: Date.now() + 250_500 });
    await putPair(env, r);
    await approvePair(env, r.pair_code, "JWT");
    // 250s 程度残っている → 60s 下限ではなく floor((250500)/1000)=250
    expect(kv._ttls["mcp/pair/PC-test-1"]).toBeGreaterThanOrEqual(60);
    expect(kv._ttls["mcp/pair/PC-test-1"]).toBeLessThanOrEqual(251);
  });

  it("returns null when record not found", async () => {
    const { env } = envWithKv();
    expect(await approvePair(env, "missing", "JWT")).toBeNull();
  });

  it("returns null when KV not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    expect(await approvePair(env, "any", "JWT")).toBeNull();
  });
});

describe("deletePair", () => {
  it("removes the KV entry", async () => {
    const { env, kv } = envWithKv();
    await putPair(env, rec());
    expect(kv._data["mcp/pair/PC-test-1"]).toBeDefined();
    await deletePair(env, "PC-test-1");
    expect(kv._data["mcp/pair/PC-test-1"]).toBeUndefined();
  });

  it("is a no-op when KV not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    await expect(deletePair(env, "any")).resolves.toBeUndefined();
  });
});

describe("checkAndBumpRateLimit", () => {
  it("allows up to 10 requests in the same minute window, then rejects", async () => {
    const { env, kv } = envWithKv();
    const now = 60_000_000_000; // arbitrary fixed ms
    for (let i = 0; i < 10; i++) {
      expect(await checkAndBumpRateLimit(env, "1.2.3.4", now)).toBe(true);
    }
    expect(await checkAndBumpRateLimit(env, "1.2.3.4", now)).toBe(false);
    // KV key には minute bucket が反映されている
    const minute = Math.floor(now / 60_000);
    expect(kv._data[`mcp/pair_rate/1.2.3.4/${minute}`]).toBe("10");
  });

  it("resets when minute window rolls over", async () => {
    const { env } = envWithKv();
    const t0 = 60_000_000_000;
    for (let i = 0; i < 10; i++) await checkAndBumpRateLimit(env, "1.2.3.4", t0);
    expect(await checkAndBumpRateLimit(env, "1.2.3.4", t0)).toBe(false);
    // 次の分に入ると別 key になるので 10 回まで再度通る
    const t1 = t0 + 60_000;
    expect(await checkAndBumpRateLimit(env, "1.2.3.4", t1)).toBe(true);
  });

  it("counts per-IP (different IPs do not interfere)", async () => {
    const { env } = envWithKv();
    const now = 60_000_000_000;
    for (let i = 0; i < 10; i++) await checkAndBumpRateLimit(env, "a", now);
    expect(await checkAndBumpRateLimit(env, "a", now)).toBe(false);
    expect(await checkAndBumpRateLimit(env, "b", now)).toBe(true);
  });

  it("respects custom limit argument", async () => {
    const { env } = envWithKv();
    const now = 60_000_000_000;
    expect(await checkAndBumpRateLimit(env, "x", now, 2)).toBe(true);
    expect(await checkAndBumpRateLimit(env, "x", now, 2)).toBe(true);
    expect(await checkAndBumpRateLimit(env, "x", now, 2)).toBe(false);
  });

  it("returns true when KV not bound (best-effort, do not block)", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    expect(await checkAndBumpRateLimit(env, "x", Date.now())).toBe(true);
  });

  it("rejects (false) when stored counter is non-numeric (defensive parse)", async () => {
    const { env, kv } = envWithKv();
    const now = 60_000_000_000;
    const minute = Math.floor(now / 60_000);
    kv._data[`mcp/pair_rate/x/${minute}`] = "garbage";
    expect(await checkAndBumpRateLimit(env, "x", now)).toBe(false);
  });
});

// ────────────────────────────────────────────────────────────────────────
// issue #157: 30 日 refresh_token helpers
// ────────────────────────────────────────────────────────────────────────

describe("generatePairRefreshToken", () => {
  it("produces base64url string of expected length (32 byte → 43 chars)", () => {
    const t = generatePairRefreshToken();
    expect(t).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(t.length).toBe(43);
  });

  it("returns different values across calls (entropy sanity)", () => {
    const a = generatePairRefreshToken();
    const b = generatePairRefreshToken();
    expect(a).not.toBe(b);
  });
});

describe("hashRefreshToken", () => {
  it("returns 64-char lowercase hex (SHA-256)", async () => {
    const h = await hashRefreshToken("hello");
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    // 既知の SHA-256("hello")
    expect(h).toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    );
  });

  it("same token → same hash (deterministic)", async () => {
    const a = await hashRefreshToken("abc");
    const b = await hashRefreshToken("abc");
    expect(a).toBe(b);
  });

  it("different tokens → different hashes", async () => {
    const a = await hashRefreshToken("abc");
    const b = await hashRefreshToken("xyz");
    expect(a).not.toBe(b);
  });
});

describe("putPairRefresh / getPairRefresh", () => {
  function refreshRec(overrides: Partial<PairRefreshRecord> = {}): PairRefreshRecord {
    const now = Date.now();
    return {
      github_login: "alice",
      requested_scope: "mcp.read mcp.write",
      created_at: now,
      expires_at: now + PAIR_REFRESH_TTL_SEC * 1000,
      last_used_at: null,
      revoked: false,
      ...overrides,
    };
  }

  it("round-trips a record under mcp/pair_refresh/<hash> with ~30d TTL", async () => {
    const { env, kv } = envWithKv();
    const r = refreshRec();
    await putPairRefresh(env, "h0".padEnd(64, "0"), r);
    const k = `mcp/pair_refresh/${"h0".padEnd(64, "0")}`;
    expect(JSON.parse(kv._data[k]!)).toEqual(r);
    // TTL is set close to (expires_at - now)/1000 — allow small skew, but
    // anchored to 30d range.
    expect(kv._ttls[k]).toBeGreaterThan(PAIR_REFRESH_TTL_SEC - 60);
    expect(kv._ttls[k]).toBeLessThanOrEqual(PAIR_REFRESH_TTL_SEC);
    const got = await getPairRefresh(env, "h0".padEnd(64, "0"));
    expect(got).toEqual(r);
  });

  it("clamps TTL to 60s minimum when expires_at is nearly past", async () => {
    const { env, kv } = envWithKv();
    await putPairRefresh(env, "h", refreshRec({ expires_at: Date.now() + 1_000 }));
    expect(kv._ttls["mcp/pair_refresh/h"]).toBe(60);
  });

  it("getPairRefresh returns null when missing / KV unbound / bad JSON", async () => {
    const { env, kv } = envWithKv();
    expect(await getPairRefresh(env, "no-such")).toBeNull();
    kv._data["mcp/pair_refresh/bad"] = "{not json";
    expect(await getPairRefresh(env, "bad")).toBeNull();
    const envNone = createMockEnv({ MCP_OAUTH_KV: undefined });
    expect(await getPairRefresh(envNone, "x")).toBeNull();
  });

  it("putPairRefresh throws when KV not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    await expect(putPairRefresh(env, "h", refreshRec())).rejects.toThrow(
      /MCP_OAUTH_KV not bound/,
    );
  });
});

describe("touchPairRefresh", () => {
  function rec(): PairRefreshRecord {
    const now = Date.now();
    return {
      github_login: "alice",
      requested_scope: "mcp.read",
      created_at: now,
      expires_at: now + PAIR_REFRESH_TTL_SEC * 1000,
      last_used_at: null,
      revoked: false,
    };
  }

  it("bumps last_used_at without extending expires_at", async () => {
    const { env, kv } = envWithKv();
    const r = rec();
    await putPairRefresh(env, "h", r);
    const t = Date.now() + 1_000;
    const updated = await touchPairRefresh(env, "h", t);
    expect(updated?.last_used_at).toBe(t);
    expect(updated?.expires_at).toBe(r.expires_at);
    const stored = JSON.parse(kv._data["mcp/pair_refresh/h"]!) as PairRefreshRecord;
    expect(stored.last_used_at).toBe(t);
  });

  it("clamps TTL to 60s when remaining is nearly past", async () => {
    const { env, kv } = envWithKv();
    const now = Date.now();
    await putPairRefresh(env, "h", { ...rec(), expires_at: now + 1_000 });
    await touchPairRefresh(env, "h", now);
    expect(kv._ttls["mcp/pair_refresh/h"]).toBe(60);
  });

  it("returns null when record missing or KV unbound", async () => {
    const { env } = envWithKv();
    expect(await touchPairRefresh(env, "missing", Date.now())).toBeNull();
    const envNone = createMockEnv({ MCP_OAUTH_KV: undefined });
    expect(await touchPairRefresh(envNone, "h", Date.now())).toBeNull();
  });
});

describe("checkAndBumpGrantRateLimit", () => {
  it("allows up to 10/min per token hash, then rejects", async () => {
    const { env, kv } = envWithKv();
    const now = 60_000_000_000;
    for (let i = 0; i < 10; i++) {
      expect(await checkAndBumpGrantRateLimit(env, "h", now)).toBe(true);
    }
    expect(await checkAndBumpGrantRateLimit(env, "h", now)).toBe(false);
    const minute = Math.floor(now / 60_000);
    expect(kv._data[`mcp/pair_grant_rate/h/${minute}`]).toBe("10");
  });

  it("counts per token hash (different hashes do not interfere)", async () => {
    const { env } = envWithKv();
    const now = 60_000_000_000;
    for (let i = 0; i < 10; i++) await checkAndBumpGrantRateLimit(env, "h1", now);
    expect(await checkAndBumpGrantRateLimit(env, "h1", now)).toBe(false);
    expect(await checkAndBumpGrantRateLimit(env, "h2", now)).toBe(true);
  });

  it("custom limit and minute rollover work", async () => {
    const { env } = envWithKv();
    const t0 = 60_000_000_000;
    expect(await checkAndBumpGrantRateLimit(env, "h", t0, 2)).toBe(true);
    expect(await checkAndBumpGrantRateLimit(env, "h", t0, 2)).toBe(true);
    expect(await checkAndBumpGrantRateLimit(env, "h", t0, 2)).toBe(false);
    expect(await checkAndBumpGrantRateLimit(env, "h", t0 + 60_000, 2)).toBe(true);
  });

  it("returns true when KV not bound (best-effort)", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    expect(await checkAndBumpGrantRateLimit(env, "h", Date.now())).toBe(true);
  });

  it("rejects when stored counter is non-numeric", async () => {
    const { env, kv } = envWithKv();
    const now = 60_000_000_000;
    const minute = Math.floor(now / 60_000);
    kv._data[`mcp/pair_grant_rate/h/${minute}`] = "garbage";
    expect(await checkAndBumpGrantRateLimit(env, "h", now)).toBe(false);
  });
});

describe("approvePair — refresh_token plumbing (issue #157)", () => {
  it("writes refresh_token + refresh_token_expires_at when passed", async () => {
    const { env, kv } = envWithKv();
    await putPair(env, rec());
    const expiresAt = Date.now() + 1_000_000;
    const updated = await approvePair(env, "PC-test-1", "JWT", {
      token: "RT-opaque",
      expires_at: expiresAt,
    });
    expect(updated?.refresh_token).toBe("RT-opaque");
    expect(updated?.refresh_token_expires_at).toBe(expiresAt);
    const stored = JSON.parse(kv._data["mcp/pair/PC-test-1"]!) as PairRecord;
    expect(stored.refresh_token).toBe("RT-opaque");
    expect(stored.refresh_token_expires_at).toBe(expiresAt);
  });

  it("does not touch refresh_token fields when not passed (legacy path)", async () => {
    const { env, kv } = envWithKv();
    await putPair(env, rec());
    const updated = await approvePair(env, "PC-test-1", "JWT");
    expect(updated?.refresh_token).toBeUndefined();
    expect(updated?.refresh_token_expires_at).toBeUndefined();
    const stored = JSON.parse(kv._data["mcp/pair/PC-test-1"]!) as PairRecord;
    expect(stored.refresh_token).toBeUndefined();
  });
});
