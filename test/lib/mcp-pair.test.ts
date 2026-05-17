/**
 * `mcp-pair.ts` (issue #144) — KV schema + helpers のテスト。
 * KV mock を介して put/get/approve/delete/rate-limit を網羅する。
 */

import { describe, it, expect } from "vitest";
import {
  PAIR_CODE_TTL_SEC,
  approvePair,
  checkAndBumpRateLimit,
  deletePair,
  getPair,
  putPair,
  type PairRecord,
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
