/**
 * `mcp-oat-binding.ts` (issue ippoan/auth-worker#174) — KV layer のテスト。
 * KV mock を介して hashOat / put / get / TTL 計算を網羅する。
 */

import { describe, it, expect } from "vitest";
import {
  OAT_BINDING_TTL_SEC,
  type OatBindingRecord,
  getOatBinding,
  hashOat,
  putOatBinding,
} from "../../src/lib/mcp-oat-binding";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";

function envWithKv(): { env: ReturnType<typeof createMockEnv>; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({ MCP_OAUTH_KV: kv });
  return { env, kv };
}

function rec(overrides: Partial<OatBindingRecord> = {}): OatBindingRecord {
  const now = Date.now();
  return {
    github_login: "alice",
    bound_at: now,
    expires_at: now + OAT_BINDING_TTL_SEC * 1000,
    ...overrides,
  };
}

describe("hashOat", () => {
  it("returns 64-char lowercase hex sha256", async () => {
    const h = await hashOat("sk-ant-oat01-deadbeef");
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic for the same input", async () => {
    const a = await hashOat("sk-ant-oat01-xxxx");
    const b = await hashOat("sk-ant-oat01-xxxx");
    expect(a).toBe(b);
  });

  it("differs for different inputs", async () => {
    const a = await hashOat("token-a");
    const b = await hashOat("token-b");
    expect(a).not.toBe(b);
  });
});

describe("putOatBinding / getOatBinding", () => {
  it("round-trips a record through KV with ~30d TTL", async () => {
    const { env, kv } = envWithKv();
    const h = await hashOat("token-x");
    const r = rec();
    await putOatBinding(env, h, r);
    // ms gap between rec()'s Date.now() and putOatBinding's Date.now() means
    // Math.floor((expires_at - now) / 1000) may be 1 short — allow ±2s tolerance.
    const ttl = kv._ttls[`oat_hash:${h}`] as number;
    expect(ttl).toBeGreaterThanOrEqual(OAT_BINDING_TTL_SEC - 2);
    expect(ttl).toBeLessThanOrEqual(OAT_BINDING_TTL_SEC);
    const got = await getOatBinding(env, h);
    expect(got).toEqual(r);
  });

  it("returns null for missing key", async () => {
    const { env } = envWithKv();
    const got = await getOatBinding(env, "nonexistent");
    expect(got).toBeNull();
  });

  it("returns null when KV not bound", async () => {
    const env = createMockEnv({});
    delete (env as { MCP_OAUTH_KV?: unknown }).MCP_OAUTH_KV;
    const got = await getOatBinding(env as ReturnType<typeof createMockEnv>, "h");
    expect(got).toBeNull();
  });

  it("returns null when stored JSON is corrupt", async () => {
    const { env, kv } = envWithKv();
    kv._data["oat_hash:corrupt"] = "{not-json";
    const got = await getOatBinding(env, "corrupt");
    expect(got).toBeNull();
  });

  it("throws on put when KV not bound", async () => {
    const env = createMockEnv({});
    delete (env as { MCP_OAUTH_KV?: unknown }).MCP_OAUTH_KV;
    await expect(
      putOatBinding(env as ReturnType<typeof createMockEnv>, "h", rec()),
    ).rejects.toThrow(/MCP_OAUTH_KV/);
  });

  it("clamps TTL to 60s minimum when expires_at is nearly now", async () => {
    const { env, kv } = envWithKv();
    const r = rec({ expires_at: Date.now() + 1000 }); // < 60s
    await putOatBinding(env, "h2", r);
    expect(kv._ttls[`oat_hash:h2`]).toBe(60);
  });
});
