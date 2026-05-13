import { describe, it, expect } from "vitest";
import type { Env } from "../../src/index";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import {
  DEVICE_CODE_TTL_SEC,
  getDeviceCode,
  getDeviceCodeByUserCode,
  putDeviceCode,
  type DeviceCodeRecord,
} from "../../src/lib/mcp-kv";

function rec(overrides: Partial<DeviceCodeRecord> = {}): DeviceCodeRecord {
  const now = Date.now();
  return {
    device_code: "d".repeat(64),
    user_code: "BCDF-GHJK",
    client_id: "github-mcp-server-rs",
    scope: "mcp.read",
    status: "pending",
    created_at: now,
    expires_at: now + DEVICE_CODE_TTL_SEC * 1000,
    ...overrides,
  };
}

function envWithMcpKv(): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({ MCP_OAUTH_KV: kv });
  return { env, kv };
}

describe("putDeviceCode", () => {
  it("writes both device_code:* and user_code:* keys with 900s TTL", async () => {
    const { env, kv } = envWithMcpKv();
    const r = rec();
    await putDeviceCode(env, r);

    const stored = kv._data[`device_code:${r.device_code}`];
    expect(stored).toBeDefined();
    expect(JSON.parse(stored as string)).toEqual(r);

    expect(kv._data[`user_code:${r.user_code}`]).toBe(r.device_code);

    expect(kv._ttls[`device_code:${r.device_code}`]).toBe(900);
    expect(kv._ttls[`user_code:${r.user_code}`]).toBe(900);
  });

  it("throws if MCP_OAUTH_KV is not bound (fail-closed)", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    await expect(putDeviceCode(env, rec())).rejects.toThrow(/MCP_OAUTH_KV not bound/);
  });
});

describe("getDeviceCode", () => {
  it("returns parsed record on hit", async () => {
    const { env, kv } = envWithMcpKv();
    const r = rec({ device_code: "abc123" });
    kv._data[`device_code:abc123`] = JSON.stringify(r);

    const got = await getDeviceCode(env, "abc123");
    expect(got).toEqual(r);
  });

  it("returns null on miss", async () => {
    const { env } = envWithMcpKv();
    const got = await getDeviceCode(env, "nope");
    expect(got).toBeNull();
  });

  it("returns null on JSON parse error (defense-in-depth)", async () => {
    const { env, kv } = envWithMcpKv();
    kv._data[`device_code:bad`] = "not-json{";
    const got = await getDeviceCode(env, "bad");
    expect(got).toBeNull();
  });

  it("returns null if MCP_OAUTH_KV is not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    const got = await getDeviceCode(env, "anything");
    expect(got).toBeNull();
  });
});

describe("getDeviceCodeByUserCode", () => {
  it("returns device_code string on hit", async () => {
    const { env, kv } = envWithMcpKv();
    kv._data[`user_code:BCDF-GHJK`] = "device-xyz";
    const got = await getDeviceCodeByUserCode(env, "BCDF-GHJK");
    expect(got).toBe("device-xyz");
  });

  it("returns null on miss", async () => {
    const { env } = envWithMcpKv();
    const got = await getDeviceCodeByUserCode(env, "ZZZZ-ZZZZ");
    expect(got).toBeNull();
  });

  it("returns null if MCP_OAUTH_KV is not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    const got = await getDeviceCodeByUserCode(env, "anything");
    expect(got).toBeNull();
  });
});
