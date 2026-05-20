/**
 * `mcp-oat-binding.ts` (issues ippoan/auth-worker#174, #176) — KV layer
 * のテスト。KV mock を介して hashOat / put / get / TTL 計算と
 * #176 の org_uuid binding / UUID validation / response header 抽出を網羅。
 */

import { describe, it, expect } from "vitest";
import {
  OAT_BINDING_TTL_SEC,
  type OatBindingRecord,
  extractOrgUuidFromResponse,
  getOatBinding,
  getOrgBinding,
  hashOat,
  isValidOrgUuid,
  putOatBinding,
  putOrgBinding,
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

// ── #176 org_uuid binding tests ─────────────────────────────────────────

const VALID_ORG_UUID = "bbe9480d-6a09-4689-92d2-7197609417fe";

describe("isValidOrgUuid", () => {
  it.each([
    ["bbe9480d-6a09-4689-92d2-7197609417fe", true],
    ["11111111-2222-3333-4444-555555555555", true],
    ["00000000-0000-0000-0000-000000000000", true],
    // wrong cases / format violations
    ["BBE9480D-6A09-4689-92D2-7197609417FE", false], // uppercase
    ["bbe9480d-6a09-4689-92d2-7197609417f", false], // too short
    ["bbe9480d-6a09-4689-92d2-7197609417fe0", false], // too long
    ["bbe9480d_6a09_4689_92d2_7197609417fe", false], // wrong separator
    ["", false],
    ["not-a-uuid", false],
    ["bbe9480d-6a09-4689-92d2-7197609417fg", false], // non-hex char
  ])("isValidOrgUuid(%s) === %s", (input, expected) => {
    expect(isValidOrgUuid(input)).toBe(expected);
  });
});

describe("putOrgBinding / getOrgBinding", () => {
  it("round-trips a record through KV with org_uuid: prefix", async () => {
    const { env, kv } = envWithKv();
    const r = rec();
    await putOrgBinding(env, VALID_ORG_UUID, r);
    expect(kv._data[`org_uuid:${VALID_ORG_UUID}`]).toBeDefined();
    const got = await getOrgBinding(env, VALID_ORG_UUID);
    expect(got).toEqual(r);
  });

  it("getOrgBinding returns null for missing key", async () => {
    const { env } = envWithKv();
    const got = await getOrgBinding(env, VALID_ORG_UUID);
    expect(got).toBeNull();
  });

  it("getOrgBinding returns null when KV not bound", async () => {
    const env = createMockEnv({});
    delete (env as { MCP_OAUTH_KV?: unknown }).MCP_OAUTH_KV;
    const got = await getOrgBinding(
      env as ReturnType<typeof createMockEnv>,
      VALID_ORG_UUID,
    );
    expect(got).toBeNull();
  });

  it("getOrgBinding returns null for invalid UUID format (= sanitization)", async () => {
    const { env } = envWithKv();
    const got = await getOrgBinding(env, "not-a-uuid");
    expect(got).toBeNull();
  });

  it("getOrgBinding returns null when stored JSON is corrupt", async () => {
    const { env, kv } = envWithKv();
    kv._data[`org_uuid:${VALID_ORG_UUID}`] = "{broken-json";
    const got = await getOrgBinding(env, VALID_ORG_UUID);
    expect(got).toBeNull();
  });

  it("putOrgBinding throws when KV not bound", async () => {
    const env = createMockEnv({});
    delete (env as { MCP_OAUTH_KV?: unknown }).MCP_OAUTH_KV;
    await expect(
      putOrgBinding(
        env as ReturnType<typeof createMockEnv>,
        VALID_ORG_UUID,
        rec(),
      ),
    ).rejects.toThrow(/MCP_OAUTH_KV/);
  });

  it("putOrgBinding throws on invalid UUID format (= KV key injection guard)", async () => {
    const { env } = envWithKv();
    await expect(
      putOrgBinding(env, "not-a-uuid; DROP TABLE", rec()),
    ).rejects.toThrow(/invalid org_uuid format/);
  });

  it("clamps TTL to 60s minimum", async () => {
    const { env, kv } = envWithKv();
    const r = rec({ expires_at: Date.now() + 1000 });
    await putOrgBinding(env, VALID_ORG_UUID, r);
    expect(kv._ttls[`org_uuid:${VALID_ORG_UUID}`]).toBe(60);
  });
});

describe("extractOrgUuidFromResponse", () => {
  function resp(headerValue?: string | null): Response {
    const headers: Record<string, string> = {};
    if (headerValue !== undefined && headerValue !== null) {
      headers["anthropic-organization-id"] = headerValue;
    }
    return new Response("{}", { status: 200, headers });
  }

  it("returns lowercased UUID when header is present", () => {
    expect(extractOrgUuidFromResponse(resp(VALID_ORG_UUID))).toBe(VALID_ORG_UUID);
  });

  it("normalizes uppercase / mixed case to lowercase", () => {
    expect(
      extractOrgUuidFromResponse(resp("BBE9480D-6A09-4689-92D2-7197609417FE")),
    ).toBe(VALID_ORG_UUID);
  });

  it("trims surrounding whitespace", () => {
    expect(extractOrgUuidFromResponse(resp(`  ${VALID_ORG_UUID}  `))).toBe(
      VALID_ORG_UUID,
    );
  });

  it("returns null when header is missing", () => {
    expect(extractOrgUuidFromResponse(resp())).toBeNull();
  });

  it("returns null when header value is not a valid UUID", () => {
    expect(extractOrgUuidFromResponse(resp("garbage"))).toBeNull();
    expect(extractOrgUuidFromResponse(resp(""))).toBeNull();
  });
});
