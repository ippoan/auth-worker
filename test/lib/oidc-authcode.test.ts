import { describe, it, expect, vi } from "vitest";
import {
  createMockAlarmNonceDO,
  createMockEnv,
  createMockKV,
  type MockAlarmNonceNamespace,
  type MockKV,
} from "../helpers/mock-env";
import type { Env } from "../../src/index";
import {
  OIDC_ACCESS_TOKEN_TTL_SEC,
  OIDC_CODE_TTL_SEC,
  generateOidcOpaqueToken,
  oidcCodeStore,
  getOidcAccessTokenClaims,
  putOidcAccessToken,
  putOidcCode,
  takeOidcCode,
  type OidcCodeRecord,
} from "../../src/lib/oidc-authcode";

const RECORD: OidcCodeRecord = {
  client_id: "cf-access",
  redirect_uri: "https://team.cloudflareaccess.com/cdn-cgi/access/callback",
  nonce: "n-1",
  code_challenge: "chal",
  scope: "openid email",
  claims: { sub: "u1", email: "a@example.com", tenant_id: "t1", role: "admin" },
};

describe("generateOidcOpaqueToken", () => {
  it("is URL-safe base64 with no padding", () => {
    expect(generateOidcOpaqueToken()).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("does not repeat across calls", () => {
    const seen = new Set(Array.from({ length: 50 }, () => generateOidcOpaqueToken()));
    expect(seen.size).toBe(50);
  });
});

describe("putOidcCode / takeOidcCode (Durable Object)", () => {
  function envWithDO(): { env: Env; ns: MockAlarmNonceNamespace } {
    const ns = createMockAlarmNonceDO();
    return { env: createMockEnv({ ALARM_NONCE_DO: ns }), ns };
  }

  it("round-trips the record", async () => {
    const { env } = envWithDO();
    await putOidcCode(env, "c1", RECORD);
    expect(await takeOidcCode(env, "c1")).toEqual(RECORD);
  });

  it("stores under an `oidc:code:` prefix with an exp the DO alarm can sweep", async () => {
    const { env, ns } = envWithDO();
    const before = Math.floor(Date.now() / 1000);
    await putOidcCode(env, "c1", RECORD);
    expect(Object.keys(ns._data)).toEqual(["oidc:code:c1"]);
    const { exp } = JSON.parse(ns._data["oidc:code:c1"] as string) as { exp: number };
    expect(exp - before).toBeGreaterThanOrEqual(OIDC_CODE_TTL_SEC);
    expect(exp - before).toBeLessThanOrEqual(OIDC_CODE_TTL_SEC + 1);
    expect(OIDC_CODE_TTL_SEC).toBeLessThanOrEqual(600); // RFC 6749 §4.1.2 の上限
  });

  it("uses its own DO instance placed in apac-ne (not the device-nonce one)", async () => {
    const { env, ns } = envWithDO();
    const idFromName = vi.spyOn(ns, "idFromName");
    oidcCodeStore(env);
    expect(idFromName).toHaveBeenCalledWith("oidc-code");
    // デバイス nonce・回数制限の `global` インスタンスとは別 (key も `oidc:code:` で `devnonce:`・`rate:` と重ならない)
    expect(idFromName).not.toHaveBeenCalledWith("global");
    expect(ns._hints).toEqual(["apac-ne"]);
  });

  it("is readable right after the write from a different worker instance", async () => {
    const ns = createMockAlarmNonceDO();
    await putOidcCode(createMockEnv({ ALARM_NONCE_DO: ns }), "c1", RECORD);
    expect(await takeOidcCode(createMockEnv({ ALARM_NONCE_DO: ns }), "c1")).toEqual(RECORD);
  });

  it("is single-use — the second take returns null", async () => {
    const { env } = envWithDO();
    await putOidcCode(env, "c1", RECORD);
    expect(await takeOidcCode(env, "c1")).not.toBeNull();
    expect(await takeOidcCode(env, "c1")).toBeNull();
  });

  it("returns null for an unknown code", async () => {
    expect(await takeOidcCode(envWithDO().env, "missing")).toBeNull();
  });

  it("returns null once the TTL has passed — and still deletes it", async () => {
    const { env, ns } = envWithDO();
    await putOidcCode(env, "c1", RECORD);
    vi.useFakeTimers({ now: Date.now() + OIDC_CODE_TTL_SEC * 1000 });
    try {
      expect(await takeOidcCode(env, "c1")).toBeNull();
    } finally {
      vi.useRealTimers();
    }
    expect(ns._data["oidc:code:c1"]).toBeUndefined();
  });

  it("returns null for a record without exp", async () => {
    const { env, ns } = envWithDO();
    ns._data["oidc:code:c1"] = JSON.stringify(RECORD);
    expect(await takeOidcCode(env, "c1")).toBeNull();
  });

  it("returns null for a corrupted record — and still deletes it", async () => {
    const { env, ns } = envWithDO();
    ns._data["oidc:code:c1"] = "{broken";
    expect(await takeOidcCode(env, "c1")).toBeNull();
    expect(ns._data["oidc:code:c1"]).toBeUndefined();
  });
});

describe("putOidcAccessToken / getOidcAccessTokenClaims", () => {
  it("round-trips the identity claims", async () => {
    const kv = createMockKV();
    await putOidcAccessToken(kv, "at1", RECORD.claims);
    expect(await getOidcAccessTokenClaims(kv, "at1")).toEqual(RECORD.claims);
  });

  it("stores under its own prefix with the access-token TTL", async () => {
    const kv = createMockKV();
    await putOidcAccessToken(kv, "at1", RECORD.claims);
    expect((kv as unknown as MockKV)._ttls["oidc:at:at1"]).toBe(OIDC_ACCESS_TOKEN_TTL_SEC);
  });

  it("is NOT single-use — repeated reads keep working within the TTL", async () => {
    const kv = createMockKV();
    await putOidcAccessToken(kv, "at1", RECORD.claims);
    expect(await getOidcAccessTokenClaims(kv, "at1")).not.toBeNull();
    expect(await getOidcAccessTokenClaims(kv, "at1")).not.toBeNull();
  });

  it("returns null for an unknown token", async () => {
    expect(await getOidcAccessTokenClaims(createMockKV(), "nope")).toBeNull();
  });

  it("returns null for a corrupted record", async () => {
    expect(await getOidcAccessTokenClaims(createMockKV({ "oidc:at:at1": "{x" }), "at1")).toBeNull();
  });
});
