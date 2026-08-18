import { describe, it, expect } from "vitest";
import { createMockKV, type MockKV } from "../helpers/mock-env";
import {
  OIDC_ACCESS_TOKEN_TTL_SEC,
  OIDC_CODE_TTL_SEC,
  generateOidcOpaqueToken,
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

describe("putOidcCode / takeOidcCode", () => {
  it("round-trips the record", async () => {
    const kv = createMockKV();
    await putOidcCode(kv, "c1", RECORD);
    expect(await takeOidcCode(kv, "c1")).toEqual(RECORD);
  });

  it("stores under an `oidc:` prefix so it cannot collide with MCP keys", async () => {
    const kv = createMockKV();
    await putOidcCode(kv, "c1", RECORD);
    expect(Object.keys((kv as unknown as MockKV)._data)).toEqual(["oidc:code:c1"]);
  });

  it("applies the short authorization-code TTL", async () => {
    const kv = createMockKV();
    await putOidcCode(kv, "c1", RECORD);
    expect((kv as unknown as MockKV)._ttls["oidc:code:c1"]).toBe(OIDC_CODE_TTL_SEC);
    expect(OIDC_CODE_TTL_SEC).toBeLessThanOrEqual(600); // RFC 6749 §4.1.2 の上限
  });

  it("is single-use — the second take returns null", async () => {
    const kv = createMockKV();
    await putOidcCode(kv, "c1", RECORD);
    expect(await takeOidcCode(kv, "c1")).not.toBeNull();
    expect(await takeOidcCode(kv, "c1")).toBeNull();
  });

  it("returns null for an unknown code", async () => {
    expect(await takeOidcCode(createMockKV(), "missing")).toBeNull();
  });

  it("returns null for a corrupted record — and still deletes it", async () => {
    const kv = createMockKV({ "oidc:code:c1": "{broken" });
    expect(await takeOidcCode(kv, "c1")).toBeNull();
    expect((kv as unknown as MockKV)._data["oidc:code:c1"]).toBeUndefined();
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
