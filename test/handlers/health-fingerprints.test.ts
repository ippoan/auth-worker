/**
 * Tests for handleSecretFingerprint (Refs ippoan/auth-worker#274).
 *
 * Endpoint: GET /health/secret-fingerprint?name=<binding>&expected=<8hex>
 *   → 200 { match: bool }
 *
 * 値の hex は返さない。env 不在 / 値違い / typo は全て match:false に集約。
 */
import { describe, it, expect } from "vitest";
import type { Env } from "../../src/index";
import { createMockEnv } from "../helpers/mock-env";
import { handleSecretFingerprint } from "../../src/handlers/health-fingerprints";

async function sha256Prefix8(input: string): Promise<string> {
  const buf = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  const hex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return hex.slice(0, 8);
}

function makeRequest(name: string, expected: string): Request {
  const url = new URL("https://auth.test.example/health/secret-fingerprint");
  url.searchParams.set("name", name);
  url.searchParams.set("expected", expected);
  return new Request(url.toString());
}

describe("handleSecretFingerprint", () => {
  it("returns match:true for a string env binding whose sha256[0..8] matches", async () => {
    const env = createMockEnv({
      INTERNAL_SHARED_SECRET: "hello",
    } as unknown as Partial<Env>);
    const expected = await sha256Prefix8("hello");

    const res = await handleSecretFingerprint(
      makeRequest("INTERNAL_SHARED_SECRET", expected),
      env,
    );

    expect(res.status).toBe(200);
    const body = await res.json() as { match: boolean };
    expect(body).toEqual({ match: true });
    // hex 値や length を絶対に echo しない
    expect(JSON.stringify(body)).not.toContain(expected);
  });

  it("returns match:false when the expected prefix mismatches", async () => {
    const env = createMockEnv({
      INTERNAL_SHARED_SECRET: "hello",
    } as unknown as Partial<Env>);

    const res = await handleSecretFingerprint(
      makeRequest("INTERNAL_SHARED_SECRET", "deadbeef"),
      env,
    );

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ match: false });
  });

  it("returns match:false when the env binding is missing (no oracle on name typo)", async () => {
    const env = createMockEnv();
    const expected = await sha256Prefix8("hello");

    const res = await handleSecretFingerprint(
      makeRequest("INTERNAL_SHARED_SECRET_TYPO", expected),
      env,
    );

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ match: false });
  });

  it("returns match:true for a Secrets Store binding (object with async .get())", async () => {
    const expected = await sha256Prefix8("from-store");
    const fakeBinding = {
      get: async () => "from-store",
    };
    const env = createMockEnv({
      INTERNAL_SHARED_SECRET: fakeBinding as unknown as string,
    } as unknown as Partial<Env>);

    const res = await handleSecretFingerprint(
      makeRequest("INTERNAL_SHARED_SECRET", expected),
      env,
    );

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ match: true });
  });

  it("returns match:false when the Secrets Store binding .get() throws", async () => {
    const fakeBinding = {
      get: async () => {
        throw new Error("store unavailable");
      },
    };
    const env = createMockEnv({
      INTERNAL_SHARED_SECRET: fakeBinding as unknown as string,
    } as unknown as Partial<Env>);

    const res = await handleSecretFingerprint(
      makeRequest("INTERNAL_SHARED_SECRET", "deadbeef"),
      env,
    );

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ match: false });
  });

  it("returns 400 on missing or invalid name (non-200 surfaces query bugs to CI)", async () => {
    const env = createMockEnv();
    const url = new URL("https://auth.test.example/health/secret-fingerprint");
    url.searchParams.set("expected", "deadbeef");
    const res = await handleSecretFingerprint(new Request(url.toString()), env);
    expect(res.status).toBe(400);
  });

  it("returns 400 on name with invalid characters", async () => {
    const env = createMockEnv();
    const res = await handleSecretFingerprint(
      makeRequest("BAD NAME!", "deadbeef"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 on expected with wrong length", async () => {
    const env = createMockEnv();
    const res = await handleSecretFingerprint(
      makeRequest("INTERNAL_SHARED_SECRET", "deadbe"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 on expected with non-hex characters", async () => {
    const env = createMockEnv();
    const res = await handleSecretFingerprint(
      makeRequest("INTERNAL_SHARED_SECRET", "ZZZZZZZZ"),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("works for an arbitrary env name (not limited to INTERNAL_SHARED_SECRET)", async () => {
    const env = createMockEnv({
      OAUTH_STATE_SECRET: "different-secret-here",
    } as unknown as Partial<Env>);
    const expected = await sha256Prefix8("different-secret-here");

    const res = await handleSecretFingerprint(
      makeRequest("OAUTH_STATE_SECRET", expected),
      env,
    );

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ match: true });
  });

  it("returns Content-Type application/json + no-store cache + CORS *", async () => {
    const env = createMockEnv({
      INTERNAL_SHARED_SECRET: "hello",
    } as unknown as Partial<Env>);
    const expected = await sha256Prefix8("hello");

    const res = await handleSecretFingerprint(
      makeRequest("INTERNAL_SHARED_SECRET", expected),
      env,
    );

    expect(res.headers.get("Content-Type")).toBe("application/json");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });
});
