import { describe, it, expect } from "vitest";
import {
  generateCodeVerifier,
  generateState,
  computeCodeChallenge,
  base64UrlEncode,
} from "../src/pkce";

describe("generateCodeVerifier", () => {
  it("returns a 43-char base64url string (RFC 7636 minimum)", () => {
    const v = generateCodeVerifier();
    expect(v).toHaveLength(43);
    // RFC 7636 §4.1: unreserved char set after base64url
    expect(v).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("produces a fresh verifier on each call (≥ 64 bits of entropy implied)", () => {
    const a = generateCodeVerifier();
    const b = generateCodeVerifier();
    expect(a).not.toBe(b);
  });
});

describe("generateState", () => {
  it("returns a 22-char base64url string (16 random bytes)", () => {
    const s = generateState();
    expect(s).toHaveLength(22);
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("is non-deterministic across calls", () => {
    expect(generateState()).not.toBe(generateState());
  });
});

describe("computeCodeChallenge (S256)", () => {
  it("produces a base64url SHA-256 hash of the verifier", async () => {
    // RFC 7636 §B.1 test vector:
    //   code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    //   code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    const v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const c = await computeCodeChallenge(v);
    expect(c).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  it("is deterministic for a given verifier", async () => {
    const v = generateCodeVerifier();
    const a = await computeCodeChallenge(v);
    const b = await computeCodeChallenge(v);
    expect(a).toBe(b);
  });
});

describe("base64UrlEncode", () => {
  it("strips padding and uses URL-safe alphabet", () => {
    // "hello" → SGVsbG8= (standard base64) → SGVsbG8 (URL-safe, padding stripped)
    expect(base64UrlEncode(new TextEncoder().encode("hello"))).toBe("aGVsbG8");
    // bytes that trigger `+` / `/` in standard base64
    expect(base64UrlEncode(new Uint8Array([0xff, 0xfe, 0xfd]))).toBe("__79");
  });
});
