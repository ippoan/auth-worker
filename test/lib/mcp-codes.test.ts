import { describe, it, expect } from "vitest";
import {
  generateDeviceCode,
  generatePairCode,
  generateUserCode,
} from "../../src/lib/mcp-codes";

describe("generateUserCode", () => {
  it("returns XXXX-XXXX format from 20-consonant alphabet", () => {
    const code = generateUserCode();
    expect(code).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
  });

  it("produces unique codes across 100 invocations (CSPRNG smoke test)", () => {
    const codes = new Set<string>();
    for (let i = 0; i < 100; i++) codes.add(generateUserCode());
    // 20^8 ≈ 2.56e10、100 件で衝突する確率は事実上 0
    expect(codes.size).toBe(100);
  });

  it("does not include ambiguous characters (0/O/1/I/U/A/E)", () => {
    // 1000 件サンプリングして紛らわしい文字が出ないこと確認
    for (let i = 0; i < 1000; i++) {
      const code = generateUserCode();
      expect(code).not.toMatch(/[0OI1UAE]/);
    }
  });
});

describe("generateDeviceCode", () => {
  it("returns 64 lowercase-hex characters (32 byte = 256 bit)", () => {
    const code = generateDeviceCode();
    expect(code).toMatch(/^[0-9a-f]{64}$/);
  });

  it("produces unique codes across 100 invocations", () => {
    const codes = new Set<string>();
    for (let i = 0; i < 100; i++) codes.add(generateDeviceCode());
    expect(codes.size).toBe(100);
  });
});

describe("generatePairCode (issue #144)", () => {
  it("returns 40 base64url characters from 30-byte CSPRNG", () => {
    const code = generatePairCode();
    // 30 byte = 240 bit = base64url 40 chars (no padding)
    expect(code).toMatch(/^[A-Za-z0-9_-]{40}$/);
  });

  it("never contains base64 '+' '/' '=' chars (URL-safe)", () => {
    for (let i = 0; i < 50; i++) {
      const code = generatePairCode();
      expect(code).not.toMatch(/[+/=]/);
    }
  });

  it("produces unique codes across 200 invocations (CSPRNG smoke test)", () => {
    const codes = new Set<string>();
    for (let i = 0; i < 200; i++) codes.add(generatePairCode());
    // 2^240 entropy なので 200 件で衝突は事実上 0
    expect(codes.size).toBe(200);
  });
});
