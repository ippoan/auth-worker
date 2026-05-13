import { describe, it, expect } from "vitest";
import { generateDeviceCode, generateUserCode } from "../../src/lib/mcp-codes";

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
