/**
 * `src/lib/mcp-pkce.ts` unit test (Phase 5 / #128).
 *
 * RFC 7636 §4.6 S256 PKCE 検証ロジックを確認。test vector は RFC 7636 Appendix B
 * の Sample Authorization (verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
 * → challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM").
 */

import { describe, it, expect } from "vitest";
import { verifyPkceS256 } from "../../src/lib/mcp-pkce";

describe("verifyPkceS256", () => {
  const RFC7636_VERIFIER =
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const RFC7636_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

  it("accepts the RFC 7636 sample verifier/challenge pair", async () => {
    expect(await verifyPkceS256(RFC7636_VERIFIER, RFC7636_CHALLENGE)).toBe(true);
  });

  it("rejects mismatched verifier", async () => {
    expect(await verifyPkceS256("wrong-verifier", RFC7636_CHALLENGE)).toBe(false);
  });

  it("rejects mismatched challenge", async () => {
    expect(await verifyPkceS256(RFC7636_VERIFIER, "wrong-challenge")).toBe(false);
  });

  it("returns false for empty verifier", async () => {
    expect(await verifyPkceS256("", RFC7636_CHALLENGE)).toBe(false);
  });

  it("returns false for empty expected challenge", async () => {
    expect(await verifyPkceS256(RFC7636_VERIFIER, "")).toBe(false);
  });
});
