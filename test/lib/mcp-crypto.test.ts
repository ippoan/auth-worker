import { describe, it, expect } from "vitest";
import { encryptWithKey, decryptWithKey } from "../../src/lib/mcp-crypto";

const KEY = "test-encryption-key-material-32!";

describe("mcp-crypto", () => {
  it("roundtrip: encrypt → decrypt returns the same plaintext", async () => {
    const plain = "gho_test_github_token_value";
    const ct = await encryptWithKey(plain, KEY);
    const recovered = await decryptWithKey(ct, KEY);
    expect(recovered).toBe(plain);
  });

  it("produces different ciphertext on every call (random IV)", async () => {
    const plain = "same-plaintext";
    const a = await encryptWithKey(plain, KEY);
    const b = await encryptWithKey(plain, KEY);
    expect(a).not.toBe(b);
    expect(await decryptWithKey(a, KEY)).toBe(plain);
    expect(await decryptWithKey(b, KEY)).toBe(plain);
  });

  it("rejects decryption with wrong key", async () => {
    const ct = await encryptWithKey("payload", KEY);
    await expect(decryptWithKey(ct, "different-key-material!")).rejects.toThrow();
  });

  it("throws on ciphertext shorter than nonce+tag", async () => {
    // 12+16 = 28 bytes minimum; "AAAAAA" (base64 of 4 bytes) is too short
    await expect(decryptWithKey("AAAAAA", KEY)).rejects.toThrow(/too short/);
  });

  it("handles unicode plaintext", async () => {
    const plain = "認証完了 🔐 GitHub token data";
    const ct = await encryptWithKey(plain, KEY);
    expect(await decryptWithKey(ct, KEY)).toBe(plain);
  });
});
