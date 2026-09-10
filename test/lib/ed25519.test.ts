import { describe, it, expect, vi } from "vitest";
import nodeCrypto from "node:crypto";
import { verifyEd25519 } from "../../src/lib/ed25519";

function generateKeypair(): { pubRaw: Uint8Array; privateKey: nodeCrypto.KeyObject } {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ed25519");
  const pubDer = publicKey.export({ format: "der", type: "spki" });
  const pubRaw = new Uint8Array(pubDer.subarray(pubDer.length - 32));
  return { pubRaw, privateKey };
}

describe("verifyEd25519", () => {
  it("returns true for a valid signature (Node WebCrypto Ed25519, same API confirmed on workerd for #522)", async () => {
    const { pubRaw, privateKey } = generateKeypair();
    const msg = new TextEncoder().encode("0123456789abcdef0123456789abcdef");
    const sig = new Uint8Array(nodeCrypto.sign(null, Buffer.from(msg), privateKey));
    await expect(verifyEd25519(pubRaw, sig, msg)).resolves.toBe(true);
  });

  it("returns false for a tampered signature", async () => {
    const { pubRaw, privateKey } = generateKeypair();
    const msg = new TextEncoder().encode("0123456789abcdef0123456789abcdef");
    const sig = new Uint8Array(nodeCrypto.sign(null, Buffer.from(msg), privateKey));
    sig[0] = sig[0]! ^ 0xff;
    await expect(verifyEd25519(pubRaw, sig, msg)).resolves.toBe(false);
  });

  it("returns false for a wrong-length pubkey (fail-closed guard, not delegated to WebCrypto)", async () => {
    await expect(
      verifyEd25519(new Uint8Array(31), new Uint8Array(64), new Uint8Array(0)),
    ).resolves.toBe(false);
  });

  it("returns false for a wrong-length signature", async () => {
    await expect(
      verifyEd25519(new Uint8Array(32), new Uint8Array(63), new Uint8Array(0)),
    ).resolves.toBe(false);
  });

  it("returns false (fail-closed) when WebCrypto itself throws", async () => {
    // `node:crypto` の `webcrypto` は auth-worker のソースが参照するグローバル
    // `crypto` (Workers 環境の ambient `crypto: Crypto`) と実行時に同一オブジェクト
    // (Node v24 で確認済み)。src 側の import を変えずに spy できる。
    const spy = vi
      .spyOn(nodeCrypto.webcrypto.subtle, "importKey")
      .mockRejectedValueOnce(new Error("boom"));
    try {
      await expect(
        verifyEd25519(new Uint8Array(32), new Uint8Array(64), new Uint8Array(0)),
      ).resolves.toBe(false);
    } finally {
      spy.mockRestore();
    }
  });
});
