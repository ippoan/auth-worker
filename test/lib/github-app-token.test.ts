/**
 * `signAppJwt` — GitHub App RS256 JWT 形式の検証。実 RSA key を生成して
 * `crypto.subtle` でラウンドトリップしたいところだが、Cloudflare runtime
 * (vanilla node) 環境では `RSASSA-PKCS1-v1_5` の sign 自体は使えるので
 * 既存 `lineworks-bot-api.test.ts` と同じ FAKE_PEM パターンで importKey は
 * mock し、signAppJwt が組み立てる **header/payload の形** を検証する。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { signAppJwt, base64UrlEncode, pemToCryptoKey } from "../../src/lib/github-app-token";

const FAKE_PEM = `-----BEGIN PRIVATE KEY-----
MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA0Z3VS5JJcds3xf0G
PGdqwYx0KVT5ePCMNkjaWOL0tEJhvsud4JL7dMtXEfehfslDrV5Rcqeqr3rSDGOu
cQIDAQABAkEAhZ3MsMYTs1Eiiekn8bfGd2sdU86WnKpynHjN+SWM3ePaiT6vK7sn
rDWCa3FG9vSzaxmQzSgMxlu5/5BffMVwwQIhAPe9lON+rnTiAhgKn3CKaaLz9Ave
eJR5k0VhTCGo/xThAiEA2S7qcIFrPZsT3F0T0G03JaKwrp4pCCe9xAvHtEVqxOkC
IEIuexLVNq3sCQ1DQ3TiRkZI2U7ChC4FaLzfhJKdLPIhAiEAgYLnkBbQfbvUDJYV
cRaQMwCdV7KNfJi7Llgwdmn+Y/kCIQDW5ndbYcIktYeKJC2qX20V8CeBVw+Yq5pJ
WJnH2j3VAw==
-----END PRIVATE KEY-----`;

function base64UrlDecode(s: string): string {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return atob(padded);
}

describe("base64UrlEncode", () => {
  it("encodes Uint8Array without padding and with url-safe alphabet", () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xfe]);
    expect(base64UrlEncode(bytes)).toBe("-__-");
  });

  it("encodes empty Uint8Array as empty string", () => {
    expect(base64UrlEncode(new Uint8Array(0))).toBe("");
  });

  it("encodes ASCII strings", () => {
    expect(base64UrlEncode("ab")).toBe("YWI");
  });
});

describe("pemToCryptoKey", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const g = globalThis as any;
  let originalSubtle: SubtleCrypto | undefined;
  beforeEach(() => {
    originalSubtle = g.crypto?.subtle;
  });
  afterEach(() => {
    if (originalSubtle) {
      Object.defineProperty(g.crypto, "subtle", {
        value: originalSubtle,
        configurable: true,
      });
    }
  });

  it("calls subtle.importKey with pkcs8 + RSASSA-PKCS1-v1_5 / SHA-256", async () => {
    const mockImportKey = vi.fn().mockResolvedValue({ type: "private" });
    Object.defineProperty(g.crypto, "subtle", {
      value: { importKey: mockImportKey, sign: vi.fn() },
      configurable: true,
    });
    await pemToCryptoKey(FAKE_PEM);
    expect(mockImportKey).toHaveBeenCalledTimes(1);
    const call = mockImportKey.mock.calls[0]!;
    expect(call[0]).toBe("pkcs8");
    // ArrayBuffer (decoded base64)
    expect(call[1]).toBeInstanceOf(ArrayBuffer);
    expect(call[2]).toEqual({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" });
    expect(call[3]).toBe(false);
    expect(call[4]).toEqual(["sign"]);
  });

  it("strips BEGIN/END markers and whitespace before decoding", async () => {
    const mockImportKey = vi.fn().mockResolvedValue({ type: "private" });
    Object.defineProperty(g.crypto, "subtle", {
      value: { importKey: mockImportKey, sign: vi.fn() },
      configurable: true,
    });
    await pemToCryptoKey(FAKE_PEM);
    // decode arg #1 (ArrayBuffer) length must equal the base64-decoded body length
    const buf = mockImportKey.mock.calls[0]![1] as ArrayBuffer;
    expect(buf.byteLength).toBeGreaterThan(100);
  });
});

describe("signAppJwt", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const g = globalThis as any;
  let originalSubtle: SubtleCrypto | undefined;
  beforeEach(() => {
    originalSubtle = g.crypto?.subtle;
  });
  afterEach(() => {
    if (originalSubtle) {
      Object.defineProperty(g.crypto, "subtle", {
        value: originalSubtle,
        configurable: true,
      });
    }
  });

  it("produces a 3-segment JWT with RS256 header and correct iss/iat/exp", async () => {
    const fakeSig = new ArrayBuffer(8);
    new Uint8Array(fakeSig).set([1, 2, 3, 4, 5, 6, 7, 8]);
    const mockSign = vi.fn().mockResolvedValue(fakeSig);
    Object.defineProperty(g.crypto, "subtle", {
      value: { importKey: vi.fn().mockResolvedValue({}), sign: mockSign },
      configurable: true,
    });
    const key = await pemToCryptoKey(FAKE_PEM);
    const now = 1_700_000_000;
    const token = await signAppJwt("123456", key, now);
    const parts = token.split(".");
    expect(parts).toHaveLength(3);
    const header = JSON.parse(base64UrlDecode(parts[0]!));
    expect(header).toEqual({ alg: "RS256", typ: "JWT" });
    const payload = JSON.parse(base64UrlDecode(parts[1]!));
    expect(payload).toEqual({
      iss: "123456",
      iat: now - 60,
      exp: now + 540,
    });
    // signature segment is base64url of the mocked signature bytes
    expect(parts[2]).toBe(base64UrlEncode(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])));
    // subtle.sign must be invoked with RSASSA-PKCS1-v1_5
    expect(mockSign.mock.calls[0]![0]).toBe("RSASSA-PKCS1-v1_5");
  });
});
