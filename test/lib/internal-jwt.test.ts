import { describe, expect, test } from "vitest";
import { signInternalJWT } from "../../src/lib/internal-jwt";

describe("signInternalJWT", () => {
  test("produces 3-segment HS256 JWT", async () => {
    const jwt = await signInternalJWT({ JWT_SECRET: "test-secret" });
    const parts = jwt.split(".");
    expect(parts).toHaveLength(3);
  });

  test("payload contains aud=alc-api-internal and iss=auth-worker", async () => {
    const jwt = await signInternalJWT({ JWT_SECRET: "test-secret" });
    const parts = jwt.split(".");
    const payload = JSON.parse(b64UrlDecodeString(parts[1] ?? ""));
    expect(payload.aud).toBe("alc-api-internal");
    expect(payload.iss).toBe("auth-worker");
  });

  test("default ttl 60s yields exp ≈ now+60", async () => {
    const before = Math.floor(Date.now() / 1000);
    const jwt = await signInternalJWT({ JWT_SECRET: "test-secret" });
    const after = Math.floor(Date.now() / 1000);
    const payload = JSON.parse(b64UrlDecodeString(jwt.split(".")[1] ?? ""));
    expect(payload.exp).toBeGreaterThanOrEqual(before + 60);
    expect(payload.exp).toBeLessThanOrEqual(after + 60);
  });

  test("custom ttl is respected", async () => {
    const jwt = await signInternalJWT({ JWT_SECRET: "test-secret" }, 600);
    const payload = JSON.parse(b64UrlDecodeString(jwt.split(".")[1] ?? ""));
    expect(payload.exp - payload.iat).toBe(600);
  });

  test("header is alg=HS256 typ=JWT", async () => {
    const jwt = await signInternalJWT({ JWT_SECRET: "test-secret" });
    const header = JSON.parse(b64UrlDecodeString(jwt.split(".")[0] ?? ""));
    expect(header.alg).toBe("HS256");
    expect(header.typ).toBe("JWT");
  });

  test("signature verifies with same secret", async () => {
    const secret = "test-secret-256-bits-long";
    const jwt = await signInternalJWT({ JWT_SECRET: secret });
    const [headerB64, payloadB64, sigB64] = jwt.split(".") as [string, string, string];
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const sigBytes = b64UrlDecodeBytes(sigB64);
    const ok = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBytes,
      enc.encode(`${headerB64}.${payloadB64}`),
    );
    expect(ok).toBe(true);
  });
});

function b64UrlDecodeString(s: string): string {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return atob(b64);
}

function b64UrlDecodeBytes(s: string): Uint8Array {
  const str = b64UrlDecodeString(s);
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i);
  return out;
}
