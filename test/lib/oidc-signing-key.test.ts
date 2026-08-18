import { describe, it, expect } from "vitest";
import {
  buildJwks,
  jwkThumbprintKid,
  parseOidcSigningKeys,
  resolveOidcSigningKeys,
  signEs256Jwt,
  toPublicJwk,
  type OidcJwk,
} from "../../src/lib/oidc-signing-key";

/** テスト用に本物の ES256 私有 JWK を作る (固定鍵を repo に置かないため)。 */
async function generateJwk(): Promise<OidcJwk> {
  const { privateKey } = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  return {
    kty: "EC",
    crv: "P-256",
    x: jwk.x!,
    y: jwk.y!,
    d: jwk.d!,
  };
}

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function b64urlToString(s: string): string {
  return new TextDecoder().decode(b64urlToBytes(s));
}

describe("parseOidcSigningKeys", () => {
  it("parses a JSON array of private JWKs, preserving order", async () => {
    const a = await generateJwk();
    const b = await generateJwk();
    const keys = parseOidcSigningKeys(JSON.stringify([a, b]));
    expect(keys).toHaveLength(2);
    expect(keys![0]!.x).toBe(a.x);
    expect(keys![1]!.x).toBe(b.x);
  });

  it("accepts a bare JWK object (not wrapped in an array)", async () => {
    const a = await generateJwk();
    const keys = parseOidcSigningKeys(JSON.stringify(a));
    expect(keys).toHaveLength(1);
    expect(keys![0]!.d).toBe(a.d);
  });

  it("returns null for malformed JSON", () => {
    expect(parseOidcSigningKeys("{not json")).toBeNull();
  });

  it("returns null for an empty array", () => {
    expect(parseOidcSigningKeys("[]")).toBeNull();
  });

  it("returns null when any element is invalid (fail-closed, no silent skip)", async () => {
    const good = await generateJwk();
    expect(parseOidcSigningKeys(JSON.stringify([good, { kty: "EC" }]))).toBeNull();
  });

  it.each([
    ["non-object element", 42],
    ["null element", null],
    ["wrong kty (RSA)", { kty: "RSA", crv: "P-256", x: "x", y: "y", d: "d" }],
    ["wrong crv (P-384)", { kty: "EC", crv: "P-384", x: "x", y: "y", d: "d" }],
    ["missing x", { kty: "EC", crv: "P-256", y: "y", d: "d" }],
    ["empty x", { kty: "EC", crv: "P-256", x: "", y: "y", d: "d" }],
    ["missing y", { kty: "EC", crv: "P-256", x: "x", d: "d" }],
    ["empty y", { kty: "EC", crv: "P-256", x: "x", y: "", d: "d" }],
    ["missing d (public key only)", { kty: "EC", crv: "P-256", x: "x", y: "y" }],
    ["empty d", { kty: "EC", crv: "P-256", x: "x", y: "y", d: "" }],
  ])("rejects %s", (_label, value) => {
    expect(parseOidcSigningKeys(JSON.stringify([value]))).toBeNull();
  });
});

describe("resolveOidcSigningKeys", () => {
  it("resolves a plain-string binding (vitest / wrangler dev shape)", async () => {
    const a = await generateJwk();
    const keys = await resolveOidcSigningKeys(JSON.stringify([a]));
    expect(keys).toHaveLength(1);
  });

  it("resolves a SecretsStoreSecret binding (.get())", async () => {
    const a = await generateJwk();
    const binding = {
      get: async () => JSON.stringify([a]),
    } as unknown as SecretsStoreSecret;
    const keys = await resolveOidcSigningKeys(binding);
    expect(keys![0]!.x).toBe(a.x);
  });

  it("returns null when the binding is missing", async () => {
    expect(await resolveOidcSigningKeys(undefined)).toBeNull();
  });

  it("returns null when the secret resolves but is not valid JWK JSON", async () => {
    expect(await resolveOidcSigningKeys("nonsense")).toBeNull();
  });
});

describe("jwkThumbprintKid", () => {
  it("is RFC 7638 (SHA-256 over crv/kty/x/y in lexicographic order)", async () => {
    // RFC 7638 §3.1 の EC 例に相当する canonical 形を、独立に計算した値と突き合わせる。
    const jwk = await generateJwk();
    const canonical = JSON.stringify({ crv: "P-256", kty: "EC", x: jwk.x, y: jwk.y });
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(canonical),
    );
    const expected = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(await jwkThumbprintKid(jwk)).toBe(expected);
  });

  it("ignores the private component (same public part → same kid)", async () => {
    const jwk = await generateJwk();
    const withoutD: OidcJwk = { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
    expect(await jwkThumbprintKid(withoutD)).toBe(await jwkThumbprintKid(jwk));
  });

  it("differs between distinct keys", async () => {
    const a = await generateJwk();
    const b = await generateJwk();
    expect(await jwkThumbprintKid(a)).not.toBe(await jwkThumbprintKid(b));
  });
});

describe("toPublicJwk", () => {
  it("strips the private component and stamps kid/alg/use", async () => {
    const jwk = await generateJwk();
    const pub = await toPublicJwk(jwk);
    expect(pub.d).toBeUndefined();
    expect(Object.keys(pub)).not.toContain("d");
    expect(pub.alg).toBe("ES256");
    expect(pub.use).toBe("sig");
    expect(pub.kid).toBe(await jwkThumbprintKid(jwk));
    expect(pub.x).toBe(jwk.x);
    expect(pub.y).toBe(jwk.y);
  });
});

describe("buildJwks", () => {
  it("emits every key, public-only, in order", async () => {
    const a = await generateJwk();
    const b = await generateJwk();
    const jwks = await buildJwks([a, b]);
    expect(jwks.keys).toHaveLength(2);
    expect(jwks.keys[0]!.kid).toBe(await jwkThumbprintKid(a));
    expect(jwks.keys[1]!.kid).toBe(await jwkThumbprintKid(b));
    expect(JSON.stringify(jwks)).not.toContain(a.d!);
    expect(JSON.stringify(jwks)).not.toContain(b.d!);
  });
});

describe("signEs256Jwt", () => {
  it("produces a JWT whose signature verifies against the public key", async () => {
    const jwk = await generateJwk();
    const token = await signEs256Jwt({ sub: "u1", exp: 123 }, jwk);
    const [h, p, sig] = token.split(".");

    const pub = await toPublicJwk(jwk);
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      b64urlToBytes(sig!),
      new TextEncoder().encode(`${h}.${p}`),
    );
    expect(ok).toBe(true);
  });

  it("emits a raw r‖s signature of 64 bytes (JOSE ES256, not DER)", async () => {
    const jwk = await generateJwk();
    const token = await signEs256Jwt({ sub: "u1" }, jwk);
    expect(b64urlToBytes(token.split(".")[2]!)).toHaveLength(64);
  });

  it("header carries alg/typ and the thumbprint kid", async () => {
    const jwk = await generateJwk();
    const token = await signEs256Jwt({ sub: "u1" }, jwk);
    const header = JSON.parse(b64urlToString(token.split(".")[0]!)) as Record<string, string>;
    expect(header.alg).toBe("ES256");
    expect(header.typ).toBe("JWT");
    expect(header.kid).toBe(await jwkThumbprintKid(jwk));
  });

  it("round-trips the payload, including multi-byte claims", async () => {
    const jwk = await generateJwk();
    const token = await signEs256Jwt({ sub: "u1", name: "大石 太郎" }, jwk);
    const payload = JSON.parse(b64urlToString(token.split(".")[1]!)) as Record<string, unknown>;
    expect(payload.sub).toBe("u1");
    expect(payload.name).toBe("大石 太郎");
  });

  it("signature differs per key (kid actually selects a distinct key)", async () => {
    const a = await generateJwk();
    const b = await generateJwk();
    const ta = await signEs256Jwt({ sub: "u1" }, a);
    const tb = await signEs256Jwt({ sub: "u1" }, b);
    expect(ta.split(".")[0]).not.toBe(tb.split(".")[0]);
  });
});
