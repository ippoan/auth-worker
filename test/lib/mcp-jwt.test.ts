import { describe, it, expect } from "vitest";
import {
  resolveMcpJwtSecret,
  signMcpJwt,
  verifyMcpJwt,
  verifyMcpJwtSignatureOnly,
} from "../../src/lib/mcp-jwt";

const SECRET = "test-mcp-jwt-secret-32chars!";
const AUD = "github-mcp-server-rs";

describe("mcp-jwt", () => {
  it("sign + verify roundtrip", async () => {
    const token = await signMcpJwt(
      { sub: "github:alice", github_login: "alice", scope: "read:user", aud: AUD },
      SECRET,
      3600,
    );
    const payload = await verifyMcpJwt(token, SECRET, AUD);
    expect(payload).not.toBeNull();
    expect(payload!.sub).toBe("github:alice");
    expect(payload!.github_login).toBe("alice");
    expect(payload!.scope).toBe("read:user");
    expect(payload!.aud).toBe(AUD);
    expect(typeof payload!.exp).toBe("number");
    expect(typeof payload!.iat).toBe("number");
    expect(payload!.exp - payload!.iat).toBe(3600);
  });

  it("sign + verify roundtrip carries an explicit iss claim (issue #432)", async () => {
    const token = await signMcpJwt(
      {
        sub: "github:alice",
        github_login: "alice",
        scope: "read:user",
        aud: AUD,
        iss: "https://auth.ippoan.example",
      },
      SECRET,
      3600,
    );
    const payload = await verifyMcpJwt(token, SECRET, AUD);
    expect(payload).not.toBeNull();
    expect(payload!.iss).toBe("https://auth.ippoan.example");
  });

  it("verify does not reject a legacy token minted without iss (non-breaking rollout)", async () => {
    const token = await signMcpJwt(
      { sub: "github:alice", github_login: "alice", scope: "read:user", aud: AUD },
      SECRET,
      3600,
    );
    const payload = await verifyMcpJwt(token, SECRET, AUD);
    expect(payload).not.toBeNull();
    expect(payload!.iss).toBeUndefined();
  });

  it("signMcpJwt throws when secret is empty", async () => {
    await expect(
      signMcpJwt({ sub: "x", github_login: "x", scope: "", aud: AUD }, "", 3600),
    ).rejects.toThrow(/not configured/);
  });

  it("verify returns null when secret is empty", async () => {
    expect(await verifyMcpJwt("a.b.c", "", AUD)).toBeNull();
  });

  it("verify returns null with wrong secret", async () => {
    const token = await signMcpJwt(
      { sub: "github:bob", github_login: "bob", scope: "", aud: AUD },
      SECRET,
      3600,
    );
    expect(await verifyMcpJwt(token, "wrong-secret", AUD)).toBeNull();
  });

  it("verify returns null with wrong audience", async () => {
    const token = await signMcpJwt(
      { sub: "github:bob", github_login: "bob", scope: "", aud: AUD },
      SECRET,
      3600,
    );
    expect(await verifyMcpJwt(token, SECRET, "different-aud")).toBeNull();
  });

  it("verify returns null when expired (negative ttlSec)", async () => {
    const token = await signMcpJwt(
      { sub: "github:bob", github_login: "bob", scope: "", aud: AUD },
      SECRET,
      -10,
    );
    expect(await verifyMcpJwt(token, SECRET, AUD)).toBeNull();
  });

  it("verify returns null for malformed token (wrong parts)", async () => {
    expect(await verifyMcpJwt("not.a.valid.jwt", SECRET, AUD)).toBeNull();
    expect(await verifyMcpJwt("only-one-part", SECRET, AUD)).toBeNull();
  });

  it("verify returns null when signature has wrong length (constantTimeEqual fast-fail)", async () => {
    // valid HS256 header + payload, but signature is too short → length mismatch
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const payload = btoa(JSON.stringify({ sub: "x", aud: AUD, exp: 9999999999, iat: 0 }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(await verifyMcpJwt(`${header}.${payload}.x`, SECRET, AUD)).toBeNull();
  });

  it("verify returns null when header has wrong alg", async () => {
    // forge a HS512 header
    const header = btoa(JSON.stringify({ alg: "HS512", typ: "JWT" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const payload = btoa(JSON.stringify({ sub: "x", aud: AUD, exp: 9999999999, iat: 0 }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(await verifyMcpJwt(`${header}.${payload}.sig`, SECRET, AUD)).toBeNull();
  });

  it("verify returns null when header is not JSON", async () => {
    // garbage header
    expect(await verifyMcpJwt("notjson.bbb.ccc", SECRET, AUD)).toBeNull();
  });

  it("verify returns null when payload is not JSON (signature matches but payload garbage)", async () => {
    // build a token with valid header + garbage payload, then sign correctly
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const garbage = "notjsongarbage";
    // sign header.garbage with the correct secret so the alg-check passes,
    // then payload parse fails.
    const enc = new TextEncoder();
    const k = await crypto.subtle.importKey("raw", enc.encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(`${header}.${garbage}`)));
    let bin = "";
    for (let i = 0; i < sig.length; i++) bin += String.fromCharCode(sig[i]!);
    const sigB64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(await verifyMcpJwt(`${header}.${garbage}.${sigB64}`, SECRET, AUD)).toBeNull();
  });

  it("verify accepts array of expectedAud — any match", async () => {
    const token = await signMcpJwt(
      { sub: "github:bob", github_login: "bob", scope: "", aud: "https://mcp.example/mcp" },
      SECRET,
      3600,
    );
    const payload = await verifyMcpJwt(token, SECRET, [
      AUD,
      "https://mcp.example/mcp",
    ]);
    expect(payload).not.toBeNull();
    expect(payload!.aud).toBe("https://mcp.example/mcp");
  });

  it("verify with array of expectedAud — none match → null", async () => {
    const token = await signMcpJwt(
      { sub: "github:bob", github_login: "bob", scope: "", aud: "x" },
      SECRET,
      3600,
    );
    expect(await verifyMcpJwt(token, SECRET, [AUD, "y"])).toBeNull();
  });

  it("verify accepts predicate for aud (RFC 8707 URL origin match)", async () => {
    const token = await signMcpJwt(
      { sub: "github:bob", github_login: "bob", scope: "", aud: "https://mcp.example/mcp" },
      SECRET,
      3600,
    );
    const payload = await verifyMcpJwt(token, SECRET, (aud) => {
      try {
        return new URL(aud).origin === "https://mcp.example";
      } catch {
        return false;
      }
    });
    expect(payload).not.toBeNull();
  });

  it("verify with predicate returning false → null", async () => {
    const token = await signMcpJwt(
      { sub: "github:bob", github_login: "bob", scope: "", aud: "https://mcp.example/mcp" },
      SECRET,
      3600,
    );
    expect(await verifyMcpJwt(token, SECRET, () => false)).toBeNull();
  });

  it("verify returns null when exp is not a number", async () => {
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const payload = btoa(JSON.stringify({ sub: "x", aud: AUD, exp: "not-a-number" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const enc = new TextEncoder();
    const k = await crypto.subtle.importKey("raw", enc.encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(`${header}.${payload}`)));
    let bin = "";
    for (let i = 0; i < sig.length; i++) bin += String.fromCharCode(sig[i]!);
    const sigB64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(await verifyMcpJwt(`${header}.${payload}.${sigB64}`, SECRET, AUD)).toBeNull();
  });

  // ─── verifyMcpJwtSignatureOnly — signature-only verifier for /mcp/jwt/pickup ───

  it("signatureOnly accepts a token whose exp is in the past", async () => {
    const token = await signMcpJwt(
      { sub: "github:carol", github_login: "carol", scope: "mcp.read", aud: AUD },
      SECRET,
      -3600, // expired 1h ago
    );
    expect(await verifyMcpJwt(token, SECRET, AUD)).toBeNull(); // exp check fails
    const payload = await verifyMcpJwtSignatureOnly(token, SECRET);
    expect(payload).not.toBeNull();
    expect(payload!.sub).toBe("github:carol");
    expect(payload!.github_login).toBe("carol");
  });

  it("signatureOnly still rejects wrong signature", async () => {
    const token = await signMcpJwt(
      { sub: "x", github_login: "x", scope: "", aud: AUD },
      SECRET,
      3600,
    );
    expect(await verifyMcpJwtSignatureOnly(token, "wrong-secret")).toBeNull();
  });

  it("signatureOnly returns null when secret is empty", async () => {
    expect(await verifyMcpJwtSignatureOnly("a.b.c", "")).toBeNull();
  });

  it("signatureOnly returns null for malformed token shape", async () => {
    expect(await verifyMcpJwtSignatureOnly("not.a.valid.jwt", SECRET)).toBeNull();
    expect(await verifyMcpJwtSignatureOnly("only-one", SECRET)).toBeNull();
  });

  it("signatureOnly rejects HS512 header (alg pinning)", async () => {
    const header = btoa(JSON.stringify({ alg: "HS512", typ: "JWT" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const payload = btoa(JSON.stringify({ sub: "x", aud: AUD, exp: 9999999999, iat: 0 }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(
      await verifyMcpJwtSignatureOnly(`${header}.${payload}.sig`, SECRET),
    ).toBeNull();
  });

  it("signatureOnly returns null when header is not JSON", async () => {
    expect(await verifyMcpJwtSignatureOnly("notjson.bbb.ccc", SECRET)).toBeNull();
  });

  it("signatureOnly returns null when payload is not JSON", async () => {
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const garbage = "notjsongarbage";
    const enc = new TextEncoder();
    const k = await crypto.subtle.importKey("raw", enc.encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(`${header}.${garbage}`)));
    let bin = "";
    for (let i = 0; i < sig.length; i++) bin += String.fromCharCode(sig[i]!);
    const sigB64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(
      await verifyMcpJwtSignatureOnly(`${header}.${garbage}.${sigB64}`, SECRET),
    ).toBeNull();
  });

  it("signatureOnly rejects payload with missing/non-string sub", async () => {
    // sign a payload with sub:42 (number) so it parses but fails sub validation
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const payload = btoa(JSON.stringify({ sub: 42, aud: AUD, exp: 9999999999, iat: 0 }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const enc = new TextEncoder();
    const k = await crypto.subtle.importKey("raw", enc.encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(`${header}.${payload}`)));
    let bin = "";
    for (let i = 0; i < sig.length; i++) bin += String.fromCharCode(sig[i]!);
    const sigB64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(
      await verifyMcpJwtSignatureOnly(`${header}.${payload}.${sigB64}`, SECRET),
    ).toBeNull();
  });

  it("signatureOnly rejects payload with empty sub", async () => {
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const payload = btoa(JSON.stringify({ sub: "", aud: AUD, exp: 9999999999, iat: 0 }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const enc = new TextEncoder();
    const k = await crypto.subtle.importKey("raw", enc.encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(`${header}.${payload}`)));
    let bin = "";
    for (let i = 0; i < sig.length; i++) bin += String.fromCharCode(sig[i]!);
    const sigB64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(
      await verifyMcpJwtSignatureOnly(`${header}.${payload}.${sigB64}`, SECRET),
    ).toBeNull();
  });

  it("signatureOnly rejects payload with non-number exp", async () => {
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const payload = btoa(JSON.stringify({ sub: "x", aud: AUD, exp: "not-a-number" }))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const enc = new TextEncoder();
    const k = await crypto.subtle.importKey("raw", enc.encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(`${header}.${payload}`)));
    let bin = "";
    for (let i = 0; i < sig.length; i++) bin += String.fromCharCode(sig[i]!);
    const sigB64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(
      await verifyMcpJwtSignatureOnly(`${header}.${payload}.${sigB64}`, SECRET),
    ).toBeNull();
  });

  describe("resolveMcpJwtSecret", () => {
    it("returns null for undefined binding (not bound)", async () => {
      expect(await resolveMcpJwtSecret(undefined)).toBeNull();
    });

    it("returns null for empty string binding", async () => {
      expect(await resolveMcpJwtSecret("")).toBeNull();
    });

    it("returns the string as-is for non-empty string binding (vitest / wrangler secret)", async () => {
      expect(await resolveMcpJwtSecret("my-hs256-key")).toBe("my-hs256-key");
    });

    it("calls .get() on a SecretsStoreSecret binding and returns the value", async () => {
      const binding = {
        get: async () => "value-from-secrets-store",
      } as unknown as SecretsStoreSecret;
      expect(await resolveMcpJwtSecret(binding)).toBe("value-from-secrets-store");
    });

    it("returns null when SecretsStoreSecret.get() throws", async () => {
      const binding = {
        get: async () => {
          throw new Error("simulated Secrets Store outage");
        },
      } as unknown as SecretsStoreSecret;
      expect(await resolveMcpJwtSecret(binding)).toBeNull();
    });

    it("returns null when SecretsStoreSecret.get() resolves to empty string", async () => {
      const binding = {
        get: async () => "",
      } as unknown as SecretsStoreSecret;
      expect(await resolveMcpJwtSecret(binding)).toBeNull();
    });
  });
});
