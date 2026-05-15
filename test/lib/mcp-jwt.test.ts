import { describe, it, expect } from "vitest";
import { signMcpJwt, verifyMcpJwt } from "../../src/lib/mcp-jwt";

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
});
