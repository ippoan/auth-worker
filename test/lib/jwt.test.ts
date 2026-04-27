import { describe, it, expect } from "vitest";
import { verifyJwt } from "../../src/lib/jwt";
import { signTestJwt } from "../helpers/test-jwt";

const SECRET = "verify-jwt-test-secret-32chars!!";

describe("verifyJwt", () => {
  it("returns the decoded payload for a valid HS256 token", async () => {
    const token = await signTestJwt({ sub: "u1", tenant_id: "t1" }, SECRET);
    const payload = await verifyJwt(token, SECRET);
    expect(payload).not.toBeNull();
    expect(payload!.sub).toBe("u1");
    expect(payload!.tenant_id).toBe("t1");
  });

  it("returns null when the signature was made with a different secret", async () => {
    const token = await signTestJwt({ sub: "u1" }, "wrong-secret");
    expect(await verifyJwt(token, SECRET)).toBeNull();
  });

  it("returns null when the token has expired", async () => {
    const token = await signTestJwt(
      { sub: "u1", exp: Math.floor(Date.now() / 1000) - 60 },
      SECRET,
    );
    expect(await verifyJwt(token, SECRET)).toBeNull();
  });

  it("returns null when the token has no exp claim", async () => {
    // signTestJwt always sets a default exp, so override with a sentinel that
    // JSON serializes away. Build the token by hand instead.
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const body = btoa(JSON.stringify({ sub: "u1" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const data = `${header}.${body}`;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = new Uint8Array(
      await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data)),
    );
    let s = "";
    for (let i = 0; i < sig.length; i++) s += String.fromCharCode(sig[i]!);
    const sigB64 = btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(await verifyJwt(`${data}.${sigB64}`, SECRET)).toBeNull();
  });

  it("returns null when the token has fewer than 3 segments", async () => {
    expect(await verifyJwt("foo.bar", SECRET)).toBeNull();
    expect(await verifyJwt("just-one-segment", SECRET)).toBeNull();
  });

  it("returns null when the header is not valid JSON", async () => {
    const body = "eyJzdWIiOiJ1MSJ9";
    expect(await verifyJwt(`not-json.${body}.sig`, SECRET)).toBeNull();
  });

  it("returns null when alg is not HS256", async () => {
    const header = btoa(JSON.stringify({ alg: "none", typ: "JWT" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const body = btoa(
      JSON.stringify({ sub: "u1", exp: Math.floor(Date.now() / 1000) + 3600 }),
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(await verifyJwt(`${header}.${body}.anything`, SECRET)).toBeNull();
  });

  it("returns null when the secret is empty", async () => {
    const token = await signTestJwt({ sub: "u1" }, SECRET);
    expect(await verifyJwt(token, "")).toBeNull();
  });

  it("returns null when the payload base64 is malformed JSON", async () => {
    // Sign over a payload segment that decodes to invalid JSON.
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const body = btoa("not-json{")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const data = `${header}.${body}`;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = new Uint8Array(
      await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data)),
    );
    let s = "";
    for (let i = 0; i < sig.length; i++) s += String.fromCharCode(sig[i]!);
    const sigB64 = btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(await verifyJwt(`${data}.${sigB64}`, SECRET)).toBeNull();
  });
});
