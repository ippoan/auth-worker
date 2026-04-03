import { describe, it, expect } from "vitest";
import {
  isAllowedRedirectUri,
  generateOAuthState,
  verifyOAuthState,
} from "../../src/lib/security";

describe("isAllowedRedirectUri", () => {
  const allowed = "https://app1.example.com,https://app2.example.com";

  it("accepts URI whose origin is in the allowed list", () => {
    expect(isAllowedRedirectUri("https://app1.example.com/callback", allowed)).toBe(true);
  });

  it("accepts URI with path and query", () => {
    expect(isAllowedRedirectUri("https://app2.example.com/path?q=1", allowed)).toBe(true);
  });

  it("rejects URI not in allowed list", () => {
    expect(isAllowedRedirectUri("https://evil.com/callback", allowed)).toBe(false);
  });

  it("rejects invalid URL", () => {
    expect(isAllowedRedirectUri("not-a-url", allowed)).toBe(false);
  });

  it("handles whitespace in allowed origins", () => {
    expect(
      isAllowedRedirectUri(
        "https://app1.example.com/x",
        " https://app1.example.com , https://app2.example.com ",
      ),
    ).toBe(true);
  });

  it("rejects when origin matches partially but not exactly", () => {
    expect(isAllowedRedirectUri("https://app1.example.com.evil.com/x", allowed)).toBe(false);
  });
});

describe("generateOAuthState / verifyOAuthState", () => {
  const secret = "test-secret-key-for-hmac-signing";

  it("round-trips: generate then verify returns original redirect_uri", async () => {
    const state = await generateOAuthState("https://app.example.com/cb", secret);
    const result = await verifyOAuthState(state, secret);
    expect(result).not.toBeNull();
    expect(result!.redirect_uri).toBe("https://app.example.com/cb");
  });

  it("round-trips with extra fields", async () => {
    const state = await generateOAuthState("https://app.example.com/cb", secret, {
      join_org: "my-org",
      provider: "google",
    });
    const result = await verifyOAuthState(state, secret);
    expect(result?.join_org).toBe("my-org");
    expect(result?.provider).toBe("google");
  });

  it("rejects tampered signature", async () => {
    const state = await generateOAuthState("https://app.example.com/cb", secret);
    const tampered = state.slice(0, -1) + "X";
    const result = await verifyOAuthState(tampered, secret);
    expect(result).toBeNull();
  });

  it("rejects state with wrong secret", async () => {
    const state = await generateOAuthState("https://app.example.com/cb", secret);
    const result = await verifyOAuthState(state, "wrong-secret");
    expect(result).toBeNull();
  });

  it("rejects state without dot separator", async () => {
    const result = await verifyOAuthState("nodot", secret);
    expect(result).toBeNull();
  });

  it("rejects state with invalid base64 payload", async () => {
    // Valid format (has dot) but payload is not valid base64/JSON
    const result = await verifyOAuthState("!!!invalid.fakesig", secret);
    expect(result).toBeNull();
  });

  it("rejects state with valid HMAC but non-JSON payload", async () => {
    // Generate a state with non-JSON content by manually signing
    // Use a raw string that is valid base64 but not valid JSON
    const rawPayload = "not-json-at-all";
    const payloadB64 = btoa(rawPayload).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    // Sign it with the correct secret to pass HMAC check
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(payloadB64),
    );
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    const state = `${payloadB64}.${sigB64}`;
    const result = await verifyOAuthState(state, secret);
    expect(result).toBeNull();
  });
});
