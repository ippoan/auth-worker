/**
 * `mcp-session.ts` (issue #144) — HMAC-signed pair session cookie。
 * sign/verify の round-trip と negative cases (tampered / expired / malformed) を網羅。
 */

import { describe, it, expect } from "vitest";
import {
  PAIR_SESSION_COOKIE_NAME,
  PAIR_SESSION_TTL_SEC,
  buildSetCookie,
  readPairSessionCookie,
  signPairSession,
  verifyPairSession,
} from "../../src/lib/mcp-session";

const SECRET = "test-session-cookie-secret-32!!!!";

describe("signPairSession / verifyPairSession", () => {
  it("round-trips github_login through HMAC-signed cookie", async () => {
    const cookie = await signPairSession("alice", SECRET);
    const payload = await verifyPairSession(cookie, SECRET);
    expect(payload).not.toBeNull();
    expect(payload?.github_login).toBe("alice");
    expect(typeof payload?.iat).toBe("number");
    expect(typeof payload?.exp).toBe("number");
    expect(payload!.exp - payload!.iat).toBe(PAIR_SESSION_TTL_SEC);
  });

  it("verifyPairSession returns null when signature is tampered", async () => {
    const cookie = await signPairSession("alice", SECRET);
    const tampered = `${cookie.slice(0, -4)}AAAA`;
    expect(await verifyPairSession(tampered, SECRET)).toBeNull();
  });

  it("verifyPairSession returns null when payload is tampered", async () => {
    const cookie = await signPairSession("alice", SECRET);
    const [, sig] = cookie.split(".");
    // payload を別の合法 base64url 文字列にする (sig は元のまま)
    const fakePayload = btoa('{"github_login":"mallory","iat":1,"exp":9999999999}')
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(await verifyPairSession(`${fakePayload}.${sig}`, SECRET)).toBeNull();
  });

  it("verifyPairSession returns null on different secret", async () => {
    const cookie = await signPairSession("alice", SECRET);
    expect(await verifyPairSession(cookie, "other-secret-32-chars-padding!")).toBeNull();
  });

  it("verifyPairSession returns null when cookie has no dot separator", async () => {
    expect(await verifyPairSession("nodotjustpayload", SECRET)).toBeNull();
  });

  it("verifyPairSession returns null when payload base64 is invalid JSON", async () => {
    // payload と sig は valid HMAC pair だが payload を decode すると非 JSON
    // sig は本物が必要なので、helper を介す
    const badPayload = btoa("not json").replace(/=+$/, "");
    // 適当 sig (verify は sig 段階で fail せず JSON decode で fail させる)
    // → signature 一致を作るには再 sign が必要だが、ここでは signature mismatch
    // path (= sig 段階で null) の確認になっている。
    // payload が非 JSON でも、まず HMAC で reject される。改めて signature が
    // 通った場合の JSON decode 失敗 path を作るには raw secret 直接 HMAC が要る。
    // ここでは「dot あり / 全体が短すぎ / payload が空文字」など多様な malformed 入力で
    // null になることを確認する。
    expect(await verifyPairSession(`${badPayload}.x`, SECRET)).toBeNull();
    expect(await verifyPairSession(".sig", SECRET)).toBeNull();
    expect(await verifyPairSession("payload.", SECRET)).toBeNull();
  });

  it("verifyPairSession returns null when payload has invalid JSON shape but valid HMAC", async () => {
    // sign 関数を経由せず手で payload+sig を組み立てる
    const payloadObj = "garbage non-object";
    const payloadJson = JSON.stringify(payloadObj);
    const payloadB64 = btoa(payloadJson).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    // HMAC は signPairSession と同じ alg で
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    // sig が valid でも payload が string なので exp/github_login が無く null
    expect(await verifyPairSession(`${payloadB64}.${sigB64}`, SECRET)).toBeNull();
  });

  it("verifyPairSession returns null when github_login is missing/empty", async () => {
    const payloadJson = JSON.stringify({ github_login: "", iat: 1, exp: 9_999_999_999 });
    const payloadB64 = btoa(payloadJson).replace(/=+$/, "");
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(await verifyPairSession(`${payloadB64}.${sigB64}`, SECRET)).toBeNull();
  });

  it("verifyPairSession returns null on expired cookie", async () => {
    // exp が過去
    const payloadJson = JSON.stringify({ github_login: "alice", iat: 1, exp: 2 });
    const payloadB64 = btoa(payloadJson).replace(/=+$/, "");
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(await verifyPairSession(`${payloadB64}.${sigB64}`, SECRET)).toBeNull();
  });

  it("verifyPairSession returns null when exp is not a number", async () => {
    const payloadJson = JSON.stringify({ github_login: "alice", iat: 1, exp: "not-a-number" });
    const payloadB64 = btoa(payloadJson).replace(/=+$/, "");
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(await verifyPairSession(`${payloadB64}.${sigB64}`, SECRET)).toBeNull();
  });

  it("verifyPairSession returns null when payload b64 decodes to non-JSON string (valid HMAC)", async () => {
    // payload を base64url valid だが decode 後は非 JSON にする
    const payloadB64 = btoa("not-json-at-all").replace(/=+$/, "");
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(await verifyPairSession(`${payloadB64}.${sigB64}`, SECRET)).toBeNull();
  });

  it("verifyPairSession returns null when github_login is missing entirely", async () => {
    const payloadJson = JSON.stringify({ iat: 1, exp: 9_999_999_999 });
    const payloadB64 = btoa(payloadJson).replace(/=+$/, "");
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(await verifyPairSession(`${payloadB64}.${sigB64}`, SECRET)).toBeNull();
  });

  it("signPairSession throws on empty secret", async () => {
    await expect(signPairSession("alice", "")).rejects.toThrow(/SESSION_COOKIE_SECRET/);
  });

  it("verifyPairSession returns null on empty secret", async () => {
    expect(await verifyPairSession("anything", "")).toBeNull();
  });

  it("respects custom ttlSec argument", async () => {
    const cookie = await signPairSession("alice", SECRET, 60);
    const payload = await verifyPairSession(cookie, SECRET);
    expect(payload!.exp - payload!.iat).toBe(60);
  });
});

describe("readPairSessionCookie", () => {
  it("extracts the cookie value from a Cookie header", () => {
    expect(
      readPairSessionCookie(`${PAIR_SESSION_COOKIE_NAME}=abc.def; other=1`),
    ).toBe("abc.def");
  });

  it("returns null when header is null", () => {
    expect(readPairSessionCookie(null)).toBeNull();
  });

  it("returns null when cookie is absent", () => {
    expect(readPairSessionCookie("other=1; another=2")).toBeNull();
  });

  it("handles entries without '=' (malformed) gracefully", () => {
    expect(readPairSessionCookie(`flagonly; ${PAIR_SESSION_COOKIE_NAME}=v`)).toBe("v");
  });

  it("matches exact name (does not partial-match)", () => {
    expect(readPairSessionCookie(`x${PAIR_SESSION_COOKIE_NAME}=v`)).toBeNull();
  });
});

describe("buildSetCookie", () => {
  it("produces a Set-Cookie value with Secure/HttpOnly/SameSite=Lax", () => {
    const v = buildSetCookie("abc.def");
    expect(v).toContain(`${PAIR_SESSION_COOKIE_NAME}=abc.def`);
    expect(v).toContain("Secure");
    expect(v).toContain("HttpOnly");
    expect(v).toContain("SameSite=Lax");
    expect(v).toContain("Path=/");
    expect(v).toContain(`Max-Age=${PAIR_SESSION_TTL_SEC}`);
  });

  it("respects custom maxAgeSec", () => {
    expect(buildSetCookie("v", 60)).toContain("Max-Age=60");
  });
});
