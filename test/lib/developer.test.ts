import { describe, it, expect } from "vitest";
import {
  DEVELOPER_EMAILS,
  isDeveloperEmail,
  isDeveloperGoogleSession,
} from "../../src/lib/developer";

// 開発者のメールアドレスの値はテストに書かない (登録簿の先頭を借りる)。
const DEV = DEVELOPER_EMAILS[0]!;

describe("isDeveloperEmail", () => {
  it("登録簿のアドレスは true", () => {
    expect(isDeveloperEmail(DEV)).toBe(true);
  });

  it("大文字小文字を区別しない", () => {
    expect(isDeveloperEmail(DEV.toUpperCase())).toBe(true);
  });

  it.each([
    ["空", ""],
    ["別人", "op@example.com"],
    ["前後に文字が付いたもの", `x${DEV}`],
  ])("%s は false", (_name, email) => {
    expect(isDeveloperEmail(email)).toBe(false);
  });
});

describe("isDeveloperGoogleSession (Refs ippoan/alc-app#387)", () => {
  it("開発者 + Google + tokenKind 空 だけ true", () => {
    expect(isDeveloperGoogleSession({ email: DEV, tokenKind: "", idp: "google" })).toBe(true);
    expect(
      isDeveloperGoogleSession({ email: DEV.toUpperCase(), tokenKind: "", idp: "google" }),
    ).toBe(true);
  });

  it.each([
    ["idp が空 (LINE WORKS のログイン・claim を足す前の cookie)", { email: DEV, tokenKind: "", idp: "" }],
    ["idp が別の値", { email: DEV, tokenKind: "", idp: "lineworks" }],
    ["idp の大文字違い", { email: DEV, tokenKind: "", idp: "Google" }],
    ["tokenKind が dev", { email: DEV, tokenKind: "dev", idp: "google" }],
    ["tokenKind が device-key", { email: DEV, tokenKind: "device-key", idp: "google" }],
    ["tokenKind が未知の値", { email: DEV, tokenKind: "other", idp: "google" }],
    ["開発者でない email", { email: "op@example.com", tokenKind: "", idp: "google" }],
    ["空の email", { email: "", tokenKind: "", idp: "google" }],
  ])("%s は false", (_name, session) => {
    expect(isDeveloperGoogleSession(session)).toBe(false);
  });
});
