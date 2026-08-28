import { describe, it, expect } from "vitest";
import {
  isAllowedVerifyTarget,
  shouldFollowAccessHop,
} from "../../src/lib/verify-shot";

describe("isAllowedVerifyTarget", () => {
  it("allows https URLs on ippoan.org and subdomains", () => {
    expect(isAllowedVerifyTarget("https://ippoan.org/")).toBe(true);
    expect(isAllowedVerifyTarget("https://dtako.ippoan.org/operations")).toBe(true);
    expect(isAllowedVerifyTarget("https://auth-staging.ippoan.org/top?x=1")).toBe(true);
    // hostname 判定なのでポート付きも同一ホスト扱い
    expect(isAllowedVerifyTarget("https://dtako.ippoan.org:8443/")).toBe(true);
    // 大文字ホストは正規化される
    expect(isAllowedVerifyTarget("https://DTAKO.IPPOAN.ORG/")).toBe(true);
  });

  it("rejects non-https schemes", () => {
    expect(isAllowedVerifyTarget("http://dtako.ippoan.org/")).toBe(false);
    expect(isAllowedVerifyTarget("ftp://dtako.ippoan.org/")).toBe(false);
    expect(isAllowedVerifyTarget("javascript:alert(1)")).toBe(false);
  });

  it("rejects lookalike / boundary-crossing hosts", () => {
    // dot 境界: evil-ippoan.org は .ippoan.org で終わらない
    expect(isAllowedVerifyTarget("https://evil-ippoan.org/")).toBe(false);
    expect(isAllowedVerifyTarget("https://ippoan.org.evil.example/")).toBe(false);
    // 末尾ドット FQDN は完全一致からも suffix 一致からも外れる
    expect(isAllowedVerifyTarget("https://dtako.ippoan.org./")).toBe(false);
    // userinfo で偽装しても URL.hostname は本当の宛先を返す
    expect(isAllowedVerifyTarget("https://dtako.ippoan.org@evil.example.com/")).toBe(false);
  });

  it("rejects unparseable input", () => {
    expect(isAllowedVerifyTarget("")).toBe(false);
    expect(isAllowedVerifyTarget("not a url")).toBe(false);
  });
});

describe("shouldFollowAccessHop", () => {
  const TEAM = "mtamaramu.cloudflareaccess.com";
  const LOGIN_URL = `https://${TEAM}/cdn-cgi/access/login/dtako.ippoan.org?kid=abc`;
  const AUTHORIZE = "https://auth.ippoan.org/oidc/authorize?client_id=cf-access";

  it("follows the hop from the Access login page to an allowed authorize URL", () => {
    expect(shouldFollowAccessHop(LOGIN_URL, AUTHORIZE, TEAM)).toBe(AUTHORIZE);
  });

  it("is case-insensitive on the team domain", () => {
    expect(
      shouldFollowAccessHop(LOGIN_URL, AUTHORIZE, "MTAMARAMU.cloudflareaccess.com"),
    ).toBe(AUTHORIZE);
  });

  it("returns null when not on the Access login page", () => {
    expect(shouldFollowAccessHop("https://dtako.ippoan.org/operations", AUTHORIZE, TEAM)).toBe(null);
    expect(shouldFollowAccessHop(`https://${TEAM}/cdn-cgi/access/other`, AUTHORIZE, TEAM)).toBe(null);
    // team domain 以外の cloudflareaccess ホストは踏まない
    expect(
      shouldFollowAccessHop("https://other.cloudflareaccess.com/cdn-cgi/access/login/x", AUTHORIZE, TEAM),
    ).toBe(null);
  });

  it("returns null for a disallowed hop target", () => {
    expect(shouldFollowAccessHop(LOGIN_URL, "https://evil.example.com/steal", TEAM)).toBe(null);
    expect(shouldFollowAccessHop(LOGIN_URL, "http://auth.ippoan.org/oidc/authorize", TEAM)).toBe(null);
  });

  it("returns null when hop URL or team domain is missing", () => {
    expect(shouldFollowAccessHop(LOGIN_URL, null, TEAM)).toBe(null);
    expect(shouldFollowAccessHop(LOGIN_URL, AUTHORIZE, undefined)).toBe(null);
    expect(shouldFollowAccessHop("not a url", AUTHORIZE, TEAM)).toBe(null);
  });
});
