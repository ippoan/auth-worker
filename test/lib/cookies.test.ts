import { describe, it, expect } from "vitest";
import {
  setAuthCookie,
  clearAuthCookie,
  clearAuthCookieVariants,
  getAuthCookie,
  getAuthCookies,
  authCookieReachesHost,
} from "../../src/lib/cookies";

describe("cookies", () => {
  describe("setAuthCookie", () => {
    it("sets Domain to parent domain for subdomain hosts", () => {
      const cookie = setAuthCookie("my-jwt-token", "auth.ippoan.org");
      expect(cookie).toBe(
        "logi_auth_token=my-jwt-token; Domain=.ippoan.org; Path=/; Max-Age=86400; Secure; SameSite=Lax",
      );
    });

    it("uses hostname as-is for two-part domains", () => {
      const cookie = setAuthCookie("my-jwt-token", "example.com");
      expect(cookie).toBe(
        "logi_auth_token=my-jwt-token; Domain=example.com; Path=/; Max-Age=86400; Secure; SameSite=Lax",
      );
    });

    it("handles workers.dev subdomains", () => {
      const cookie = setAuthCookie("tok", "auth-worker.m-tama-ramu.workers.dev");
      expect(cookie).toContain("Domain=.workers.dev");
    });
  });

  describe("clearAuthCookie", () => {
    it("returns cookie string with Max-Age=0 and parent Domain", () => {
      const cookie = clearAuthCookie("auth.ippoan.org");
      expect(cookie).toBe(
        "logi_auth_token=; Domain=.ippoan.org; Path=/; Max-Age=0; Secure; SameSite=Lax",
      );
    });
  });

  describe("getAuthCookie", () => {
    it("returns token from Cookie header", () => {
      const req = new Request("https://example.com", {
        headers: { Cookie: "logi_auth_token=abc123; other=value" },
      });
      expect(getAuthCookie(req)).toBe("abc123");
    });

    it("returns null when cookie not present", () => {
      const req = new Request("https://example.com", {
        headers: { Cookie: "other=value" },
      });
      expect(getAuthCookie(req)).toBeNull();
    });

    it("returns null when no Cookie header", () => {
      const req = new Request("https://example.com");
      expect(getAuthCookie(req)).toBeNull();
    });

    it("handles token with = in value", () => {
      const req = new Request("https://example.com", {
        headers: { Cookie: "logi_auth_token=abc=def; other=value" },
      });
      expect(getAuthCookie(req)).toBe("abc=def");
    });
  });

  describe("getAuthCookies (Refs #387)", () => {
    it("同名 cookie が複数あれば全部返す (host-only と Domain 付きの併存)", () => {
      const req = new Request("https://example.com", {
        headers: { Cookie: "logi_auth_token=stale; other=x; logi_auth_token=fresh" },
      });
      expect(getAuthCookies(req)).toEqual(["stale", "fresh"]);
    });

    it("無ければ空配列", () => {
      expect(getAuthCookies(new Request("https://example.com"))).toEqual([]);
    });
  });

  describe("clearAuthCookieVariants (Refs #387)", () => {
    it("Domain 付きと host-only の 2 本の破棄 Set-Cookie を返す", () => {
      const variants = clearAuthCookieVariants("auth.ippoan.org");
      expect(variants.length).toBe(2);
      for (const v of variants) {
        expect(v).toContain("logi_auth_token=;");
        expect(v).toContain("Max-Age=0");
        expect(v).toContain("Path=/");
      }
      expect(variants[0]).toContain("Domain=.ippoan.org");
      expect(variants[1]).not.toContain("Domain=");
    });
  });

  describe("authCookieReachesHost", () => {
    it("同一親ドメイン配下 (.ippoan.org) は true → cookie 配布可", () => {
      expect(authCookieReachesHost("auth.ippoan.org", "ichibanboshi-seikyu.ippoan.org")).toBe(true);
      expect(authCookieReachesHost("auth.ippoan.org", "auth.ippoan.org")).toBe(true);
      expect(authCookieReachesHost("auth.ippoan.org", "ippoan.org")).toBe(true);
    });

    it("親ドメインが public suffix (.workers.dev) は false → fragment 必須", () => {
      expect(
        authCookieReachesHost("auth-staging.m-tama-ramu.workers.dev", "app.m-tama-ramu.workers.dev"),
      ).toBe(false);
    });

    it("親ドメインが異なる host は false", () => {
      expect(authCookieReachesHost("auth.ippoan.org", "app.example.com")).toBe(false);
      expect(authCookieReachesHost("auth.ippoan.org", "evil-ippoan.org")).toBe(false);
    });

    it("単一ラベル host (localhost 等) は false", () => {
      expect(authCookieReachesHost("localhost", "localhost")).toBe(false);
    });
  });
});
