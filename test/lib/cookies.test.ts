import { describe, it, expect } from "vitest";
import {
  setAuthCookie,
  clearAuthCookie,
  getAuthCookie,
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
