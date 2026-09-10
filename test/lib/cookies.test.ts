import { describe, it, expect } from "vitest";
import {
  setAuthCookie,
  clearAuthCookie,
  clearAuthCookieVariants,
  getAuthCookie,
  getAuthCookies,
  authCookieReachesHost,
  getBounce,
  setBounceCookie,
  clearBounceCookie,
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

  describe("logi_bounce (Refs #526)", () => {
    it("setBounceCookie: count:reason 形式で host-only (Domain 無し) の Set-Cookie を返す", () => {
      const cookie = setBounceCookie(2, "expired");
      expect(cookie).toBe("logi_bounce=2:expired; Path=/; Max-Age=120; Secure; SameSite=Lax");
      expect(cookie).not.toContain("Domain=");
    });

    it("clearBounceCookie: Max-Age=0", () => {
      expect(clearBounceCookie()).toBe("logi_bounce=; Path=/; Max-Age=0; Secure; SameSite=Lax");
    });

    it("getBounce: cookie を count/reason に parse する", () => {
      const req = new Request("https://example.com", {
        headers: { Cookie: "logi_bounce=3:no_cookie" },
      });
      expect(getBounce(req)).toEqual({ count: 3, reason: "no_cookie" });
    });

    it("getBounce: cookie が無ければ null", () => {
      expect(getBounce(new Request("https://example.com"))).toBeNull();
    });

    it("getBounce: 壊れた値 (count が非数 / reason が未知) は count のみ / null 混在で扱う", () => {
      const badCount = new Request("https://example.com", {
        headers: { Cookie: "logi_bounce=abc:no_cookie" },
      });
      expect(getBounce(badCount)).toBeNull();

      const badReason = new Request("https://example.com", {
        headers: { Cookie: "logi_bounce=1:something_else" },
      });
      expect(getBounce(badReason)).toEqual({ count: 1, reason: null });
    });
  });
});
