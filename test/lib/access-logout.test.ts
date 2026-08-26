import { describe, it, expect } from "vitest";
import {
  ACCESS_LOGOUT_CHAIN_COOKIE,
  accessLogoutChainMarkerCookie,
  hasAccessLogoutChainMarker,
  normalizeAccessTeamDomain,
  logoutNavigationTarget,
} from "../../src/lib/access-logout";

const TEAM = "mtamaramu.cloudflareaccess.com";
const AUTH_ORIGIN = "https://auth.ippoan.org";
const AUTH_HOST = "auth.ippoan.org";

describe("normalizeAccessTeamDomain", () => {
  it("passes a bare hostname through", () => {
    expect(normalizeAccessTeamDomain(TEAM)).toBe(TEAM);
  });

  it("strips scheme and trailing slash", () => {
    expect(normalizeAccessTeamDomain(` https://${TEAM}/ `)).toBe(TEAM);
    expect(normalizeAccessTeamDomain(`http://${TEAM}`)).toBe(TEAM);
  });

  it("returns null for unset / empty values", () => {
    expect(normalizeAccessTeamDomain(undefined)).toBeNull();
    expect(normalizeAccessTeamDomain(null)).toBeNull();
    expect(normalizeAccessTeamDomain("   ")).toBeNull();
  });

  it("rejects values that carry a port or a path", () => {
    expect(normalizeAccessTeamDomain(`${TEAM}:8443`)).toBeNull();
    expect(normalizeAccessTeamDomain(`${TEAM}/cdn-cgi/access`)).toBeNull();
  });

  it("rejects a single-label host", () => {
    expect(normalizeAccessTeamDomain("localhost")).toBeNull();
    // 末尾スラッシュを落とすと "https:" が残り、host が "https" (ドット無し) になる。
    expect(normalizeAccessTeamDomain("https://")).toBeNull();
  });

  it("rejects unparsable garbage", () => {
    expect(normalizeAccessTeamDomain("::")).toBeNull();
    expect(normalizeAccessTeamDomain("team domain.example")).toBeNull();
  });
});

describe("access logout chain marker", () => {
  const req = (cookie?: string) =>
    new Request("https://auth.ippoan.org/logout", cookie ? { headers: { Cookie: cookie } } : {});

  it("is absent when no cookie is sent", () => {
    expect(hasAccessLogoutChainMarker(req())).toBe(false);
    expect(hasAccessLogoutChainMarker(req("logi_auth_token=abc"))).toBe(false);
  });

  it("is found on its own and alongside other cookies", () => {
    expect(hasAccessLogoutChainMarker(req(`${ACCESS_LOGOUT_CHAIN_COOKIE}=1`))).toBe(true);
    expect(
      hasAccessLogoutChainMarker(req(`logi_auth_token=abc; ${ACCESS_LOGOUT_CHAIN_COOKIE}=1`)),
    ).toBe(true);
  });

  it("does not match a cookie whose name merely ends with it", () => {
    expect(hasAccessLogoutChainMarker(req(`not_${ACCESS_LOGOUT_CHAIN_COOKIE}=1`))).toBe(false);
  });

  it("builds a short-lived host-only Set-Cookie", () => {
    const c = accessLogoutChainMarkerCookie();
    expect(c).toContain(`${ACCESS_LOGOUT_CHAIN_COOKIE}=1`);
    expect(c).toContain("Max-Age=60");
    expect(c).toContain("Secure");
    expect(c).not.toContain("Domain=");
  });
});

describe("logoutNavigationTarget", () => {
  const target = (redirectTo: string) =>
    logoutNavigationTarget(AUTH_ORIGIN, AUTH_HOST, redirectTo, TEAM);

  it("chains a relative redirect through the Access logout", () => {
    expect(target("/login")).toEqual({
      target: `https://${TEAM}/cdn-cgi/access/logout?returnTo=${encodeURIComponent("https://auth.ippoan.org/login")}`,
      chained: true,
    });
  });

  it("chains an Access-protected app URL and keeps its query string", () => {
    const app = "https://dtako.ippoan.org/?lw_callback=1";
    expect(target(app)).toEqual({
      target: `https://${TEAM}/cdn-cgi/access/logout?returnTo=${encodeURIComponent(app)}`,
      chained: true,
    });
  });

  // Refs #477 の redirect loop — auth-client の reauth が /logout を叩き続けるため、
  // 無条件に chain すると 1 周ごとに Cloudflare Access を往復する。
  it("does not chain when /logout was hit moments ago", () => {
    expect(logoutNavigationTarget(AUTH_ORIGIN, AUTH_HOST, "/login", TEAM, true)).toEqual({
      target: "/login",
      chained: false,
    });
  });

  it("does not chain when ACCESS_TEAM_DOMAIN is unset", () => {
    expect(logoutNavigationTarget(AUTH_ORIGIN, AUTH_HOST, "/login", undefined)).toEqual({
      target: "/login",
      chained: false,
    });
    expect(logoutNavigationTarget(AUTH_ORIGIN, AUTH_HOST, "/login", "")).toEqual({
      target: "/login",
      chained: false,
    });
  });

  // Access は知らないホストへの returnTo を 400 で弾く (2026-08-26 実測) ため、
  // chain すると「ログアウト後に CF のエラーページで行き止まり」になる。
  it("does not chain a foreign host (Access would answer 400)", () => {
    expect(target("https://example.com/evil").chained).toBe(false);
    expect(target("https://app.nuxt-logi.pages.dev/").target).toBe(
      "https://app.nuxt-logi.pages.dev/",
    );
  });

  it("does not chain a non-https destination", () => {
    expect(target("http://auth.ippoan.org/login").target).toBe("http://auth.ippoan.org/login");
    expect(target("javascript:alert(1)").chained).toBe(false);
  });

  it("does not chain an unparsable redirect target", () => {
    expect(logoutNavigationTarget("::not a url::", AUTH_HOST, "/login", TEAM).target).toBe("/login");
  });

  it("does not chain when the auth host has no shareable parent domain", () => {
    expect(
      logoutNavigationTarget("http://localhost:8787", "localhost", "/login", TEAM).chained,
    ).toBe(false);
  });
});
