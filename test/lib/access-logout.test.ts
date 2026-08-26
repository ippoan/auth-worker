import { describe, it, expect } from "vitest";
import {
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

describe("logoutNavigationTarget", () => {
  const target = (redirectTo: string) =>
    logoutNavigationTarget(AUTH_ORIGIN, AUTH_HOST, redirectTo, TEAM);

  it("chains a relative redirect through the Access logout", () => {
    expect(target("/login")).toBe(
      `https://${TEAM}/cdn-cgi/access/logout?returnTo=${encodeURIComponent("https://auth.ippoan.org/login")}`,
    );
  });

  it("chains an Access-protected app URL and keeps its query string", () => {
    const app = "https://dtako.ippoan.org/?lw_callback=1";
    expect(target(app)).toBe(
      `https://${TEAM}/cdn-cgi/access/logout?returnTo=${encodeURIComponent(app)}`,
    );
  });

  it("does not chain when ACCESS_TEAM_DOMAIN is unset", () => {
    expect(logoutNavigationTarget(AUTH_ORIGIN, AUTH_HOST, "/login", undefined)).toBe("/login");
    expect(logoutNavigationTarget(AUTH_ORIGIN, AUTH_HOST, "/login", "")).toBe("/login");
  });

  // Access は知らないホストへの returnTo を 400 で弾く (2026-08-26 実測) ため、
  // chain すると「ログアウト後に CF のエラーページで行き止まり」になる。
  it("does not chain a foreign host (Access would answer 400)", () => {
    expect(target("https://example.com/evil")).toBe("https://example.com/evil");
    expect(target("https://app.nuxt-logi.pages.dev/")).toBe("https://app.nuxt-logi.pages.dev/");
  });

  it("does not chain a non-https destination", () => {
    expect(target("http://auth.ippoan.org/login")).toBe("http://auth.ippoan.org/login");
    expect(target("javascript:alert(1)")).toBe("javascript:alert(1)");
  });

  it("does not chain an unparsable redirect target", () => {
    // base があるので相対解決はほぼ失敗しないが、壊れた値でも素通しになること。
    expect(logoutNavigationTarget("::not a url::", AUTH_HOST, "/login", TEAM)).toBe("/login");
  });

  it("does not chain when the auth host has no shareable parent domain", () => {
    expect(logoutNavigationTarget("http://localhost:8787", "localhost", "/login", TEAM)).toBe(
      "/login",
    );
  });
});
