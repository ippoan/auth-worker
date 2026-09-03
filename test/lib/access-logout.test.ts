import { describe, it, expect } from "vitest";
import {
  ACCESS_LOGOUT_CHAIN_COOKIE,
  ACCESS_LOGOUT_RETURN_PATH,
  resolveLogoutReturnTarget,
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

  // returnTo は最終先ではなく **auth-worker 自身の中継** (Refs #499)。
  const expected = (finalUrl: string) => {
    const relay = new URL(`${AUTH_ORIGIN}/logout/return`);
    relay.searchParams.set("to", finalUrl);
    return `https://${TEAM}/cdn-cgi/access/logout?returnTo=${encodeURIComponent(relay.toString())}`;
  };

  it("chains a relative redirect through the Access logout", () => {
    expect(target("/login")).toEqual({
      target: expected("https://auth.ippoan.org/login"),
      chained: true,
    });
  });

  it("chains an app URL and keeps its query string in the relay's ?to=", () => {
    const app = "https://dtako.ippoan.org/?lw_callback=1";
    expect(target(app)).toEqual({ target: expected(app), chained: true });
  });

  // 2026-09-03 の行き止まり — alc.ippoan.org には Access アプリが無く、
  // returnTo にそのまま載せると CF が `Invalid redirect URL` (400) を返した。
  // 中継を挟む今は「Access に登録の無い自ホスト」でも chain できる。
  it("chains a host that has no Access app of its own", () => {
    const app = "https://alc.ippoan.org/login";
    expect(target(app)).toEqual({ target: expected(app), chained: true });
    expect(target(app).target).not.toContain("returnTo=https%3A%2F%2Falc.ippoan.org");
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

describe("resolveLogoutReturnTarget", () => {
  const resolve = (redirectTo: string) =>
    resolveLogoutReturnTarget(AUTH_ORIGIN, AUTH_HOST, redirectTo);

  it("resolves a relative target against the auth origin", () => {
    expect(resolve("/login")?.toString()).toBe("https://auth.ippoan.org/login");
  });

  it("accepts any https host under the shared parent domain", () => {
    expect(resolve("https://alc.ippoan.org/login")?.toString()).toBe(
      "https://alc.ippoan.org/login",
    );
    expect(resolve("https://ippoan.org/")?.toString()).toBe("https://ippoan.org/");
  });

  it("rejects foreign hosts, non-https and garbage", () => {
    expect(resolve("https://example.com/evil")).toBeNull();
    expect(resolve("https://app.nuxt-logi.pages.dev/")).toBeNull();
    expect(resolve("http://auth.ippoan.org/login")).toBeNull();
    expect(resolve("javascript:alert(1)")).toBeNull();
    expect(resolveLogoutReturnTarget("::not a url::", AUTH_HOST, "/login")).toBeNull();
  });

  it("exposes the relay path used as the Access returnTo", () => {
    expect(ACCESS_LOGOUT_RETURN_PATH).toBe("/logout/return");
  });
});
