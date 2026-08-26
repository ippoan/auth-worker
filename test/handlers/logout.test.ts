import { describe, it, expect } from "vitest";
import { handleLogout } from "../../src/handlers/logout";
import { createMockEnv } from "../helpers/mock-env";

describe("handleLogout", () => {
  const env = createMockEnv();

  it("returns HTML page (not a 302 redirect)", async () => {
    const req = new Request("https://auth.test.example/logout");
    const res = await handleLogout(req, env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
  });

  it("clears logi_auth_token cookie via Set-Cookie header", async () => {
    const req = new Request("https://auth.test.example/logout");
    const res = await handleLogout(req, env);
    expect(res.headers.get("Set-Cookie")).toContain("logi_auth_token=");
    expect(res.headers.get("Set-Cookie")).toContain("Max-Age=0");
  });

  it("clears sessionStorage and localStorage", async () => {
    const req = new Request("https://auth.test.example/logout");
    const res = await handleLogout(req, env);
    const html = await res.text();
    expect(html).toContain("sessionStorage.removeItem('auth_token')");
    expect(html).toContain("localStorage.removeItem('logi_auth')");
  });

  it("clears cookies for backward compatibility", async () => {
    const req = new Request("https://auth.test.example/logout");
    const res = await handleLogout(req, env);
    const html = await res.text();
    expect(html).toContain("sso_admin_token");
    expect(html).toContain("logi_auth_token");
    expect(html).toContain("Max-Age=0");
  });

  it("redirects to /login by default", async () => {
    const req = new Request("https://auth.test.example/logout");
    const res = await handleLogout(req, env);
    const html = await res.text();
    expect(html).toContain("window.location.replace('/login')");
  });

  it("redirects to custom redirect_uri", async () => {
    const req = new Request("https://auth.test.example/logout?redirect_uri=https://app.example.com");
    const res = await handleLogout(req, env);
    const html = await res.text();
    expect(html).toContain("window.location.replace('https://app.example.com')");
  });

  // Refs #477 — cookie を捨てただけでは Access のセッション (24h) が生き残り、
  // 守られたアプリに戻ると「ログアウトしたのに Access だけ入ったまま」になる。
  describe("Cloudflare Access logout chaining", () => {
    const TEAM = "mtamaramu.cloudflareaccess.com";
    const accessEnv = createMockEnv({ ACCESS_TEAM_DOMAIN: TEAM });

    it("sends the default /login destination through the Access logout", async () => {
      const req = new Request("https://auth.test.example/logout");
      const res = await handleLogout(req, accessEnv);
      const html = await res.text();
      const returnTo = encodeURIComponent("https://auth.test.example/login");
      expect(html).toContain(
        `window.location.replace('https://${TEAM}/cdn-cgi/access/logout?returnTo=${returnTo}')`,
      );
    });

    it("keeps the caller's redirect_uri as returnTo", async () => {
      const app = "https://dtako.test.example/?lw_callback=1";
      const req = new Request(
        `https://auth.test.example/logout?redirect_uri=${encodeURIComponent(app)}`,
      );
      const res = await handleLogout(req, accessEnv);
      const html = await res.text();
      expect(html).toContain(
        `window.location.replace('https://${TEAM}/cdn-cgi/access/logout?returnTo=${encodeURIComponent(app)}')`,
      );
    });

    it("still clears the auth cookie before handing off to Access", async () => {
      const req = new Request("https://auth.test.example/logout");
      const res = await handleLogout(req, accessEnv);
      expect(res.headers.get("Set-Cookie")).toContain("logi_auth_token=");
      expect(res.headers.get("Set-Cookie")).toContain("Max-Age=0");
    });

    // Access は知らないホストへの returnTo を 400 で弾く (2026-08-26 実測)。
    it("does not chain a destination Access would reject", async () => {
      const req = new Request(
        "https://auth.test.example/logout?redirect_uri=https%3A%2F%2Fapp.example.com%2F",
      );
      const res = await handleLogout(req, accessEnv);
      const html = await res.text();
      expect(html).toContain("window.location.replace('https://app.example.com/')");
      expect(html).not.toContain("cdn-cgi/access/logout");
    });

    it("is a no-op when ACCESS_TEAM_DOMAIN is not configured", async () => {
      const req = new Request("https://auth.test.example/logout");
      const res = await handleLogout(req, env);
      const html = await res.text();
      expect(html).toContain("window.location.replace('/login')");
      expect(html).not.toContain("cdn-cgi/access/logout");
    });
  });
});

// Refs #477 の redirect loop — `@ippoan/auth-client` の initAuthSession は
// auth-worker から `?lw_callback=1` で戻ったのにセッションを復元できないと
// `redirectToLogin({ reauth: true })` = `/logout` を叩く。ここで無条件に Access を
// 切ると 1 周ごとに Cloudflare Access を往復する無限ループになる。
describe("handleLogout — Access chain loop guard", () => {
  const TEAM = "mtamaramu.cloudflareaccess.com";
  const accessEnv = createMockEnv({ ACCESS_TEAM_DOMAIN: TEAM });
  const setCookies = (res: Response): string[] => res.headers.getSetCookie();

  it("always (re)issues the marker cookie so a loop keeps refreshing it", async () => {
    const res = await handleLogout(new Request("https://auth.test.example/logout"), accessEnv);
    expect(setCookies(res).some((c) => c.startsWith("access_logout_chained=1"))).toBe(true);
  });

  it("skips the Access chain when the marker is already present", async () => {
    const req = new Request("https://auth.test.example/logout", {
      headers: { Cookie: "access_logout_chained=1" },
    });
    const html = await (await handleLogout(req, accessEnv)).text();
    expect(html).toContain("window.location.replace('/login')");
    expect(html).not.toContain("cdn-cgi/access/logout");
  });

  it("still clears the auth cookie on the guarded pass", async () => {
    const req = new Request("https://auth.test.example/logout", {
      headers: { Cookie: "access_logout_chained=1" },
    });
    const res = await handleLogout(req, accessEnv);
    expect(setCookies(res).some((c) => c.startsWith("logi_auth_token=") && c.includes("Max-Age=0")))
      .toBe(true);
  });

  // 1 周目は Access を切り、2 周目以降は切らない = ループが Access から外れる。
  it("chains only on the first pass of a logout → relogin loop", async () => {
    const first = await handleLogout(new Request("https://auth.test.example/logout"), accessEnv);
    expect(await first.text()).toContain("cdn-cgi/access/logout");

    const marker = setCookies(first).find((c) => c.startsWith("access_logout_chained="));
    expect(marker).toBeDefined();
    const second = await handleLogout(
      new Request("https://auth.test.example/logout", {
        headers: { Cookie: marker!.split(";")[0]! },
      }),
      accessEnv,
    );
    expect(await second.text()).not.toContain("cdn-cgi/access/logout");
  });
});
