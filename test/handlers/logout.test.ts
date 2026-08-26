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
