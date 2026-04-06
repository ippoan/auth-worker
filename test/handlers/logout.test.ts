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
});
