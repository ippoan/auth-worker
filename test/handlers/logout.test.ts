import { describe, it, expect } from "vitest";
import { handleLogout } from "../../src/handlers/logout";
import { createMockEnv } from "../helpers/mock-env";

describe("handleLogout", () => {
  const env = createMockEnv();

  it("redirects to /login by default", async () => {
    const req = new Request("https://auth.test.example/logout");
    const res = await handleLogout(req, env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/login");
  });

  it("redirects to custom redirect_uri", async () => {
    const req = new Request("https://auth.test.example/logout?redirect_uri=https://app.example.com");
    const res = await handleLogout(req, env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("https://app.example.com");
  });

  it("clears auth cookies", async () => {
    const req = new Request("https://auth.test.example/logout");
    const res = await handleLogout(req, env);
    // Node Headers joins Set-Cookie with ", " — check combined string
    const cookieHeader = res.headers.get("Set-Cookie") ?? "";
    expect(cookieHeader).toContain("sso_admin_token");
    expect(cookieHeader).toContain("Max-Age=0");
    expect(cookieHeader).toContain("logi_auth_token");
  });
});
