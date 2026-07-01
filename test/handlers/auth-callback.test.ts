import { describe, it, expect } from "vitest";
import { handleAuthCallback } from "../../src/handlers/auth-callback";

describe("handleAuthCallback", () => {
  it("returns 200 HTML that lands on /top by default", async () => {
    const res = await handleAuthCallback(
      new Request("https://auth.test.example/auth/callback?lw_callback=1"),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    const body = await res.text();
    expect(body).toContain("var dest = \"/top\"");
    expect(body).toContain("logi_auth_token=");
  });

  it("honors a relative ?to= path", async () => {
    const res = await handleAuthCallback(
      new Request("https://auth.test.example/auth/callback?to=/admin/line-users"),
    );
    const body = await res.text();
    expect(body).toContain('var dest = "/admin/line-users"');
  });

  it("ignores absolute ?to= (open-redirect prevention) → falls back to /top", async () => {
    const res = await handleAuthCallback(
      new Request("https://auth.test.example/auth/callback?to=https://evil.example.com"),
    );
    const body = await res.text();
    expect(body).toContain('var dest = "/top"');
    expect(body).not.toContain("evil.example.com");
  });
});
