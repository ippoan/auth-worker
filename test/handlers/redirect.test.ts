import { describe, it, expect } from "vitest";
import { handleRedirect } from "../../src/handlers/redirect";
import { createMockEnv } from "../helpers/mock-env";

describe("handleRedirect", () => {
  const env = createMockEnv();

  it("returns HTML with sessionStorage redirect for valid target", async () => {
    const req = new Request("https://auth.test.example/redirect?to=https://app1.test.example");
    const res = await handleRedirect(req, env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    const html = await res.text();
    expect(html).toContain("sessionStorage.getItem('auth_token')");
    expect(html).toContain("https://app1.test.example");
  });

  it("redirects to target with token fragment when token exists", async () => {
    const req = new Request("https://auth.test.example/redirect?to=https://app2.test.example");
    const res = await handleRedirect(req, env);
    const html = await res.text();
    expect(html).toContain("#token=");
    expect(html).toContain("window.location.replace");
  });

  it("falls back to /login when no token in sessionStorage", async () => {
    const req = new Request("https://auth.test.example/redirect?to=https://app1.test.example");
    const res = await handleRedirect(req, env);
    const html = await res.text();
    expect(html).toContain("/login?redirect_uri=");
  });

  it("returns 400 when to parameter is missing", async () => {
    const req = new Request("https://auth.test.example/redirect");
    const res = await handleRedirect(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 400 when to parameter is not in allowed origins", async () => {
    const req = new Request("https://auth.test.example/redirect?to=https://evil.example.com");
    const res = await handleRedirect(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 400 for invalid URL in to parameter", async () => {
    const req = new Request("https://auth.test.example/redirect?to=not-a-url");
    const res = await handleRedirect(req, env);
    expect(res.status).toBe(400);
  });
});
