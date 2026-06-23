import { describe, it, expect } from "vitest";
import { handleRedirect } from "../../src/handlers/redirect";
import { createMockEnv } from "../helpers/mock-env";

describe("handleRedirect", () => {
  const env = createMockEnv();

  it("returns HTML that reads the token (sessionStorage / cookie)", async () => {
    const req = new Request("https://auth.test.example/redirect?to=https://app1.test.example");
    const res = await handleRedirect(req, env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    const html = await res.text();
    expect(html).toContain("sessionStorage.getItem('auth_token')");
    expect(html).toContain("https://app1.test.example");
  });

  it("uses cookie handoff (no token fragment) for a same-parent-domain target", async () => {
    // app1.test.example shares parent .test.example with auth.test.example, so the
    // shared cookie reaches it → no #token= in the URL, redirect to the bare target.
    const req = new Request("https://auth.test.example/redirect?to=https://app1.test.example");
    const res = await handleRedirect(req, env);
    const html = await res.text();
    // 両ブランチが静的 HTML に含まれるため、実行時にどちらを走らせるかは
    // cookieHandoff フラグで決まる。フラグ値と cookie 配布コードを検査する。
    expect(html).toContain("var cookieHandoff = true");
    expect(html).toContain("document.cookie =");
    expect(html).toContain("window.location.replace(target)");
  });

  it("falls back to token fragment for a target the shared cookie cannot reach", async () => {
    // *.workers.dev is a public suffix → Domain cookie cannot be set → fragment handoff.
    const wdEnv = createMockEnv({
      allowedOrigins:
        "https://app1.test.example,https://app2.test.example,https://auth.test.example,https://my-app.workers.dev",
    });
    const req = new Request("https://auth.test.example/redirect?to=https://my-app.workers.dev");
    const res = await handleRedirect(req, wdEnv);
    const html = await res.text();
    expect(html).toContain("var cookieHandoff = false");
    expect(html).toContain("#token=");
    expect(html).toContain("window.location.replace");
  });

  it("falls back to /login when no token is available", async () => {
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
