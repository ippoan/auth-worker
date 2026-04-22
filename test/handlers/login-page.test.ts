import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

vi.mock("../../src/lib/html", () => ({
  renderLoginPage: vi.fn(() => "<html>mock login page</html>"),
}));

import { handleLoginPage } from "../../src/handlers/login-page";
import { renderLoginPage } from "../../src/lib/html";

describe("handleLoginPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("redirects to /login?redirect_uri=.../top when no redirect_uri", async () => {
    const env = createMockEnv();
    const request = new Request("https://auth.test.example/login");

    const response = await handleLoginPage(request, env);

    expect(response.status).toBe(302);
    const location = response.headers.get("Location");
    expect(location).toContain("/login?redirect_uri=");
    expect(location).toContain(encodeURIComponent("https://auth.test.example/top"));
  });

  it("returns 400 for invalid redirect_uri", async () => {
    const env = createMockEnv();
    const request = new Request(
      "https://auth.test.example/login?redirect_uri=https://evil.example.com",
    );

    const response = await handleLoginPage(request, env);

    expect(response.status).toBe(400);
    expect(await response.text()).toBe("Invalid redirect_uri");
  });

  it("renders HTML with Content-Type for valid redirect_uri", async () => {
    const env = createMockEnv();
    const request = new Request(
      "https://auth.test.example/login?redirect_uri=https://app1.test.example/page",
    );

    const response = await handleLoginPage(request, env);

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(await response.text()).toBe("<html>mock login page</html>");
    expect(renderLoginPage).toHaveBeenCalledOnce();
  });

  it("passes googleEnabled=false when GOOGLE_CLIENT_ID is empty", async () => {
    const env = createMockEnv({ GOOGLE_CLIENT_ID: "" });
    const request = new Request(
      "https://auth.test.example/login?redirect_uri=https://app1.test.example/page",
    );

    await handleLoginPage(request, env);

    expect(renderLoginPage).toHaveBeenCalledWith(
      expect.objectContaining({
        googleEnabled: false,
        googleRedirectUrl: "",
      }),
    );
  });

  it("passes googleEnabled=true when GOOGLE_CLIENT_ID is set", async () => {
    const env = createMockEnv();
    const request = new Request(
      "https://auth.test.example/login?redirect_uri=https://app1.test.example/page",
    );

    await handleLoginPage(request, env);

    expect(renderLoginPage).toHaveBeenCalledWith(
      expect.objectContaining({
        googleEnabled: true,
      }),
    );
  });

  it("passes orgId and error params", async () => {
    const env = createMockEnv();
    const request = new Request(
      "https://auth.test.example/login?redirect_uri=https://app1.test.example/page&org_id=org123&error=invalid_token",
    );

    await handleLoginPage(request, env);

    expect(renderLoginPage).toHaveBeenCalledWith(
      expect.objectContaining({
        orgId: "org123",
        error: "invalid_token",
      }),
    );
  });

  it("handles empty ALC_API_ORIGIN and AUTH_WORKER_ORIGIN", async () => {
    const env = createMockEnv({ ALC_API_ORIGIN: "", AUTH_WORKER_ORIGIN: "" });
    const request = new Request(
      "https://auth.test.example/login?redirect_uri=https://app1.test.example/page",
    );
    await handleLoginPage(request, env);
    expect(renderLoginPage).toHaveBeenCalledWith(
      expect.objectContaining({
        googleRedirectUrl: expect.stringContaining("/oauth/google/redirect"),
        lineworksRedirectUrl: expect.stringContaining("/oauth/lineworks/redirect"),
      }),
    );
  });

  it("passes undefined for missing orgId and error", async () => {
    const env = createMockEnv();
    const request = new Request(
      "https://auth.test.example/login?redirect_uri=https://app1.test.example/page",
    );

    await handleLoginPage(request, env);

    expect(renderLoginPage).toHaveBeenCalledWith(
      expect.objectContaining({
        orgId: undefined,
        error: undefined,
      }),
    );
  });

  describe("LOGIN_DELEGATE_TO delegation (wt-quick tunnel mode)", () => {
    it("delegates to LOGIN_DELEGATE_TO preserving explicit redirect_uri", async () => {
      const env = createMockEnv({ LOGIN_DELEGATE_TO: "https://auth.mtamaramu.com" });
      const request = new Request(
        "https://wt.trycloudflare.com/login?redirect_uri=https://wt.trycloudflare.com/top",
      );

      const response = await handleLoginPage(request, env);

      expect(response.status).toBe(200);
      expect(response.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
      const body = await response.text();
      expect(body).toContain(
        'https://auth.mtamaramu.com/login?redirect_uri=https%3A%2F%2Fwt.trycloudflare.com%2Ftop',
      );
      expect(body).toContain("location.replace");
      expect(body).toContain('<meta http-equiv="refresh"');
      expect(renderLoginPage).not.toHaveBeenCalled();
    });

    it("falls back target to AUTH_WORKER_ORIGIN/top when redirect_uri is missing", async () => {
      const env = createMockEnv({
        LOGIN_DELEGATE_TO: "https://auth.mtamaramu.com",
        AUTH_WORKER_ORIGIN: "https://wt.trycloudflare.com",
      });
      const request = new Request("https://wt.trycloudflare.com/login");

      const response = await handleLoginPage(request, env);

      expect(response.status).toBe(200);
      const body = await response.text();
      expect(body).toContain(
        'redirect_uri=https%3A%2F%2Fwt.trycloudflare.com%2Ftop',
      );
    });

    it("falls back target to url.origin/top when AUTH_WORKER_ORIGIN is empty", async () => {
      const env = createMockEnv({
        LOGIN_DELEGATE_TO: "https://auth.mtamaramu.com",
        AUTH_WORKER_ORIGIN: "",
      });
      const request = new Request("https://fallback.example/login");

      const response = await handleLoginPage(request, env);

      expect(response.status).toBe(200);
      const body = await response.text();
      expect(body).toContain(
        'redirect_uri=https%3A%2F%2Ffallback.example%2Ftop',
      );
    });

    it("forwards org_id in delegation URL when present", async () => {
      const env = createMockEnv({ LOGIN_DELEGATE_TO: "https://auth.mtamaramu.com" });
      const request = new Request(
        "https://wt.trycloudflare.com/login?redirect_uri=https://wt.trycloudflare.com/top&org_id=org-xyz",
      );

      const response = await handleLoginPage(request, env);

      expect(response.status).toBe(200);
      const body = await response.text();
      expect(body).toContain("org_id=org-xyz");
    });

    it("does not delegate when LOGIN_DELEGATE_TO is unset (default behavior)", async () => {
      const env = createMockEnv();
      const request = new Request(
        "https://auth.test.example/login?redirect_uri=https://app1.test.example/page",
      );

      const response = await handleLoginPage(request, env);

      expect(response.status).toBe(200);
      expect(renderLoginPage).toHaveBeenCalledOnce();
    });
  });
});
