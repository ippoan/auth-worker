import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

vi.mock("../../src/lib/admin-html", () => ({
  renderAdminSsoPage: vi.fn(() => "<html>mock admin sso page</html>"),
}));

import { handleAdminSsoPage, handleAdminSsoCallback } from "../../src/handlers/admin-sso";
import { renderAdminSsoPage } from "../../src/lib/admin-html";

describe("handleAdminSsoPage", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("redirects to /login when no cookie", async () => {
    const env = createMockEnv();
    const request = new Request("https://auth.test.example/admin/sso");

    const response = await handleAdminSsoPage(request, env);

    expect(response.status).toBe(302);
    const location = response.headers.get("Location");
    expect(location).toContain("/login?redirect_uri=");
    expect(location).toContain(encodeURIComponent("/admin/sso/callback"));
  });

  it("uses sso_admin_token cookie when present", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("ok", { status: 200 })),
    );
    const env = createMockEnv();
    const request = new Request("https://auth.test.example/admin/sso", {
      headers: { Cookie: "sso_admin_token=admin-jwt-123" },
    });

    const response = await handleAdminSsoPage(request, env);

    expect(response.status).toBe(200);
    expect(await response.text()).toBe("<html>mock admin sso page</html>");
    expect(globalThis.fetch).toHaveBeenCalledWith(
      "https://alc-api.test.example/api/admin/sso/configs",
      expect.objectContaining({
        headers: { Authorization: "Bearer admin-jwt-123" },
      }),
    );
  });

  it("falls back to logi_auth_token cookie", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("ok", { status: 200 })),
    );
    const env = createMockEnv();
    const request = new Request("https://auth.test.example/admin/sso", {
      headers: { Cookie: "logi_auth_token=shared-jwt-456" },
    });

    const response = await handleAdminSsoPage(request, env);

    expect(response.status).toBe(200);
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        headers: { Authorization: "Bearer shared-jwt-456" },
      }),
    );
  });

  it("redirects to /top?error=no_permission on 403", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("forbidden", { status: 403 })),
    );
    const env = createMockEnv();
    const request = new Request("https://auth.test.example/admin/sso", {
      headers: { Cookie: "sso_admin_token=bad-token" },
    });

    const response = await handleAdminSsoPage(request, env);

    expect(response.status).toBe(302);
    expect(response.headers.get("Location")).toContain("/top?error=no_permission");
  });

  it("still renders page when permission fetch throws", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("network error")),
    );
    const env = createMockEnv();
    const request = new Request("https://auth.test.example/admin/sso", {
      headers: { Cookie: "sso_admin_token=some-token" },
    });

    const response = await handleAdminSsoPage(request, env);

    expect(response.status).toBe(200);
    expect(await response.text()).toBe("<html>mock admin sso page</html>");
  });

  it("renders admin HTML page on permission OK", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("ok", { status: 200 })),
    );
    const env = createMockEnv({
      ALLOWED_REDIRECT_ORIGINS: "https://app1.example,https://auth.test.example",
    });
    const request = new Request("https://auth.test.example/admin/sso", {
      headers: { Cookie: "sso_admin_token=good-token" },
    });

    const response = await handleAdminSsoPage(request, env);

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(renderAdminSsoPage).toHaveBeenCalledWith(["https://app1.example"]);
  });

  it("handles undefined ALLOWED_REDIRECT_ORIGINS", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("ok", { status: 200 })),
    );
    const env = createMockEnv({ ALLOWED_REDIRECT_ORIGINS: "" });
    const request = new Request("https://auth.test.example/admin/sso", {
      headers: { Cookie: "sso_admin_token=tok" },
    });
    const response = await handleAdminSsoPage(request, env);
    expect(response.status).toBe(200);
    expect(renderAdminSsoPage).toHaveBeenCalledWith([]);
  });
});

describe("handleAdminSsoCallback", () => {
  it("returns HTML with correct Content-Type", async () => {
    const response = await handleAdminSsoCallback();

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    const html = await response.text();
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("sso_admin_token");
  });
});
