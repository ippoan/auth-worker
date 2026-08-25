import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

vi.mock("../../src/lib/admin-html", () => ({
  renderAdminSsoPage: vi.fn(() => "<html>mock admin sso page</html>"),
}));

import { handleAdminSsoPage, handleAdminSsoCallback } from "../../src/handlers/admin-sso";
import { renderAdminSsoPage } from "../../src/lib/admin-html";

describe("handleAdminSsoPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("always returns HTML (no server-side auth check)", async () => {
    const env = createMockEnv();
    const request = new Request("https://auth.test.example/admin/sso");

    const response = await handleAdminSsoPage(request, env);

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(await response.text()).toBe("<html>mock admin sso page</html>");
  });

  it("filters out AUTH_WORKER_ORIGIN from ALLOWED_REDIRECT_ORIGINS", async () => {
    const env = createMockEnv({
      allowedOrigins: "https://app1.example,https://auth.test.example",
    });
    const request = new Request("https://auth.test.example/admin/sso");

    await handleAdminSsoPage(request, env);

    expect(renderAdminSsoPage).toHaveBeenCalledWith(["https://app1.example"], "/top");
  });

  it("handles empty ALLOWED_REDIRECT_ORIGINS", async () => {
    const env = createMockEnv({ allowedOrigins: "" });
    const request = new Request("https://auth.test.example/admin/sso");

    await handleAdminSsoPage(request, env);

    expect(renderAdminSsoPage).toHaveBeenCalledWith([], "/top");
  });

  it("uses ?from= as backUrl when origin is in allowlist", async () => {
    const env = createMockEnv({
      allowedOrigins: "https://app1.example,https://auth.test.example",
    });
    const request = new Request(
      "https://auth.test.example/admin/sso?from=https%3A%2F%2Fapp1.example",
    );

    await handleAdminSsoPage(request, env);

    expect(renderAdminSsoPage).toHaveBeenCalledWith(
      ["https://app1.example"],
      "https://app1.example",
    );
  });

  it("falls back to /top when ?from= is not in allowlist", async () => {
    const env = createMockEnv({
      allowedOrigins: "https://app1.example,https://auth.test.example",
    });
    const request = new Request(
      "https://auth.test.example/admin/sso?from=https%3A%2F%2Fevil.example",
    );

    await handleAdminSsoPage(request, env);

    expect(renderAdminSsoPage).toHaveBeenCalledWith(["https://app1.example"], "/top");
  });

  it("allows ?from= matching AUTH_WORKER_ORIGIN itself", async () => {
    const env = createMockEnv({
      allowedOrigins: "https://app1.example,https://auth.test.example",
    });
    const request = new Request(
      "https://auth.test.example/admin/sso?from=https%3A%2F%2Fauth.test.example",
    );

    await handleAdminSsoPage(request, env);

    // frontendOrigins still excludes AUTH_WORKER_ORIGIN, but backUrl can use it
    expect(renderAdminSsoPage).toHaveBeenCalledWith(
      ["https://app1.example"],
      "https://auth.test.example",
    );
  });
});

describe("handleAdminSsoCallback", () => {
  it("returns HTML that stores token in sessionStorage", async () => {
    const response = await handleAdminSsoCallback();

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    const html = await response.text();
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("sessionStorage.setItem('auth_token'");
    // #474: cookie 配送 (fragment 無し) でも着地できるよう、共通門番が
    // document.cookie の logi_auth_token を読む。
    expect(html).toContain("document.cookie");
    expect(html).toContain("logi_auth_token");
  });
});
