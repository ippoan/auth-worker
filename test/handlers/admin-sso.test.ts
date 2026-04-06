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
      ALLOWED_REDIRECT_ORIGINS: "https://app1.example,https://auth.test.example",
    });
    const request = new Request("https://auth.test.example/admin/sso");

    await handleAdminSsoPage(request, env);

    expect(renderAdminSsoPage).toHaveBeenCalledWith(["https://app1.example"]);
  });

  it("handles empty ALLOWED_REDIRECT_ORIGINS", async () => {
    const env = createMockEnv({ ALLOWED_REDIRECT_ORIGINS: "" });
    const request = new Request("https://auth.test.example/admin/sso");

    await handleAdminSsoPage(request, env);

    expect(renderAdminSsoPage).toHaveBeenCalledWith([]);
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
    expect(html).not.toContain("document.cookie");
  });
});
