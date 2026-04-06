import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/lib/admin-users-html", () => ({
  renderAdminUsersPage: vi.fn(() => "<html>mock admin users page</html>"),
}));

import { handleAdminUsersPage, handleAdminUsersCallback } from "../../src/handlers/admin-users";
import { createMockEnv } from "../helpers/mock-env";

describe("handleAdminUsersPage", () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it("always returns HTML", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/admin/users");
    const res = await handleAdminUsersPage(req, env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(await res.text()).toBe("<html>mock admin users page</html>");
  });
});

describe("handleAdminUsersCallback", () => {
  it("returns HTML with sessionStorage.setItem", async () => {
    const res = await handleAdminUsersCallback();
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("sessionStorage.setItem('auth_token'");
    expect(html).not.toContain("document.cookie");
  });
});
