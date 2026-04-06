import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/lib/admin-requests-html", () => ({
  renderAdminRequestsPage: vi.fn(() => "<html>mock admin requests page</html>"),
}));

import { handleAdminRequestsPage, handleAdminRequestsCallback } from "../../src/handlers/admin-requests";
import { createMockEnv } from "../helpers/mock-env";

describe("handleAdminRequestsPage", () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it("always returns HTML", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/admin/requests");
    const res = await handleAdminRequestsPage(req, env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(await res.text()).toBe("<html>mock admin requests page</html>");
  });
});

describe("handleAdminRequestsCallback", () => {
  it("returns HTML with sessionStorage.setItem", async () => {
    const res = await handleAdminRequestsCallback();
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("sessionStorage.setItem('auth_token'");
    expect(html).not.toContain("document.cookie");
  });
});
