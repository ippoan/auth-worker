import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/lib/admin-rich-menu-html", () => ({
  renderAdminRichMenuPage: vi.fn(() => "<html>mock admin rich menu page</html>"),
}));

import { handleAdminRichMenuPage, handleAdminRichMenuCallback } from "../../src/handlers/admin-rich-menu";
import { createMockEnv } from "../helpers/mock-env";

describe("handleAdminRichMenuPage", () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it("always returns HTML", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/admin/rich-menu");
    const res = await handleAdminRichMenuPage(req, env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(await res.text()).toBe("<html>mock admin rich menu page</html>");
  });
});

describe("handleAdminRichMenuCallback", () => {
  it("returns HTML with sessionStorage.setItem", async () => {
    const res = await handleAdminRichMenuCallback();
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("sessionStorage.setItem('auth_token'");
    expect(html).not.toContain("document.cookie");
  });
});
