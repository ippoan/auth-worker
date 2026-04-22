import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/lib/admin-notify-html", () => ({
  renderAdminNotifyPage: vi.fn(
    (origin: string) => `<html>mock admin notify page (${origin})</html>`,
  ),
}));

import {
  handleAdminNotifyPage,
  handleAdminNotifyCallback,
} from "../../src/handlers/admin-notify";
import { createMockEnv } from "../helpers/mock-env";
import { renderAdminNotifyPage } from "../../src/lib/admin-notify-html";

describe("handleAdminNotifyPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns HTML built from env.ALC_API_ORIGIN", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/admin/notify");
    const res = await handleAdminNotifyPage(req, env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(renderAdminNotifyPage).toHaveBeenCalledWith(env.ALC_API_ORIGIN);
    expect(await res.text()).toContain("mock admin notify page");
  });
});

describe("handleAdminNotifyCallback", () => {
  it("stores token in sessionStorage and redirects to /admin/notify", async () => {
    const res = await handleAdminNotifyCallback();
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("sessionStorage.setItem('auth_token'");
    expect(html).toContain("/admin/notify");
    expect(html).not.toContain("document.cookie");
  });
});
