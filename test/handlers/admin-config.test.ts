import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/lib/admin-config-html", () => ({
  renderAdminConfigPage: vi.fn(
    (origin: string) => `<html>mock admin config page (${origin})</html>`,
  ),
}));

import {
  handleAdminConfigPage,
  handleAdminConfigCallback,
} from "../../src/handlers/admin-config";
import { createMockEnv } from "../helpers/mock-env";
import { renderAdminConfigPage } from "../../src/lib/admin-config-html";

describe("handleAdminConfigPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns HTML built from the env's ALC_API_ORIGIN", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/admin/config");
    const res = await handleAdminConfigPage(req, env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(renderAdminConfigPage).toHaveBeenCalledWith(env.ALC_API_ORIGIN);
    expect(await res.text()).toContain("mock admin config page");
  });
});

describe("handleAdminConfigCallback", () => {
  it("returns HTML that stores the token in sessionStorage", async () => {
    const res = await handleAdminConfigCallback();
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    const html = await res.text();
    expect(html).toContain("sessionStorage.setItem('auth_token'");
    expect(html).toContain("/admin/config");
    expect(html).not.toContain("document.cookie");
  });
});
