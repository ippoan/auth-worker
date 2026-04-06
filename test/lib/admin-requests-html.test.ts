import { describe, it, expect } from "vitest";
import { renderAdminRequestsPage } from "../../src/lib/admin-requests-html";

describe("renderAdminRequestsPage", () => {
  it("returns a string", () => {
    const result = renderAdminRequestsPage();
    expect(typeof result).toBe("string");
  });

  it("contains DOCTYPE html", () => {
    const result = renderAdminRequestsPage();
    expect(result).toContain("<!DOCTYPE html>");
  });

  it("contains page title", () => {
    const result = renderAdminRequestsPage();
    expect(result).toContain("参加リクエスト管理");
  });

  it("contains tab buttons", () => {
    const result = renderAdminRequestsPage();
    expect(result).toContain("保留中");
    expect(result).toContain("承認済み");
    expect(result).toContain("却下済み");
  });

  it("contains sessionStorage token handling", () => {
    const result = renderAdminRequestsPage();
    expect(result).toContain("sessionStorage");
    expect(result).toContain("auth_token");
  });
});
