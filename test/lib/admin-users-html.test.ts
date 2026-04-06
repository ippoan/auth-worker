import { describe, it, expect } from "vitest";
import { renderAdminUsersPage } from "../../src/lib/admin-users-html";

describe("renderAdminUsersPage", () => {
  it("returns a string", () => {
    const result = renderAdminUsersPage();
    expect(typeof result).toBe("string");
  });

  it("contains DOCTYPE html", () => {
    const result = renderAdminUsersPage();
    expect(result).toContain("<!DOCTYPE html>");
  });

  it("contains page title", () => {
    const result = renderAdminUsersPage();
    expect(result).toContain("ユーザー管理");
  });

  it("contains user list section", () => {
    const result = renderAdminUsersPage();
    expect(result).toContain("users-list");
  });

  it("contains invite form", () => {
    const result = renderAdminUsersPage();
    expect(result).toContain("invite-form");
  });

  it("contains sessionStorage token handling", () => {
    const result = renderAdminUsersPage();
    expect(result).toContain("sessionStorage");
    expect(result).toContain("auth_token");
  });
});
