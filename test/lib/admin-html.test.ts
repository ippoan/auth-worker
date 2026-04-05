import { describe, it, expect } from "vitest";
import { renderAdminSsoPage } from "../../src/lib/admin-html";

describe("renderAdminSsoPage", () => {
  it("returns a string", () => {
    const result = renderAdminSsoPage();
    expect(typeof result).toBe("string");
  });

  it("contains DOCTYPE html", () => {
    const result = renderAdminSsoPage();
    expect(result).toContain("<!DOCTYPE html>");
  });

  it("handles empty frontendOrigins", () => {
    const result = renderAdminSsoPage([]);
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
  });

  it("includes frontendOrigins data", () => {
    const result = renderAdminSsoPage(["https://app1.example.com", "https://app2.example.com"]);
    expect(result).toContain("app1.example.com");
  });
});
