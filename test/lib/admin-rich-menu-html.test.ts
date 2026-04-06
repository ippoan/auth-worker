import { describe, it, expect } from "vitest";
import { renderAdminRichMenuPage } from "../../src/lib/admin-rich-menu-html";

describe("renderAdminRichMenuPage", () => {
  it("returns a string", () => {
    const result = renderAdminRichMenuPage();
    expect(typeof result).toBe("string");
  });

  it("contains DOCTYPE html", () => {
    const result = renderAdminRichMenuPage();
    expect(result).toContain("<!DOCTYPE html>");
  });

  it("has non-zero length", () => {
    const result = renderAdminRichMenuPage();
    expect(result.length).toBeGreaterThan(0);
  });
});
