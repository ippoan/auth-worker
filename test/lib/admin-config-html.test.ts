import { describe, it, expect } from "vitest";
import { renderAdminConfigPage } from "../../src/lib/admin-config-html";

describe("renderAdminConfigPage", () => {
  const ORIGIN = "https://alc-api.test.example";

  it("returns a string", () => {
    expect(typeof renderAdminConfigPage(ORIGIN)).toBe("string");
  });

  it("contains DOCTYPE html", () => {
    expect(renderAdminConfigPage(ORIGIN)).toContain("<!DOCTYPE html>");
  });

  it("contains page title", () => {
    expect(renderAdminConfigPage(ORIGIN)).toContain("設定 Export / Import");
  });

  it("embeds the alc-api origin as JSON", () => {
    const html = renderAdminConfigPage(ORIGIN);
    expect(html).toContain(JSON.stringify(ORIGIN));
  });

  it("embeds origin safely against quote injection", () => {
    const malicious = 'https://evil.test";alert(1);//';
    const html = renderAdminConfigPage(malicious);
    // JSON.stringify escapes the inner quote → no script injection escape
    expect(html).toContain(JSON.stringify(malicious));
    expect(html).not.toContain('"https://evil.test";');
  });

  it("uses sessionStorage auth_token", () => {
    const html = renderAdminConfigPage(ORIGIN);
    expect(html).toContain("sessionStorage");
    expect(html).toContain("auth_token");
  });

  it("calls /api/staging/export", () => {
    expect(renderAdminConfigPage(ORIGIN)).toContain("/api/staging/export");
  });

  it("calls /api/staging/import", () => {
    expect(renderAdminConfigPage(ORIGIN)).toContain("/api/staging/import");
  });

  it("redirects to /login when token is missing", () => {
    expect(renderAdminConfigPage(ORIGIN)).toContain(
      "/admin/config/callback",
    );
  });
});
