import { describe, it, expect } from "vitest";
import { renderAdminNotifyPage } from "../../src/lib/admin-notify-html";

describe("renderAdminNotifyPage", () => {
  const ORIGIN = "https://alc-api.test.example";

  it("returns an HTML string", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html.startsWith("<!DOCTYPE html>")).toBe(true);
  });

  it("contains page title", () => {
    expect(renderAdminNotifyPage(ORIGIN)).toContain("通知管理");
  });

  it("embeds the alc-api origin via JSON.stringify", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html).toContain(JSON.stringify(ORIGIN));
  });

  it("safely escapes an origin containing a quote", () => {
    const malicious = 'https://evil.test";alert(1);//';
    const html = renderAdminNotifyPage(malicious);
    expect(html).toContain(JSON.stringify(malicious));
    expect(html).not.toContain('"https://evil.test";');
  });

  it("contains 3 tabs (LINE WORKS / Recipients / Groups)", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html).toContain("LINE WORKS から追加");
    expect(html).toContain("受信者一覧");
    expect(html).toContain("グループ管理");
  });

  it("uses sessionStorage auth_token + redirects to /login if missing", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html).toContain("sessionStorage.getItem('auth_token')");
    expect(html).toContain("/admin/notify/callback");
  });

  it("calls the expected rust-alc-api endpoints", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html).toContain("/notify/lineworks/users");
    expect(html).toContain("/notify/recipients");
    expect(html).toContain("/notify/recipients/bulk");
    expect(html).toContain("/notify/groups");
  });

  it("shows directory.read scope guidance when LINE WORKS returns 403", () => {
    const html = renderAdminNotifyPage(ORIGIN);
    expect(html).toContain("directory.read");
  });
});
