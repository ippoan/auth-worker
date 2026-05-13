import { describe, it, expect } from "vitest";
import {
  renderDeviceConsentPage,
  renderDevicePage,
  renderDeviceResultPage,
} from "../../src/lib/mcp-device-html";

const ISSUER = "https://auth-staging.ippoan.org";

describe("renderDevicePage", () => {
  it("returns valid HTML with form posting to /device/verify", () => {
    const html = renderDevicePage({ issuer: ISSUER });
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain('action="/device/verify"');
    expect(html).toContain('name="user_code"');
    expect(html).toContain("auth-staging.ippoan.org"); // security banner
  });

  it("pre-fills the user_code input when prefilledCode given", () => {
    const html = renderDevicePage({ prefilledCode: "BCDF-GHJK", issuer: ISSUER });
    expect(html).toContain('value="BCDF-GHJK"');
  });

  it("shows the error banner when errorMessage given", () => {
    const html = renderDevicePage({
      errorMessage: "Code expired",
      issuer: ISSUER,
    });
    expect(html).toContain("banner--err");
    expect(html).toContain("Code expired");
  });

  it("does not show an error banner when errorMessage is absent", () => {
    const html = renderDevicePage({ issuer: ISSUER });
    // `banner--err` class is defined in <style>, but no error <div> should be rendered
    expect(html).not.toMatch(/<div class="banner banner--err"/);
  });

  it("escapes XSS payload in prefilledCode", () => {
    const html = renderDevicePage({
      prefilledCode: '"><script>alert(1)</script>',
      issuer: ISSUER,
    });
    expect(html).not.toContain("<script>alert(1)");
    expect(html).toContain("&lt;script&gt;");
  });

  it("falls back to the raw issuer string when not a valid URL", () => {
    const html = renderDevicePage({ issuer: "not-a-url" });
    expect(html).toContain("not-a-url");
  });
});

describe("renderDeviceConsentPage", () => {
  it("displays client_id, scope, and user_code inside meta block", () => {
    const html = renderDeviceConsentPage({
      user_code: "BCDF-GHJK",
      client_id: "github-mcp-server-rs",
      scope: "read:user offline_access",
      issuer: ISSUER,
    });
    expect(html).toContain("github-mcp-server-rs");
    expect(html).toContain("read:user offline_access");
    expect(html).toContain("BCDF-GHJK");
    expect(html).toContain('action="/device/proceed"');
    expect(html).toContain('name="action" value="approve"');
    expect(html).toContain('name="action" value="deny"');
  });

  it("shows (no scopes requested) when scope is empty string", () => {
    const html = renderDeviceConsentPage({
      user_code: "BCDF-GHJK",
      client_id: "foo",
      scope: "",
      issuer: ISSUER,
    });
    expect(html).toContain("(no scopes requested)");
  });

  it("escapes XSS payload in client_id, scope, and user_code", () => {
    const html = renderDeviceConsentPage({
      user_code: "<x>",
      client_id: '"><script>x</script>',
      scope: "<scope>",
      issuer: ISSUER,
    });
    expect(html).not.toContain("<script>x</script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("&lt;x&gt;");
    expect(html).toContain("&lt;scope&gt;");
  });
});

describe("renderDeviceResultPage", () => {
  it("uses banner--ok for success level", () => {
    const html = renderDeviceResultPage({
      title: "Approved",
      message: "Done",
      level: "success",
      issuer: ISSUER,
    });
    expect(html).toContain("banner--ok");
    expect(html).toContain("Done");
  });

  it("uses banner--err for error level", () => {
    const html = renderDeviceResultPage({
      title: "Bad",
      message: "Nope",
      level: "error",
      issuer: ISSUER,
    });
    expect(html).toContain("banner--err");
  });

  it("uses banner--info for info level", () => {
    const html = renderDeviceResultPage({
      title: "Denied",
      message: "...",
      level: "info",
      issuer: ISSUER,
    });
    expect(html).toContain("banner--info");
  });

  it("escapes XSS payload in title and message", () => {
    const html = renderDeviceResultPage({
      title: "<x>",
      message: '"><script>x</script>',
      level: "error",
      issuer: ISSUER,
    });
    expect(html).not.toContain("<script>x</script>");
    expect(html).toContain("&lt;x&gt;");
  });
});
