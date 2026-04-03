import { describe, it, expect } from "vitest";
import { renderLoginPage } from "../../src/lib/html";

describe("renderLoginPage", () => {
  it("returns a string", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      googleEnabled: true,
      googleRedirectUrl: "https://api.example.com/auth/google/redirect",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
    });
    expect(typeof result).toBe("string");
  });

  it("contains DOCTYPE html", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      googleEnabled: true,
      googleRedirectUrl: "https://api.example.com/auth/google/redirect",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
    });
    expect(result).toContain("<!DOCTYPE html>");
  });

  it("contains Google login button when googleEnabled=true", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      googleEnabled: true,
      googleRedirectUrl: "https://api.example.com/auth/google/redirect",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
    });
    expect(result).toContain("google");
  });

  it("does not contain Google redirect URL when googleEnabled=false", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      googleEnabled: false,
      googleRedirectUrl: "",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
    });
    // The <a> tag with google-btn class should not be present, but CSS may still reference it
    expect(result).not.toContain('href="https://api.example.com/auth/google');
  });

  it("includes error message when provided", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      error: "invalid_token",
      googleEnabled: true,
      googleRedirectUrl: "https://api.example.com/auth/google/redirect",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
    });
    expect(result).toContain("invalid_token");
  });

  it("escapes HTML special characters in error", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      error: '<script>alert("xss")</script>',
      googleEnabled: true,
      googleRedirectUrl: "https://api.example.com/auth/google/redirect",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
    });
    expect(result).toContain("&lt;script&gt;");
    expect(result).not.toContain('<script>alert("xss")</script>');
  });

  it("escapes & < > characters", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      error: "a&b<c>d",
      googleEnabled: true,
      googleRedirectUrl: "https://api.example.com/auth/google/redirect",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
    });
    expect(result).toContain("a&amp;b&lt;c&gt;d");
  });

  it("includes orgId in hidden field when provided", () => {
    const result = renderLoginPage({
      redirectUri: "https://app.example.com/callback",
      orgId: "test-org-id",
      googleEnabled: true,
      googleRedirectUrl: "https://api.example.com/auth/google/redirect",
      lineworksRedirectUrl: "https://api.example.com/auth/lineworks/redirect",
    });
    expect(result).toContain("test-org-id");
  });
});
