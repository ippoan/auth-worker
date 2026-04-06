import { describe, it, expect } from "vitest";
import {
  renderJoinPage,
  renderJoinDonePage,
  renderJoinNotFoundPage,
} from "../../src/lib/join-html";

describe("renderJoinPage", () => {
  const defaultParams = {
    orgName: "Test Organization",
    orgSlug: "test-org",
    googleEnabled: true,
    authWorkerOrigin: "https://auth.example.com",
  };

  it("returns a string", () => {
    const result = renderJoinPage(defaultParams);
    expect(typeof result).toBe("string");
  });

  it("contains DOCTYPE html", () => {
    const result = renderJoinPage(defaultParams);
    expect(result).toContain("<!DOCTYPE html>");
  });

  it("contains organization name", () => {
    const result = renderJoinPage(defaultParams);
    expect(result).toContain("Test Organization");
  });

  it("contains organization slug in callback URI", () => {
    const result = renderJoinPage(defaultParams);
    expect(result).toContain("/join/test-org/done");
  });

  it("includes Google login button when googleEnabled is true", () => {
    const result = renderJoinPage(defaultParams);
    expect(result).toContain("Google");
    expect(result).toContain("oauth/google/redirect");
  });

  it("excludes Google login button when googleEnabled is false", () => {
    const result = renderJoinPage({ ...defaultParams, googleEnabled: false });
    expect(result).not.toContain("oauth/google/redirect");
  });

  it("contains LINE WORKS login section", () => {
    const result = renderJoinPage(defaultParams);
    expect(result).toContain("LINE WORKS");
    expect(result).toContain("lwAddress");
  });

  it("includes join_org parameter in LINE WORKS redirect", () => {
    const result = renderJoinPage(defaultParams);
    expect(result).toContain("join_org=");
  });

  it("escapes HTML in org name", () => {
    const result = renderJoinPage({
      ...defaultParams,
      orgName: "<script>alert(1)</script>",
    });
    expect(result).not.toContain("<script>alert(1)</script>");
    expect(result).toContain("&lt;script&gt;");
  });
});

describe("renderJoinDonePage", () => {
  it("returns a string", () => {
    const result = renderJoinDonePage("test-org");
    expect(typeof result).toBe("string");
  });

  it("contains DOCTYPE html", () => {
    const result = renderJoinDonePage("test-org");
    expect(result).toContain("<!DOCTYPE html>");
  });

  it("includes org slug in the API call body", () => {
    const result = renderJoinDonePage("my-slug");
    expect(result).toContain("my-slug");
  });

  it("contains access-requests create endpoint", () => {
    const result = renderJoinDonePage("test-org");
    expect(result).toContain("/api/access-requests/create");
  });

  it("handles token extraction from fragment", () => {
    const result = renderJoinDonePage("test-org");
    expect(result).toContain("token=");
  });
});

describe("renderJoinNotFoundPage", () => {
  it("returns a string", () => {
    const result = renderJoinNotFoundPage();
    expect(typeof result).toBe("string");
  });

  it("contains DOCTYPE html", () => {
    const result = renderJoinNotFoundPage();
    expect(result).toContain("<!DOCTYPE html>");
  });

  it("contains not-found message", () => {
    const result = renderJoinNotFoundPage();
    expect(result).toContain("組織が見つかりません");
  });
});
