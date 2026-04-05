import { describe, it, expect } from "vitest";
import { renderTopPage } from "../../src/lib/top-html";

describe("renderTopPage", () => {
  it("returns a string", () => {
    const result = renderTopPage([], "https://auth.example.com");
    expect(typeof result).toBe("string");
  });

  it("contains DOCTYPE html", () => {
    const result = renderTopPage([], "https://auth.example.com");
    expect(result).toContain("<!DOCTYPE html>");
  });

  it("handles empty apps array", () => {
    const result = renderTopPage([], "https://auth.example.com");
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
  });

  it("includes apps data in output", () => {
    const apps = [
      { name: "Test App", url: "https://app.example.com", icon: "T", description: "A test app" },
    ];
    const result = renderTopPage(apps, "https://auth.example.com");
    expect(result).toContain("Test App");
  });

  it("includes authWorkerOrigin", () => {
    const result = renderTopPage([], "https://auth.my-domain.com");
    expect(result).toContain("auth.my-domain.com");
  });
});
