import { describe, it, expect } from "vitest";
import { renderTopPage, renderStagingFooter } from "../../src/lib/top-html";

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

  describe("staging footer", () => {
    it("omits the staging footer when workerEnv is prod", () => {
      const result = renderTopPage([], "https://auth.example.com", {
        workerEnv: "prod",
        alcApiOrigin: "https://alc.example.com",
        tenantId: "tid-1",
      });
      expect(result).not.toContain("staging-footer");
    });

    it("omits the footer when alcApiOrigin is missing", () => {
      const result = renderTopPage([], "https://auth.example.com", {
        workerEnv: "staging",
      });
      expect(result).not.toContain("staging-footer");
    });

    it("renders the footer when workerEnv is staging and alcApiOrigin is set", () => {
      const result = renderTopPage([], "https://auth.example.com", {
        workerEnv: "staging",
        alcApiOrigin: "https://alc-staging.example.com",
        tenantId: "tid-1",
      });
      expect(result).toContain("staging-footer");
      expect(result).toContain("STAGING");
    });

    it("defaults to no footer when stagingOpts is omitted", () => {
      const result = renderTopPage([], "https://auth.example.com");
      expect(result).not.toContain("staging-footer");
    });
  });
});

describe("renderStagingFooter", () => {
  it("embeds the alc api origin via JSON.stringify", () => {
    const html = renderStagingFooter("https://alc.example.com", "tid-1");
    expect(html).toContain(JSON.stringify("https://alc.example.com"));
  });

  it("embeds the tenant_id via JSON.stringify", () => {
    const html = renderStagingFooter("https://alc.example.com", "tid-xyz");
    expect(html).toContain(JSON.stringify("tid-xyz"));
  });

  it("uses /api/staging/export with URL-encoded tenant_id", () => {
    const html = renderStagingFooter("https://alc.example.com", "tid-xyz");
    expect(html).toContain("/api/staging/export");
    expect(html).toContain("encodeURIComponent(TENANT_ID)");
  });

  it("uses POST /api/staging/import", () => {
    const html = renderStagingFooter("https://alc.example.com", "tid-xyz");
    expect(html).toContain("/api/staging/import");
    expect(html).toContain("method: 'POST'");
  });

  it("contains Export and Import buttons", () => {
    const html = renderStagingFooter("https://alc.example.com", "tid-xyz");
    expect(html).toContain("staging-btn-export");
    expect(html).toContain("staging-btn-import");
  });

  it("safely escapes a tenant_id that contains a quote", () => {
    const html = renderStagingFooter("https://alc.example.com", 'tid\";alert(1);//');
    expect(html).toContain(JSON.stringify('tid\";alert(1);//'));
    expect(html).not.toContain('"tid";alert(1);//"');
  });
});
