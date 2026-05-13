import { describe, it, expect } from "vitest";
import { handleMcpDevicePage } from "../../src/handlers/mcp-device-page";
import { createMockEnv } from "../helpers/mock-env";

describe("GET /device", () => {
  it("returns 200 + text/html + no-store", () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth.test.example" });
    const req = new Request("https://auth.test.example/device");
    const res = handleMcpDevicePage(req, env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("renders an empty form when no query is given", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/device");
    const html = await handleMcpDevicePage(req, env).text();
    expect(html).toContain('name="user_code"');
    expect(html).toContain('value=""');
  });

  it("pre-fills the form from ?user_code= (RFC 8628 verification_uri_complete)", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/device?user_code=BCDF-GHJK");
    const html = await handleMcpDevicePage(req, env).text();
    expect(html).toContain('value="BCDF-GHJK"');
  });

  it("also accepts ?code= alias", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/device?code=BCDF-GHJK");
    const html = await handleMcpDevicePage(req, env).text();
    expect(html).toContain('value="BCDF-GHJK"');
  });

  it("prefers user_code over code when both are given", async () => {
    const env = createMockEnv();
    const req = new Request(
      "https://auth.test.example/device?user_code=AAAA-AAAA&code=BBBB-BBBB",
    );
    const html = await handleMcpDevicePage(req, env).text();
    expect(html).toContain('value="AAAA-AAAA"');
    expect(html).not.toContain('value="BBBB-BBBB"');
  });

  it("falls back to https://auth.ippoan.org when AUTH_WORKER_ORIGIN is empty", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "" });
    const req = new Request("https://x.example/device");
    const html = await handleMcpDevicePage(req, env).text();
    expect(html).toContain("auth.ippoan.org");
  });
});
