import { describe, it, expect, beforeEach, vi } from "vitest";
import { createMockEnv } from "../helpers/mock-env";
import { handleGhapiRedirect } from "../../src/handlers/ghapi-redirect";

describe("handleGhapiRedirect", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 503 when GOOGLE_HEALTH_CLIENT_ID is unset", async () => {
    const env = createMockEnv();
    const req = new Request(
      "https://auth.test.example/oauth/ghapi/redirect?redirect_uri=https://app1.test.example/api/ghapi/connected",
    );
    const res = await handleGhapiRedirect(req, env);
    expect(res.status).toBe(503);
    expect(await res.text()).toBe("Google Health OAuth not configured");
  });

  it("returns 400 when redirect_uri is missing", async () => {
    const env = createMockEnv({ GOOGLE_HEALTH_CLIENT_ID: "test-ghapi-client-id" });
    const req = new Request("https://auth.test.example/oauth/ghapi/redirect");
    const res = await handleGhapiRedirect(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid or missing redirect_uri");
  });

  it("returns 400 when redirect_uri origin is not allowlisted", async () => {
    const env = createMockEnv({ GOOGLE_HEALTH_CLIENT_ID: "test-ghapi-client-id" });
    const req = new Request(
      "https://auth.test.example/oauth/ghapi/redirect?redirect_uri=https://evil.example.com/hack",
    );
    const res = await handleGhapiRedirect(req, env);
    expect(res.status).toBe(400);
  });

  it("redirects 302 to Google OAuth with ghapi-specific params", async () => {
    const env = createMockEnv({ GOOGLE_HEALTH_CLIENT_ID: "test-ghapi-client-id" });
    const req = new Request(
      "https://auth.test.example/oauth/ghapi/redirect?redirect_uri=https://app1.test.example/api/ghapi/connected",
    );
    const res = await handleGhapiRedirect(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("accounts.google.com/o/oauth2/v2/auth");
    expect(location).toContain("client_id=test-ghapi-client-id");
    expect(location).toContain(
      encodeURIComponent("https://auth.test.example/oauth/ghapi/callback"),
    );
    expect(location).toContain("access_type=offline");
    expect(location).toContain("prompt=consent");
    expect(location).toContain("fitness.activity.read");
    expect(location).toContain("state=");
  });

  it("uses GOOGLE_HEALTH_SCOPES override when provided", async () => {
    const env = createMockEnv({
      GOOGLE_HEALTH_CLIENT_ID: "test-ghapi-client-id",
      GOOGLE_HEALTH_SCOPES: "openid https://www.googleapis.com/auth/healthdata.read",
    });
    const req = new Request(
      "https://auth.test.example/oauth/ghapi/redirect?redirect_uri=https://app1.test.example/api/ghapi/connected",
    );
    const res = await handleGhapiRedirect(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("healthdata.read");
    expect(location).not.toContain("fitness.activity.read");
  });

  it("accepts SecretsStoreSecret binding for GOOGLE_HEALTH_CLIENT_ID", async () => {
    const binding = {
      get: async () => "secrets-store-ghapi-client-id",
    } as unknown as SecretsStoreSecret;
    const env = createMockEnv({ GOOGLE_HEALTH_CLIENT_ID: binding });
    const req = new Request(
      "https://auth.test.example/oauth/ghapi/redirect?redirect_uri=https://app1.test.example/api/ghapi/connected",
    );
    const res = await handleGhapiRedirect(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("client_id=secrets-store-ghapi-client-id");
    expect(location).not.toContain("%5Bobject");
  });
});
