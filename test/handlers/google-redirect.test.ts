import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";
import { handleGoogleRedirect } from "../../src/handlers/google-redirect";

describe("handleGoogleRedirect", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 503 when GOOGLE_CLIENT_ID is empty", async () => {
    const env = createMockEnv({ GOOGLE_CLIENT_ID: "" });
    const req = new Request(
      "https://auth.test.example/oauth/google/redirect?redirect_uri=https://app1.test.example/callback",
    );
    const res = await handleGoogleRedirect(req, env);
    expect(res.status).toBe(503);
    expect(await res.text()).toBe("Google OAuth not configured");
  });

  it("returns 400 when redirect_uri is missing", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/oauth/google/redirect");
    const res = await handleGoogleRedirect(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid or missing redirect_uri");
  });

  it("returns 400 when redirect_uri origin is not allowed", async () => {
    const env = createMockEnv();
    const req = new Request(
      "https://auth.test.example/oauth/google/redirect?redirect_uri=https://evil.example.com/callback",
    );
    const res = await handleGoogleRedirect(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid or missing redirect_uri");
  });

  it("redirects 302 to Google OAuth URL on success", async () => {
    const env = createMockEnv();
    const req = new Request(
      "https://auth.test.example/oauth/google/redirect?redirect_uri=https://app1.test.example/callback",
    );
    const res = await handleGoogleRedirect(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("accounts.google.com/o/oauth2/v2/auth");
    expect(location).toContain("client_id=test-google-client-id");
    expect(location).toContain("response_type=code");
    expect(location).toContain("scope=openid+email+profile");
    expect(location).toContain("state=");
  });

  it("includes join_org in state when provided", async () => {
    const env = createMockEnv();
    const req = new Request(
      "https://auth.test.example/oauth/google/redirect?redirect_uri=https://app1.test.example/callback&join_org=test-slug",
    );
    const res = await handleGoogleRedirect(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("accounts.google.com");
    // State param should be present (contains join_org internally)
    expect(location).toContain("state=");
  });

  it("sets correct redirect_uri in Google OAuth URL", async () => {
    const env = createMockEnv({
      AUTH_WORKER_ORIGIN: "https://auth.my-domain.com",
    });
    const req = new Request(
      "https://auth.my-domain.com/oauth/google/redirect?redirect_uri=https://app1.test.example/callback",
    );
    const res = await handleGoogleRedirect(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain(
      encodeURIComponent("https://auth.my-domain.com/oauth/google/callback"),
    );
  });
});
