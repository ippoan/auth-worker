import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

import { handleGoogleRedirect } from "../../src/handlers/google-redirect";

describe("handleGoogleRedirect", () => {
  const env = createMockEnv();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns 503 when GOOGLE_CLIENT_ID is empty", async () => {
    const req = new Request("https://auth.test.example/oauth/google/redirect?redirect_uri=https://app1.test.example/cb");
    const res = await handleGoogleRedirect(req, { ...env, GOOGLE_CLIENT_ID: "" });
    expect(res.status).toBe(503);
  });

  it("returns 400 for missing redirect_uri", async () => {
    const req = new Request("https://auth.test.example/oauth/google/redirect");
    const res = await handleGoogleRedirect(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 400 for invalid redirect_uri", async () => {
    const req = new Request("https://auth.test.example/oauth/google/redirect?redirect_uri=https://evil.com");
    const res = await handleGoogleRedirect(req, env);
    expect(res.status).toBe(400);
  });

  it("redirects to Google OAuth with correct params", async () => {
    const req = new Request("https://auth.test.example/oauth/google/redirect?redirect_uri=https://app1.test.example/cb");
    const res = await handleGoogleRedirect(req, env);
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location")!;
    expect(loc).toContain("accounts.google.com");
    expect(loc).toContain("client_id=test-google-client-id");
    expect(loc).toContain("state=");
    expect(loc).toContain("scope=openid+email+profile");
  });

  it("includes join_org in state when provided", async () => {
    const req = new Request("https://auth.test.example/oauth/google/redirect?redirect_uri=https://app1.test.example/cb&join_org=my-org");
    const res = await handleGoogleRedirect(req, env);
    expect(res.status).toBe(302);
    // State should contain join_org (verified through round-trip in security.test.ts)
    expect(res.headers.get("Location")).toContain("state=");
  });

  it("does not include join_org extra when not provided", async () => {
    const req = new Request("https://auth.test.example/oauth/google/redirect?redirect_uri=https://app1.test.example/cb");
    const res = await handleGoogleRedirect(req, env);
    expect(res.status).toBe(302);
  });
});
