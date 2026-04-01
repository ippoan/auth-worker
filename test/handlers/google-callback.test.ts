import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";
import { createTestJwt } from "../helpers/test-jwt";
import { generateOAuthState } from "../../src/lib/security";

const mockLoginWithGoogle = vi.fn();
vi.mock("@connectrpc/connect", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@connectrpc/connect")>();
  return {
    ...actual,
    createClient: vi.fn(() => ({ loginWithGoogle: mockLoginWithGoogle })),
  };
});
vi.mock("../../src/lib/transport", () => ({
  createTransport: vi.fn(),
}));
vi.mock("@yhonda-ohishi-pub-dev/logi-proto", () => ({
  AuthService: {},
}));

import { handleGoogleCallback } from "../../src/handlers/google-callback";

describe("handleGoogleCallback", () => {
  const env = createMockEnv();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  async function makeState(redirectUri: string, extra?: Record<string, string>) {
    return generateOAuthState(redirectUri, env.OAUTH_STATE_SECRET, extra);
  }

  it("returns 400 when Google returns error param", async () => {
    const req = new Request("https://auth.test.example/oauth/google/callback?error=access_denied");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("access_denied");
  });

  it("returns 400 for missing code", async () => {
    const state = await makeState("https://app1.test.example/cb");
    const req = new Request(`https://auth.test.example/oauth/google/callback?state=${state}`);
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 400 for missing state", async () => {
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 400 for invalid state", async () => {
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=invalid.sig");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Invalid state");
  });

  it("returns 400 when state contains disallowed redirect_uri", async () => {
    const state = await generateOAuthState("https://evil.com/cb", env.OAUTH_STATE_SECRET);
    const req = new Request(`https://auth.test.example/oauth/google/callback?code=abc&state=${state}`);
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Invalid redirect_uri");
  });

  it("redirects to login when Google token exchange fails", async () => {
    const state = await makeState("https://app1.test.example/cb");
    const req = new Request(`https://auth.test.example/oauth/google/callback?code=abc&state=${state}`);

    const originalFetch = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response("bad", { status: 400 }),
    ));

    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("error=");

    vi.stubGlobal("fetch", originalFetch);
  });

  it("redirects to login when no id_token in Google response", async () => {
    const state = await makeState("https://app1.test.example/cb");
    const req = new Request(`https://auth.test.example/oauth/google/callback?code=abc&state=${state}`);

    const originalFetch = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ access_token: "at" }), { status: 200 }),
    ));

    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("error=");

    vi.stubGlobal("fetch", originalFetch);
  });

  it("redirects with JWT fragment on successful login (normal flow)", async () => {
    const state = await makeState("https://app1.test.example/cb");
    const jwt = createTestJwt({ org: "org-1" });
    const req = new Request(`https://auth.test.example/oauth/google/callback?code=abc&state=${state}`);

    const originalFetch = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ id_token: "google-id-token" }), { status: 200 }),
    ));
    mockLoginWithGoogle.mockResolvedValueOnce({ token: jwt, expiresAt: "9999" });

    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location")!;
    expect(loc).toContain("https://app1.test.example/cb");
    expect(loc).toContain("lw_callback=1");
    expect(loc).toContain("token=");
    expect(loc).toContain("org_id=org-1");
    expect(res.headers.get("Set-Cookie")).toContain("logi_auth_token=");

    vi.stubGlobal("fetch", originalFetch);
  });

  it("preserves existing lw_callback param", async () => {
    const state = await makeState("https://app1.test.example/cb?lw_callback=1");
    const jwt = createTestJwt({ org: "org-1" });
    const req = new Request(`https://auth.test.example/oauth/google/callback?code=abc&state=${state}`);

    const originalFetch = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ id_token: "id" }), { status: 200 }),
    ));
    mockLoginWithGoogle.mockResolvedValueOnce({ token: jwt, expiresAt: "9999" });

    const res = await handleGoogleCallback(req, env);
    const loc = res.headers.get("Location")!;
    // Should not duplicate lw_callback
    expect(loc.match(/lw_callback/g)?.length).toBe(1);

    vi.stubGlobal("fetch", originalFetch);
  });

  it("redirects to /join/:slug/done on join flow", async () => {
    const state = await makeState("https://app1.test.example/cb", { join_org: "my-org" });
    const jwt = createTestJwt({ org: "org-1" });
    const req = new Request(`https://auth.test.example/oauth/google/callback?code=abc&state=${state}`);

    const originalFetch = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ id_token: "id" }), { status: 200 }),
    ));
    mockLoginWithGoogle.mockResolvedValueOnce({ token: jwt, expiresAt: "9999" });

    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location")!;
    expect(loc).toContain("/join/my-org/done#");
    expect(res.headers.get("Set-Cookie")).toContain("logi_auth_token=");

    vi.stubGlobal("fetch", originalFetch);
  });

  it("handles JWT payload decode failure gracefully", async () => {
    const state = await makeState("https://app1.test.example/cb");
    const req = new Request(`https://auth.test.example/oauth/google/callback?code=abc&state=${state}`);

    const originalFetch = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ id_token: "id" }), { status: 200 }),
    ));
    mockLoginWithGoogle.mockResolvedValueOnce({ token: "bad.!!!.jwt", expiresAt: "9999" });

    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);

    vi.stubGlobal("fetch", originalFetch);
  });

  it("handles JWT with no dots (no payload)", async () => {
    const state = await makeState("https://app1.test.example/cb");
    const req = new Request(`https://auth.test.example/oauth/google/callback?code=abc&state=${state}`);

    const originalFetch = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ id_token: "id" }), { status: 200 }),
    ));
    mockLoginWithGoogle.mockResolvedValueOnce({ token: "nodots", expiresAt: "9999" });

    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);

    vi.stubGlobal("fetch", originalFetch);
  });

  it("redirects to login on ConnectError", async () => {
    const state = await makeState("https://app1.test.example/cb");
    const req = new Request(`https://auth.test.example/oauth/google/callback?code=abc&state=${state}`);

    const originalFetch = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ id_token: "id" }), { status: 200 }),
    ));
    const { ConnectError } = await import("@connectrpc/connect");
    mockLoginWithGoogle.mockRejectedValueOnce(new ConnectError("denied", 7));

    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("error=");

    vi.stubGlobal("fetch", originalFetch);
  });

  it("throws non-ConnectError", async () => {
    const state = await makeState("https://app1.test.example/cb");
    const req = new Request(`https://auth.test.example/oauth/google/callback?code=abc&state=${state}`);

    const originalFetch = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ id_token: "id" }), { status: 200 }),
    ));
    mockLoginWithGoogle.mockRejectedValueOnce(new Error("boom"));

    await expect(handleGoogleCallback(req, env)).rejects.toThrow("boom");

    vi.stubGlobal("fetch", originalFetch);
  });

  it("uses hostname as-is for cookie when hostname has 2 parts", async () => {
    // For 2-part hostnames like "example.com", getParentDomain returns "example.com"
    const envWithTwoPart = {
      ...env,
      ALLOWED_REDIRECT_ORIGINS: "https://example.com",
    };
    const state = await generateOAuthState("https://example.com/cb", envWithTwoPart.OAUTH_STATE_SECRET);
    const jwt = createTestJwt({ org: "o1" });
    const req = new Request(`https://auth.test.example/oauth/google/callback?code=abc&state=${state}`);

    const originalFetch = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ id_token: "id" }), { status: 200 }),
    ));
    mockLoginWithGoogle.mockResolvedValueOnce({ token: jwt, expiresAt: "9999" });

    const res = await handleGoogleCallback(req, envWithTwoPart);
    expect(res.headers.get("Set-Cookie")).toContain("Domain=.example.com");

    vi.stubGlobal("fetch", originalFetch);
  });

  it("uses hostname as-is for cookie in join flow with 2-part domain", async () => {
    // Test the else branch of getParentDomain in join flow
    const state = await makeState("https://app1.test.example/cb", { join_org: "my-org" });
    const jwt = createTestJwt({ org: "o1" });
    // The join flow uses the origin of the callback URL (auth.test.example = 3 parts)
    // To hit the else branch, we need a 2-part origin. But origin is from request URL.
    // getParentDomain is called on joinDoneUrl.hostname which is always the request origin.
    // auth.test.example is 3 parts. We need the request origin to be 2 parts.
    const req = new Request(`https://example.com/oauth/google/callback?code=abc&state=${state}`);

    const originalFetch = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ id_token: "id" }), { status: 200 }),
    ));
    mockLoginWithGoogle.mockResolvedValueOnce({ token: jwt, expiresAt: "9999" });

    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    // example.com is 2 parts, so Domain=.example.com (hostname as-is)
    expect(res.headers.get("Set-Cookie")).toContain("Domain=.example.com");

    vi.stubGlobal("fetch", originalFetch);
  });
});
