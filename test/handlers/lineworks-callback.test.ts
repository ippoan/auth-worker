import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";
import { createTestJwt } from "../helpers/test-jwt";
import { generateOAuthState } from "../../src/lib/security";

const mockLoginWithSsoProvider = vi.fn();
vi.mock("@connectrpc/connect", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@connectrpc/connect")>();
  return {
    ...actual,
    createClient: vi.fn(() => ({ loginWithSsoProvider: mockLoginWithSsoProvider })),
  };
});
vi.mock("../../src/lib/transport", () => ({
  createTransport: vi.fn(),
}));
vi.mock("@yhonda-ohishi-pub-dev/logi-proto", () => ({
  AuthService: {},
}));

import { handleLineworksCallback } from "../../src/handlers/lineworks-callback";

describe("handleLineworksCallback", () => {
  const env = createMockEnv();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  async function makeState(redirectUri: string, extra?: Record<string, string>) {
    return generateOAuthState(redirectUri, env.OAUTH_STATE_SECRET, extra);
  }

  it("returns 400 on error param", async () => {
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?error=denied");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("denied");
  });

  it("returns 400 for missing code", async () => {
    const state = await makeState("https://app1.test.example/cb", { provider: "lineworks", external_org_id: "ohishi" });
    const req = new Request(`https://auth.test.example/oauth/lineworks/callback?state=${state}`);
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 400 for missing state", async () => {
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 400 for invalid state", async () => {
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc&state=bad.sig");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 400 when state has disallowed redirect_uri", async () => {
    const state = await generateOAuthState("https://evil.com/cb", env.OAUTH_STATE_SECRET, { provider: "lineworks", external_org_id: "ohishi" });
    const req = new Request(`https://auth.test.example/oauth/lineworks/callback?code=abc&state=${state}`);
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 400 when state missing provider info", async () => {
    const state = await makeState("https://app1.test.example/cb");
    const req = new Request(`https://auth.test.example/oauth/lineworks/callback?code=abc&state=${state}`);
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Missing provider");
  });

  it("redirects with JWT on successful normal flow", async () => {
    const state = await makeState("https://app1.test.example/cb", { provider: "lineworks", external_org_id: "ohishi" });
    const jwt = createTestJwt({ org: "org-1" });
    mockLoginWithSsoProvider.mockResolvedValueOnce({ token: jwt, expiresAt: "9999" });

    const req = new Request(`https://auth.test.example/oauth/lineworks/callback?code=abc&state=${state}`);
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location")!;
    expect(loc).toContain("https://app1.test.example/cb");
    expect(loc).toContain("lw_callback=1");
    expect(loc).toContain("token=");
    expect(res.headers.get("Set-Cookie")).toContain("logi_auth_token=");
  });

  it("preserves existing lw_callback param", async () => {
    const state = await makeState("https://app1.test.example/cb?lw_callback=1", { provider: "lineworks", external_org_id: "ohishi" });
    const jwt = createTestJwt({ org: "org-1" });
    mockLoginWithSsoProvider.mockResolvedValueOnce({ token: jwt, expiresAt: "9999" });

    const req = new Request(`https://auth.test.example/oauth/lineworks/callback?code=abc&state=${state}`);
    const res = await handleLineworksCallback(req, env);
    const loc = res.headers.get("Location")!;
    expect(loc.match(/lw_callback/g)?.length).toBe(1);
  });

  it("redirects to /join/:slug/done on join flow", async () => {
    const state = await makeState("https://app1.test.example/cb", {
      provider: "lineworks",
      external_org_id: "ohishi",
      join_org: "my-org",
    });
    const jwt = createTestJwt({ org: "org-1" });
    mockLoginWithSsoProvider.mockResolvedValueOnce({ token: jwt, expiresAt: "9999" });

    const req = new Request(`https://auth.test.example/oauth/lineworks/callback?code=abc&state=${state}`);
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location")!;
    expect(loc).toContain("/join/my-org/done#");
    expect(res.headers.get("Set-Cookie")).toContain("logi_auth_token=");
  });

  it("handles JWT with no payload (no dots)", async () => {
    const state = await makeState("https://app1.test.example/cb", { provider: "lineworks", external_org_id: "ohishi" });
    mockLoginWithSsoProvider.mockResolvedValueOnce({ token: "nodots", expiresAt: "9999" });

    const req = new Request(`https://auth.test.example/oauth/lineworks/callback?code=abc&state=${state}`);
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(302);
  });

  it("handles JWT payload decode failure", async () => {
    const state = await makeState("https://app1.test.example/cb", { provider: "lineworks", external_org_id: "ohishi" });
    mockLoginWithSsoProvider.mockResolvedValueOnce({ token: "a.!!!.b", expiresAt: "9999" });

    const req = new Request(`https://auth.test.example/oauth/lineworks/callback?code=abc&state=${state}`);
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(302);
  });

  it("redirects to login on ConnectError", async () => {
    const state = await makeState("https://app1.test.example/cb", { provider: "lineworks", external_org_id: "ohishi" });
    const { ConnectError } = await import("@connectrpc/connect");
    mockLoginWithSsoProvider.mockRejectedValueOnce(new ConnectError("fail", 16));

    const req = new Request(`https://auth.test.example/oauth/lineworks/callback?code=abc&state=${state}`);
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("error=");
  });

  it("throws non-ConnectError", async () => {
    const state = await makeState("https://app1.test.example/cb", { provider: "lineworks", external_org_id: "ohishi" });
    mockLoginWithSsoProvider.mockRejectedValueOnce(new Error("boom"));

    const req = new Request(`https://auth.test.example/oauth/lineworks/callback?code=abc&state=${state}`);
    await expect(handleLineworksCallback(req, env)).rejects.toThrow("boom");
  });

  it("uses hostname as-is for cookie in join flow with 2-part domain", async () => {
    const state = await makeState("https://app1.test.example/cb", {
      provider: "lineworks",
      external_org_id: "ohishi",
      join_org: "my-org",
    });
    const jwt = createTestJwt({ org: "o1" });
    mockLoginWithSsoProvider.mockResolvedValueOnce({ token: jwt, expiresAt: "9999" });

    // Use 2-part origin to hit else branch of parentDomain ternary
    const req = new Request(`https://example.com/oauth/lineworks/callback?code=abc&state=${state}`);
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Set-Cookie")).toContain("Domain=.example.com");
  });

  it("uses hostname as-is for normal flow cookie with 2-part redirect domain", async () => {
    const envWith2Part = {
      ...env,
      ALLOWED_REDIRECT_ORIGINS: "https://example.com",
    };
    const state = await generateOAuthState("https://example.com/cb", envWith2Part.OAUTH_STATE_SECRET, {
      provider: "lineworks",
      external_org_id: "ohishi",
    });
    const jwt = createTestJwt({ org: "o1" });
    mockLoginWithSsoProvider.mockResolvedValueOnce({ token: jwt, expiresAt: "9999" });

    const req = new Request(`https://auth.test.example/oauth/lineworks/callback?code=abc&state=${state}`);
    const res = await handleLineworksCallback(req, envWith2Part);
    expect(res.headers.get("Set-Cookie")).toContain("Domain=.example.com");
  });

  it("uses parent domain for cookie on multi-part hostname", async () => {
    const state = await makeState("https://app1.test.example/cb", { provider: "lineworks", external_org_id: "ohishi" });
    const jwt = createTestJwt({ org: "o1" });
    mockLoginWithSsoProvider.mockResolvedValueOnce({ token: jwt, expiresAt: "9999" });

    const req = new Request(`https://auth.test.example/oauth/lineworks/callback?code=abc&state=${state}`);
    const res = await handleLineworksCallback(req, env);
    expect(res.headers.get("Set-Cookie")).toContain("Domain=.test.example");
  });
});
