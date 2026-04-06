import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

vi.mock("../../src/lib/security", () => ({
  verifyOAuthState: vi.fn(),
  isAllowedRedirectUri: vi.fn(),
}));

import { handleLineworksCallback } from "../../src/handlers/lineworks-callback";
import { verifyOAuthState, isAllowedRedirectUri } from "../../src/lib/security";

const mockVerify = vi.mocked(verifyOAuthState);
const mockIsAllowed = vi.mocked(isAllowedRedirectUri);

describe("handleLineworksCallback", () => {
  const env = createMockEnv();
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    vi.resetAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("returns 400 if error param present", async () => {
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?error=access_denied");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain("access_denied");
  });

  it("returns 400 if code missing", async () => {
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?state=abc");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Missing code or state parameter");
  });

  it("returns 400 if state missing", async () => {
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Missing code or state parameter");
  });

  it("returns 400 if state verification fails", async () => {
    mockVerify.mockResolvedValue(null);
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc&state=invalid");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid state parameter");
  });

  it("returns 400 if redirect_uri not allowed", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://evil.example/hack",
      provider: "lineworks",
      external_org_id: "org1",
    });
    mockIsAllowed.mockReturnValue(false);
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc&state=valid");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid redirect_uri in state");
  });

  it("returns 400 if redirect_uri is empty", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "",
      provider: "lineworks",
      external_org_id: "org1",
    });
    // isAllowedRedirectUri won't even be called since redirectUri is falsy
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc&state=valid");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid redirect_uri in state");
  });

  it("returns 400 if provider missing in state", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://app1.test.example/page",
      external_org_id: "org1",
    });
    mockIsAllowed.mockReturnValue(true);
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc&state=valid");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Missing provider info in state");
  });

  it("returns 400 if externalOrgId missing in state", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://app1.test.example/page",
      provider: "lineworks",
    });
    mockIsAllowed.mockReturnValue(true);
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc&state=valid");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Missing provider info in state");
  });

  it("passes through 302 from rust-alc-api", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://app1.test.example/page",
      provider: "lineworks",
      external_org_id: "org1",
    });
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(null, {
          status: 302,
          headers: { Location: "https://app1.test.example/page#token=backend-jwt" },
        }),
      ),
    );
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc&state=valid");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("https://app1.test.example/page#token=backend-jwt");
  });

  it("passes through 307 from rust-alc-api", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://app1.test.example/page",
      provider: "lineworks",
      external_org_id: "org1",
    });
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(null, {
          status: 307,
          headers: { Location: "https://app1.test.example/page#token=backend-jwt" },
        }),
      ),
    );
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc&state=valid");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("https://app1.test.example/page#token=backend-jwt");
  });

  it("302 redirects with #token=xxx on JSON response (normal flow)", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://app1.test.example/page",
      provider: "lineworks",
      external_org_id: "org1",
    });
    mockIsAllowed.mockReturnValue(true);
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9.sig";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ token: jwt, expires_at: "2099-01-01T00:00:00Z" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc&state=valid");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("https://app1.test.example/page");
    expect(location).toContain("#token=");
    expect(location).toContain(jwt);
    expect(location).toContain("org_id=test-org");
    expect(location).toContain("lw_callback=1");
  });

  it("302 redirects to /join/:slug/done on join flow", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://app1.test.example/page",
      provider: "lineworks",
      external_org_id: "org1",
      join_org: "my-company",
    });
    mockIsAllowed.mockReturnValue(true);
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9.sig";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ token: jwt, expires_at: "2099-01-01T00:00:00Z" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc&state=valid");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("/join/my-company/done");
    expect(location).toContain("#token=");
    expect(location).toContain(jwt);
    expect(location).not.toContain("lw_callback");
  });

  it("does not set Set-Cookie header", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://app1.test.example/page",
      provider: "lineworks",
      external_org_id: "org1",
    });
    mockIsAllowed.mockReturnValue(true);
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9.sig";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ token: jwt, expires_at: "2099-01-01T00:00:00Z" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc&state=valid");
    const res = await handleLineworksCallback(req, env);
    expect(res.headers.get("Set-Cookie")).toBeNull();
  });

  it("redirects to /login on backend failure", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://app1.test.example/page",
      provider: "lineworks",
      external_org_id: "org1",
    });
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("Internal Server Error", { status: 500 })),
    );
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc&state=valid");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("/login");
    expect(location).toContain("Internal+Server+Error");
  });

  it("calls rust-alc-api with correct callback URL params", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://app1.test.example/page",
      provider: "lineworks",
      external_org_id: "org1",
    });
    mockIsAllowed.mockReturnValue(true);
    const mockFetch = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({ token: "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9.sig", expires_at: "2099-01-01T00:00:00Z" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", mockFetch);
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=test-code&state=test-state");
    await handleLineworksCallback(req, env);

    const [callUrl, callOpts] = mockFetch.mock.calls[0];
    const parsedUrl = new URL(callUrl);
    expect(parsedUrl.origin).toBe("https://alc-api.test.example");
    expect(parsedUrl.pathname).toBe("/api/auth/lineworks/callback");
    expect(parsedUrl.searchParams.get("code")).toBe("test-code");
    expect(parsedUrl.searchParams.get("state")).toBe("test-state");
    expect(callOpts.redirect).toBe("manual");
  });

  it("handles 302 without Location header", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://app1.test.example/page",
      provider: "lineworks",
      external_org_id: "org1",
    });
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(null, { status: 302 }),
    ));
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc&state=valid");
    const res = await handleLineworksCallback(req, env);
    // Falls through to the JSON response path which calls resp.ok (302 is not ok)
    // then to the error path
    expect(res.status).toBe(302);
  });

  it("handles token without payload segment", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://app1.test.example/page",
      provider: "lineworks",
      external_org_id: "org1",
    });
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ token: "no-dots", expires_at: "2099-01-01" }), { status: 200, headers: { "Content-Type": "application/json" } }),
    ));
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc&state=valid");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(302);
  });

  it("handles invalid base64 in JWT payload", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://app1.test.example/page",
      provider: "lineworks",
      external_org_id: "org1",
    });
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ token: "h.!!!bad!!!.s", expires_at: "2099-01-01" }), { status: 200, headers: { "Content-Type": "application/json" } }),
    ));
    const req = new Request("https://auth.test.example/oauth/lineworks/callback?code=abc&state=valid");
    const res = await handleLineworksCallback(req, env);
    expect(res.status).toBe(302);
  });
});
