import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

vi.mock("../../src/lib/security", () => ({
  verifyOAuthState: vi.fn(),
  isAllowedRedirectUri: vi.fn(),
}));

import { handleGoogleCallback } from "../../src/handlers/google-callback";
import { verifyOAuthState, isAllowedRedirectUri } from "../../src/lib/security";

const mockVerify = vi.mocked(verifyOAuthState);
const mockIsAllowed = vi.mocked(isAllowedRedirectUri);

describe("handleGoogleCallback", () => {
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
    const req = new Request("https://auth.test.example/oauth/google/callback?error=access_denied");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain("access_denied");
  });

  it("returns 400 if code missing", async () => {
    const req = new Request("https://auth.test.example/oauth/google/callback?state=abc");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Missing code or state parameter");
  });

  it("returns 400 if state missing", async () => {
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Missing code or state parameter");
  });

  it("returns 400 if state verification fails", async () => {
    mockVerify.mockResolvedValue(null);
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=invalid");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid state parameter");
  });

  it("returns 400 if redirect_uri in state is not allowed", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: "https://evil.example/hack" });
    mockIsAllowed.mockReturnValue(false);
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid redirect_uri in state");
  });

  it("redirects to /login on Google token exchange failure", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("token error", { status: 400 })),
    );
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("/login");
    expect(location).toContain("Google+authentication+failed");
  });

  it("redirects to /login when no id_token in Google response", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "at" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("/login");
    expect(location).toContain("No+ID+token");
  });

  it("redirects to /login on rust-alc-api auth failure", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ id_token: "mock-id-token" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        )
        .mockResolvedValueOnce(new Response("User not found", { status: 401 })),
    );
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("/login");
    expect(location).toContain("User+not+found");
  });

  it("302 redirects with cookie only (no token in URL) when target shares the auth cookie domain", async () => {
    // redirect 先 (app1.test.example) は auth host (auth.test.example) と同じ親ドメイン
    // (.test.example) 配下 → 共有 cookie が届くので token を URL に載せず cookie だけで渡す。
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    // JWT: {"alg":"HS256"}.{"tenant_id":"test-org"}.sig
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9.sig";
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ id_token: "mock-id-token" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ access_token: jwt, expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        ),
    );
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toBe("https://app1.test.example/page"); // クリーン (fragment/lw_callback なし)
    expect(location).not.toContain("#token=");
    expect(location).not.toContain("lw_callback");
    expect(res.headers.get("Set-Cookie")).toContain(`logi_auth_token=${jwt}`);
  });

  it("302 redirects with #token= fragment when cookie domain is a public suffix (workers.dev)", async () => {
    // auth host が *.workers.dev (public suffix → Domain cookie 不可) の場合は従来どおり
    // fragment で配布する。
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9.sig";
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ id_token: "mock-id-token" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ access_token: jwt, expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        ),
    );
    const req = new Request(
      "https://auth-staging.m-tama-ramu.workers.dev/oauth/google/callback?code=abc&state=valid",
    );
    const res = await handleGoogleCallback(req, env);
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
      join_org: "my-company",
    });
    mockIsAllowed.mockReturnValue(true);
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9.sig";
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ id_token: "mock-id-token" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ access_token: jwt, expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        ),
    );
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("/join/my-company/done");
    expect(location).toContain("#token=");
    expect(location).toContain(jwt);
    // Should NOT contain lw_callback for join flow
    expect(location).not.toContain("lw_callback");
  });

  it("sets logi_auth_token cookie on success (normal flow)", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9.sig";
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ id_token: "mock-id-token" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ access_token: jwt, expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        ),
    );
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.headers.get("Set-Cookie")).toContain(`logi_auth_token=${jwt}`);
  });

  it("sets logi_auth_token cookie on join flow", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://app1.test.example/page",
      join_org: "my-company",
    });
    mockIsAllowed.mockReturnValue(true);
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9.sig";
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ id_token: "mock-id-token" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ access_token: jwt, expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        ),
    );
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.headers.get("Set-Cookie")).toContain(`logi_auth_token=${jwt}`);
  });

  it("calls Google token endpoint with correct params", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ id_token: "mock-id-token" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9.sig", expires_in: 3600 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", mockFetch);
    const req = new Request("https://auth.test.example/oauth/google/callback?code=test-code&state=valid");
    await handleGoogleCallback(req, env);

    // First call: Google token exchange
    const googleCall = mockFetch.mock.calls[0]!;
    const [googleUrl, googleOpts] = googleCall;
    expect(googleUrl).toBe("https://oauth2.googleapis.com/token");
    expect(googleOpts.method).toBe("POST");
    const body = googleOpts.body as URLSearchParams;
    expect(body.get("code")).toBe("test-code");
    expect(body.get("client_id")).toBe("test-google-client-id");
    expect(body.get("client_secret")).toBe("test-google-client-secret");
    expect(body.get("redirect_uri")).toBe("https://auth.test.example/oauth/google/callback");

    // Second call: rust-alc-api auth
    const alcCall = mockFetch.mock.calls[1]!;
    const [alcUrl] = alcCall;
    expect(alcUrl).toBe("https://alc-api.test.example/api/auth/google");
  });

  it("handles token without payload segment (no dot)", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ id_token: "mock" }), { status: 200, headers: { "Content-Type": "application/json" } }),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ access_token: "no-dots-token", expires_in: 3600 }), { status: 200, headers: { "Content-Type": "application/json" } }),
        ),
    );
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    // org_id should not be in fragment since token has no payload
    expect(location).not.toContain("org_id=");
  });

  it("handles invalid base64 in JWT payload gracefully", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ id_token: "mock" }), { status: 200, headers: { "Content-Type": "application/json" } }),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ access_token: "header.!!!invalid-base64!!!.sig", expires_in: 3600 }), { status: 200, headers: { "Content-Type": "application/json" } }),
        ),
    );
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
  });

  it("returns 403 when tenant is not in TENANT_ACL for an ohishi-exp redirect target", async () => {
    const aclEnv = createMockEnv({
      AUTH_CONFIG: (await import("../helpers/mock-env")).createMockKV({
        "origins:prod": "https://dtako-admin.example",
        "app-orgs": JSON.stringify({ "dtako-admin": "ohishi-exp" }),
      }),
      TENANT_ACL: JSON.stringify({ "ohishi-exp": ["allowed-tenant"] }),
    });
    mockVerify.mockResolvedValue({ redirect_uri: "https://dtako-admin.example/page" });
    mockIsAllowed.mockReturnValue(true);
    // JWT: {"tenant_id":"some-other-tenant"}
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJzb21lLW90aGVyLXRlbmFudCJ9.sig";
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ id_token: "mock-id-token" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ access_token: jwt, expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        ),
    );
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, aclEnv);
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("許可されていません");
  });

  it("allows redirect when tenant IS in TENANT_ACL for an ohishi-exp target", async () => {
    const aclEnv = createMockEnv({
      AUTH_CONFIG: (await import("../helpers/mock-env")).createMockKV({
        "origins:prod": "https://dtako-admin.example",
        "app-orgs": JSON.stringify({ "dtako-admin": "ohishi-exp" }),
      }),
      TENANT_ACL: JSON.stringify({ "ohishi-exp": ["allowed-tenant"] }),
    });
    mockVerify.mockResolvedValue({ redirect_uri: "https://dtako-admin.example/page" });
    mockIsAllowed.mockReturnValue(true);
    // JWT: {"tenant_id":"allowed-tenant"}
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJhbGxvd2VkLXRlbmFudCJ9.sig";
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ id_token: "mock-id-token" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ access_token: jwt, expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        ),
    );
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, aclEnv);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("https://dtako-admin.example/page");
  });

  it("wt origin bypasses ACL even with no tenant_id", async () => {
    const aclEnv = createMockEnv({
      AUTH_CONFIG: (await import("../helpers/mock-env")).createMockKV({
        "origins:prod": "https://a.example",
        "origins:wt": "https://vast.trycloudflare.com",
        "app-orgs": JSON.stringify({ vast: "ohishi-exp" }),
      }),
      TENANT_ACL: JSON.stringify({ "ohishi-exp": [] }),
    });
    mockVerify.mockResolvedValue({ redirect_uri: "https://vast.trycloudflare.com/callback" });
    mockIsAllowed.mockReturnValue(true);
    // Token without payload → tenant_id "" → would normally be denied for ohishi-exp
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ id_token: "mock" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ access_token: "no-payload-token", expires_in: 3600 }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        ),
    );
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, aclEnv);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("https://vast.trycloudflare.com/callback");
  });
});
