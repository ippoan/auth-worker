import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

vi.mock("../../src/lib/security", () => ({
  verifyOAuthState: vi.fn(),
  isAllowedRedirectUri: vi.fn(),
}));

import { handleGoogleCallback } from "../../src/handlers/google-callback";
import { verifyOAuthState, isAllowedRedirectUri } from "../../src/lib/security";
import type { InternalUserWithSlug } from "../../src/lib/alc-internal";

const mockVerify = vi.mocked(verifyOAuthState);
const mockIsAllowed = vi.mocked(isAllowedRedirectUri);

/** base64url で JWT 形式の id_token を組む (署名はダミー — handler は decode のみ)。 */
function makeIdToken(payload: Record<string, unknown>): string {
  const b64 = (o: unknown) =>
    btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${b64({ alg: "RS256" })}.${b64(payload)}.sig`;
}

const GOOGLE_ID_TOKEN = makeIdToken({
  sub: "google-sub-1",
  email: "user@example.com",
  name: "Test User",
  email_verified: true,
});

function mockUser(overrides: Partial<InternalUserWithSlug> = {}): InternalUserWithSlug {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    tenant_id: "test-org",
    email: "user@example.com",
    name: "Test User",
    role: "admin",
    google_sub: "google-sub-1",
    lineworks_id: null,
    line_user_id: null,
    slug: "test-slug",
    ...overrides,
  };
}

/** 1st fetch = Google token 交換 (id_token) / 2nd fetch = internal upsert-google。 */
function stubLoginFetches(
  secondResponse: Response,
  idToken: string = GOOGLE_ID_TOKEN,
): ReturnType<typeof vi.fn> {
  const mockFetch = vi
    .fn()
    .mockResolvedValueOnce(
      new Response(JSON.stringify({ id_token: idToken }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    )
    .mockResolvedValueOnce(secondResponse);
  vi.stubGlobal("fetch", mockFetch);
  return mockFetch;
}

function userResponse(user: InternalUserWithSlug = mockUser()): Response {
  return new Response(JSON.stringify(user), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

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

  it("redirects to /login when id_token is not decodable", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify({ id_token: "not-a-jwt" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("Invalid+ID+token");
  });

  it("redirects to /login when Google email is not verified", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    const unverified = makeIdToken({
      sub: "google-sub-1",
      email: "user@example.com",
      email_verified: false,
    });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify({ id_token: unverified }), {
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
    expect(location).toContain(encodeURIComponent("未確認"));
  });

  it("redirects to /login on internal upsert-google failure (5xx)", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    stubLoginFetches(new Response("boom", { status: 500 }));
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("/login");
    expect(location).toContain(encodeURIComponent("ログイン処理に失敗しました"));
  });

  it("redirects to /login when no tenant matches (internal 403)", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    stubLoginFetches(
      new Response(JSON.stringify({ error: "no_tenant_for_email" }), { status: 403 }),
    );
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("/login");
    expect(location).toContain(encodeURIComponent("どのテナントにも登録されていません"));
  });

  it("302 redirects with cookie only (no token in URL) when target shares the auth cookie domain", async () => {
    // redirect 先 (app1.test.example) は auth host (auth.test.example) と同じ親ドメイン
    // (.test.example) 配下 → 共有 cookie が届くので token を URL に載せず cookie だけで渡す。
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    stubLoginFetches(userResponse());
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toBe("https://app1.test.example/page"); // クリーン (fragment/lw_callback なし)
    expect(location).not.toContain("#token=");
    expect(location).not.toContain("lw_callback");
    // auth-worker 自身が署名した HS256 JWT が cookie に載る
    expect(res.headers.get("Set-Cookie")).toContain("logi_auth_token=eyJ");
  });

  it("302 redirects with #token= fragment when cookie domain is a public suffix (workers.dev)", async () => {
    // auth host が *.workers.dev (public suffix → Domain cookie 不可) の場合は従来どおり
    // fragment で配布する。
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    stubLoginFetches(userResponse());
    const req = new Request(
      "https://auth-staging.m-tama-ramu.workers.dev/oauth/google/callback?code=abc&state=valid",
    );
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("https://app1.test.example/page");
    expect(location).toContain("#token=");
    expect(location).toContain("org_id=test-org");
    expect(location).toContain("lw_callback=1");
  });

  it("302 redirects to /join/:slug/done on join flow", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://app1.test.example/page",
      join_org: "my-company",
    });
    mockIsAllowed.mockReturnValue(true);
    stubLoginFetches(userResponse());
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("/join/my-company/done");
    expect(location).toContain("#token=");
    // Should NOT contain lw_callback for join flow
    expect(location).not.toContain("lw_callback");
  });

  it("sets logi_auth_token cookie on success (normal flow)", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    stubLoginFetches(userResponse());
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.headers.get("Set-Cookie")).toContain("logi_auth_token=eyJ");
  });

  it("sets logi_auth_token cookie on join flow", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://app1.test.example/page",
      join_org: "my-company",
    });
    mockIsAllowed.mockReturnValue(true);
    stubLoginFetches(userResponse());
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, env);
    expect(res.headers.get("Set-Cookie")).toContain("logi_auth_token=eyJ");
  });

  it("calls Google token endpoint and internal upsert-google with correct params", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: "https://app1.test.example/page" });
    mockIsAllowed.mockReturnValue(true);
    const mockFetch = stubLoginFetches(userResponse());
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

    // Second call: internal upsert-google (旧 /api/auth/google は撤去済み)
    const alcCall = mockFetch.mock.calls[1]!;
    const [alcUrl, alcOpts] = alcCall;
    expect(alcUrl).toBe("https://alc-api.test.example/api/internal/auth/users/upsert-google");
    const headers = new Headers(alcOpts.headers);
    expect(headers.get("Authorization")).toContain("Bearer ");
    expect(JSON.parse(alcOpts.body as string)).toEqual({
      google_sub: "google-sub-1",
      email: "user@example.com",
      name: "Test User",
    });
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
    stubLoginFetches(userResponse(mockUser({ tenant_id: "some-other-tenant" })));
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
    stubLoginFetches(userResponse(mockUser({ tenant_id: "allowed-tenant" })));
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
    // tenant_id "" → would normally be denied for ohishi-exp, but wt origin bypasses ACL
    stubLoginFetches(userResponse(mockUser({ tenant_id: "" })));
    const req = new Request("https://auth.test.example/oauth/google/callback?code=abc&state=valid");
    const res = await handleGoogleCallback(req, aclEnv);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("https://vast.trycloudflare.com/callback");
  });
});
