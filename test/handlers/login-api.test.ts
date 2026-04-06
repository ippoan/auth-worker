import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

vi.mock("../../src/lib/security", () => ({
  isAllowedRedirectUri: vi.fn(),
}));

import { handleAuthLogin } from "../../src/handlers/login-api";
import { isAllowedRedirectUri } from "../../src/lib/security";

const mockIsAllowed = vi.mocked(isAllowedRedirectUri);

function buildFormRequest(fields: Record<string, string>): Request {
  const form = new FormData();
  for (const [key, value] of Object.entries(fields)) {
    form.set(key, value);
  }
  return new Request("https://auth.test.example/auth/login", {
    method: "POST",
    body: form,
  });
}

describe("handleAuthLogin", () => {
  const env = createMockEnv();
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    vi.resetAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("returns 400 if redirect_uri missing", async () => {
    mockIsAllowed.mockReturnValue(false);
    const req = buildFormRequest({
      username: "testuser",
      password: "testpass",
    });
    const res = await handleAuthLogin(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid redirect_uri");
  });

  it("returns 400 if redirect_uri invalid", async () => {
    mockIsAllowed.mockReturnValue(false);
    const req = buildFormRequest({
      redirect_uri: "https://evil.example/hack",
      username: "testuser",
      password: "testpass",
    });
    const res = await handleAuthLogin(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid redirect_uri");
  });

  it("redirects to /login if username missing", async () => {
    mockIsAllowed.mockReturnValue(true);
    const req = buildFormRequest({
      redirect_uri: "https://app1.test.example/page",
      password: "testpass",
    });
    const res = await handleAuthLogin(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("/login");
    expect(location).toContain("Username+and+password+are+required");
  });

  it("redirects to /login if password missing", async () => {
    mockIsAllowed.mockReturnValue(true);
    const req = buildFormRequest({
      redirect_uri: "https://app1.test.example/page",
      username: "testuser",
    });
    const res = await handleAuthLogin(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("/login");
    expect(location).toContain("Username+and+password+are+required");
  });

  it("redirects to /login on auth failure", async () => {
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response("Invalid credentials", { status: 401 }),
      ),
    );
    const req = buildFormRequest({
      redirect_uri: "https://app1.test.example/page",
      username: "testuser",
      password: "wrongpass",
      organization_id: "org-123",
    });
    const res = await handleAuthLogin(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("/login");
    expect(location).toContain("Invalid+credentials");
    expect(location).toContain("org_id=org-123");
  });

  it("redirects to /login with default error when backend returns empty body", async () => {
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response("", { status: 401 }),
      ),
    );
    const req = buildFormRequest({
      redirect_uri: "https://app1.test.example/page",
      username: "testuser",
      password: "wrongpass",
    });
    const res = await handleAuthLogin(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("/login");
    expect(location).toContain("Authentication+failed");
  });

  it("302 redirects to redirect_uri#token=xxx on success", async () => {
    mockIsAllowed.mockReturnValue(true);
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9.sig";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: jwt, expires_in: 3600 }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const req = buildFormRequest({
      redirect_uri: "https://app1.test.example/page",
      username: "testuser",
      password: "testpass",
      organization_id: "org-123",
    });
    const res = await handleAuthLogin(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("https://app1.test.example/page");
    expect(location).toContain("#token=");
    expect(location).toContain(jwt);
    expect(location).toContain("org_id=test-org");
    expect(location).toContain("expires_at=");
  });

  it("passes organization_id to backend", async () => {
    mockIsAllowed.mockReturnValue(true);
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9.sig";
    const mockFetch = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({ access_token: jwt, expires_in: 3600 }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", mockFetch);
    const req = buildFormRequest({
      redirect_uri: "https://app1.test.example/page",
      username: "testuser",
      password: "testpass",
      organization_id: "org-123",
    });
    await handleAuthLogin(req, env);

    const [callUrl, callOpts] = mockFetch.mock.calls[0];
    expect(callUrl).toBe("https://alc-api.test.example/api/auth/login");
    expect(callOpts.method).toBe("POST");
    const body = JSON.parse(callOpts.body);
    expect(body.organization_id).toBe("org-123");
    expect(body.username).toBe("testuser");
    expect(body.password).toBe("testpass");
  });

  it("sends empty string for organization_id when not provided", async () => {
    mockIsAllowed.mockReturnValue(true);
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9.sig";
    const mockFetch = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({ access_token: jwt, expires_in: 3600 }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", mockFetch);
    const req = buildFormRequest({
      redirect_uri: "https://app1.test.example/page",
      username: "testuser",
      password: "testpass",
    });
    await handleAuthLogin(req, env);

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.organization_id).toBe("");
  });

  it("does not include org_id in login redirect when organization_id not provided", async () => {
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response("Unauthorized", { status: 401 }),
      ),
    );
    const req = buildFormRequest({
      redirect_uri: "https://app1.test.example/page",
      username: "testuser",
      password: "wrongpass",
    });
    const res = await handleAuthLogin(req, env);
    const location = res.headers.get("Location")!;
    expect(location).not.toContain("org_id=");
  });

  it("handles token without payload segment", async () => {
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "no-dots", expires_in: 3600 }), { status: 200, headers: { "Content-Type": "application/json" } }),
      ),
    );
    const req = buildFormRequest({
      redirect_uri: "https://app1.test.example/page",
      username: "testuser",
      password: "testpass",
    });
    const res = await handleAuthLogin(req, env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).not.toContain("org_id=");
  });

  it("handles invalid base64 in JWT payload", async () => {
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: "h.!!!bad!!!.s", expires_in: 3600 }), { status: 200, headers: { "Content-Type": "application/json" } }),
      ),
    );
    const req = buildFormRequest({
      redirect_uri: "https://app1.test.example/page",
      username: "testuser",
      password: "testpass",
    });
    const res = await handleAuthLogin(req, env);
    expect(res.status).toBe(302);
  });
});
