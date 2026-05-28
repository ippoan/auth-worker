import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

vi.mock("../../src/lib/security", () => ({
  verifyOAuthState: vi.fn(),
  isAllowedRedirectUri: vi.fn(),
}));

import { handleGhapiCallback } from "../../src/handlers/ghapi-callback";
import { verifyOAuthState, isAllowedRedirectUri } from "../../src/lib/security";

const mockVerify = vi.mocked(verifyOAuthState);
const mockIsAllowed = vi.mocked(isAllowedRedirectUri);

function makeIdToken(payload: Record<string, unknown>): string {
  const b64 = (s: string) =>
    btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${b64('{"alg":"RS256"}')}.${b64(JSON.stringify(payload))}.sig`;
}

function configuredEnv(overrides = {}) {
  return createMockEnv({
    GOOGLE_HEALTH_CLIENT_ID: "test-ghapi-client-id",
    GOOGLE_HEALTH_CLIENT_SECRET: "test-ghapi-client-secret",
    INTERNAL_SHARED_SECRET: "test-internal-shared",
    HCREADER_WORKER_ORIGIN: "https://hcreader.test.example",
    ...overrides,
  });
}

describe("handleGhapiCallback", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    vi.resetAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("returns 503 if GOOGLE_HEALTH_CLIENT_ID is unset", async () => {
    const env = createMockEnv();
    const req = new Request("https://auth.test.example/oauth/ghapi/callback?code=x&state=y");
    const res = await handleGhapiCallback(req, env);
    expect(res.status).toBe(503);
  });

  it("returns 503 if INTERNAL_SHARED_SECRET is unset", async () => {
    const env = configuredEnv({ INTERNAL_SHARED_SECRET: undefined });
    const req = new Request("https://auth.test.example/oauth/ghapi/callback?code=x&state=y");
    const res = await handleGhapiCallback(req, env);
    expect(res.status).toBe(503);
    expect(await res.text()).toContain("INTERNAL_SHARED_SECRET");
  });

  it("returns 503 if HCREADER_WORKER_ORIGIN is unset", async () => {
    const env = configuredEnv({ HCREADER_WORKER_ORIGIN: undefined });
    const req = new Request("https://auth.test.example/oauth/ghapi/callback?code=x&state=y");
    const res = await handleGhapiCallback(req, env);
    expect(res.status).toBe(503);
    expect(await res.text()).toContain("HCREADER_WORKER_ORIGIN");
  });

  it("returns 400 on Google error param", async () => {
    const env = configuredEnv();
    const req = new Request(
      "https://auth.test.example/oauth/ghapi/callback?error=access_denied",
    );
    const res = await handleGhapiCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("access_denied");
  });

  it("returns 400 if code or state missing", async () => {
    const env = configuredEnv();
    const req = new Request("https://auth.test.example/oauth/ghapi/callback?code=abc");
    const res = await handleGhapiCallback(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 400 on state verification failure", async () => {
    mockVerify.mockResolvedValue(null);
    const env = configuredEnv();
    const req = new Request(
      "https://auth.test.example/oauth/ghapi/callback?code=abc&state=bad",
    );
    const res = await handleGhapiCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid state parameter");
  });

  it("returns 400 if redirect_uri in state is not allowlisted", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: "https://evil.example/hack" });
    mockIsAllowed.mockReturnValue(false);
    const env = configuredEnv();
    const req = new Request(
      "https://auth.test.example/oauth/ghapi/callback?code=abc&state=valid",
    );
    const res = await handleGhapiCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid redirect_uri in state");
  });

  it("returns 502 on Google token exchange failure", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://hcreader.test.example/api/ghapi/connected",
    });
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("bad code", { status: 400 })),
    );
    const env = configuredEnv();
    const req = new Request(
      "https://auth.test.example/oauth/ghapi/callback?code=abc&state=valid",
    );
    const res = await handleGhapiCallback(req, env);
    expect(res.status).toBe(502);
  });

  it("returns 502 when token response lacks refresh_token", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://hcreader.test.example/api/ghapi/connected",
    });
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ access_token: "a", id_token: makeIdToken({ sub: "u1" }) }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const env = configuredEnv();
    const req = new Request(
      "https://auth.test.example/oauth/ghapi/callback?code=abc&state=valid",
    );
    const res = await handleGhapiCallback(req, env);
    expect(res.status).toBe(502);
    expect(await res.text()).toContain("refresh_token");
  });

  it("returns 502 when id_token has no sub claim", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://hcreader.test.example/api/ghapi/connected",
    });
    mockIsAllowed.mockReturnValue(true);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_token: "a",
            refresh_token: "rt",
            id_token: makeIdToken({ email: "x@y.z" }),
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const env = configuredEnv();
    const req = new Request(
      "https://auth.test.example/oauth/ghapi/callback?code=abc&state=valid",
    );
    const res = await handleGhapiCallback(req, env);
    expect(res.status).toBe(502);
    expect(await res.text()).toContain("id_token");
  });

  it("returns 502 when hcreader store-tokens returns non-2xx", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://hcreader.test.example/api/ghapi/connected",
    });
    mockIsAllowed.mockReturnValue(true);
    const fetchSpy = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            refresh_token: "rt-1",
            id_token: makeIdToken({ sub: "user-123" }),
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      )
      .mockResolvedValueOnce(new Response("nope", { status: 500 }));
    vi.stubGlobal("fetch", fetchSpy);
    const env = configuredEnv();
    const req = new Request(
      "https://auth.test.example/oauth/ghapi/callback?code=abc&state=valid",
    );
    const res = await handleGhapiCallback(req, env);
    expect(res.status).toBe(502);
    expect(await res.text()).toContain("store-tokens");
  });

  it("posts refresh_token to hcreader and redirects to redirect_uri on success", async () => {
    mockVerify.mockResolvedValue({
      redirect_uri: "https://hcreader.test.example/api/ghapi/connected",
    });
    mockIsAllowed.mockReturnValue(true);

    const fetchSpy = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            access_token: "at-1",
            refresh_token: "rt-1",
            id_token: makeIdToken({ sub: "user-123" }),
            expires_in: 3600,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetchSpy);

    const env = configuredEnv();
    const req = new Request(
      "https://auth.test.example/oauth/ghapi/callback?code=abc&state=valid",
    );
    const res = await handleGhapiCallback(req, env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe(
      "https://hcreader.test.example/api/ghapi/connected",
    );

    // 1st call: Google token exchange
    const tokenCall = fetchSpy.mock.calls[0];
    expect(tokenCall[0]).toBe("https://oauth2.googleapis.com/token");

    // 2nd call: hcreader store-tokens
    const storeCall = fetchSpy.mock.calls[1];
    expect(storeCall[0]).toBe("https://hcreader.test.example/api/ghapi/store-tokens");
    const init = storeCall[1] as RequestInit;
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).Authorization).toBe(
      "Bearer test-internal-shared",
    );
    const body = JSON.parse(init.body as string);
    expect(body.refresh_token).toBe("rt-1");
    expect(body.healthUserId).toBe("user-123");
  });
});
