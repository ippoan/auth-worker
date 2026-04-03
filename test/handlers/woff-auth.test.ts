import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";
import { createTestJwt } from "../helpers/test-jwt";

const mockLoginWithSsoProvider = vi.fn();
const mockResolveSsoProvider = vi.fn();
vi.mock("@connectrpc/connect", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@connectrpc/connect")>();
  return {
    ...actual,
    createClient: vi.fn(() => ({
      loginWithSsoProvider: mockLoginWithSsoProvider,
      resolveSsoProvider: mockResolveSsoProvider,
    })),
  };
});
vi.mock("../../src/lib/transport", () => ({
  createTransport: vi.fn(),
}));
vi.mock("@yhonda-ohishi-pub-dev/logi-proto", () => ({
  AuthService: {},
}));

import { handleWoffAuth, handleWoffConfig } from "../../src/handlers/woff-auth";

describe("handleWoffAuth", () => {
  const env = createMockEnv();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  function makeRequest(body: unknown) {
    return new Request("https://auth.test.example/auth/woff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  it("returns 400 for invalid JSON", async () => {
    const req = new Request("https://auth.test.example/auth/woff", {
      method: "POST",
      body: "not json",
    });
    const res = await handleWoffAuth(req, env);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Invalid JSON body" });
  });

  it("returns 400 for missing accessToken", async () => {
    const res = await handleWoffAuth(
      makeRequest({ domainId: "d1", redirectUri: "https://app1.test.example/cb" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 for missing domainId", async () => {
    const res = await handleWoffAuth(
      makeRequest({ accessToken: "t1", redirectUri: "https://app1.test.example/cb" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 for invalid redirect_uri", async () => {
    const res = await handleWoffAuth(
      makeRequest({ accessToken: "t1", domainId: "d1", redirectUri: "https://evil.com" }),
      env,
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Invalid or missing redirect_uri" });
  });

  it("returns 400 for missing redirect_uri", async () => {
    const res = await handleWoffAuth(
      makeRequest({ accessToken: "t1", domainId: "d1" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns token on success", async () => {
    const jwt = createTestJwt({ org: "org-1" });
    mockLoginWithSsoProvider.mockResolvedValueOnce({ token: jwt, expiresAt: "9999" });

    const res = await handleWoffAuth(
      makeRequest({
        accessToken: "t1",
        domainId: "d1",
        redirectUri: "https://app1.test.example/cb",
      }),
      env,
    );
    expect(res.status).toBe(200);
    const data = await res.json<{ token: string; orgId: string }>();
    expect(data.token).toBe(jwt);
    expect(data.orgId).toBe("org-1");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  it("returns orgId empty when payload has no org field", async () => {
    // JWT with valid base64 payload but no 'org' field
    const payload = btoa(JSON.stringify({ sub: "test" }));
    const token = `header.${payload}.sig`;
    mockLoginWithSsoProvider.mockResolvedValueOnce({ token, expiresAt: "9999" });

    const res = await handleWoffAuth(
      makeRequest({
        accessToken: "t1",
        domainId: "d1",
        redirectUri: "https://app1.test.example/cb",
      }),
      env,
    );
    const data = await res.json<{ orgId: string }>();
    expect(data.orgId).toBe("");
  });

  it("returns orgId empty when token has no dots", async () => {
    mockLoginWithSsoProvider.mockResolvedValueOnce({ token: "nodots", expiresAt: "9999" });

    const res = await handleWoffAuth(
      makeRequest({
        accessToken: "t1",
        domainId: "d1",
        redirectUri: "https://app1.test.example/cb",
      }),
      env,
    );
    const data = await res.json<{ orgId: string }>();
    expect(data.orgId).toBe("");
  });

  it("returns orgId empty when JWT payload decode fails", async () => {
    mockLoginWithSsoProvider.mockResolvedValueOnce({ token: "bad.!!!.jwt", expiresAt: "9999" });

    const res = await handleWoffAuth(
      makeRequest({
        accessToken: "t1",
        domainId: "d1",
        redirectUri: "https://app1.test.example/cb",
      }),
      env,
    );
    const data = await res.json<{ orgId: string }>();
    expect(data.orgId).toBe("");
  });

  it("returns 401 on ConnectError", async () => {
    const { ConnectError } = await import("@connectrpc/connect");
    mockLoginWithSsoProvider.mockRejectedValueOnce(new ConnectError("auth failed", 16));

    const res = await handleWoffAuth(
      makeRequest({
        accessToken: "t1",
        domainId: "d1",
        redirectUri: "https://app1.test.example/cb",
      }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("throws non-ConnectError", async () => {
    mockLoginWithSsoProvider.mockRejectedValueOnce(new Error("boom"));

    await expect(
      handleWoffAuth(
        makeRequest({
          accessToken: "t1",
          domainId: "d1",
          redirectUri: "https://app1.test.example/cb",
        }),
        env,
      ),
    ).rejects.toThrow("boom");
  });
});

describe("handleWoffConfig", () => {
  const env = createMockEnv();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns 400 for missing domain", async () => {
    const req = new Request("https://auth.test.example/auth/woff-config");
    const res = await handleWoffConfig(req, env);
    expect(res.status).toBe(400);
  });

  it("returns woffId on success", async () => {
    mockResolveSsoProvider.mockResolvedValueOnce({ available: true, woffId: "woff-123" });

    const req = new Request("https://auth.test.example/auth/woff-config?domain=ohishi");
    const res = await handleWoffConfig(req, env);
    expect(res.status).toBe(200);
    const data = await res.json<{ woffId: string }>();
    expect(data.woffId).toBe("woff-123");
  });

  it("returns 404 when not available", async () => {
    mockResolveSsoProvider.mockResolvedValueOnce({ available: false, woffId: "" });

    const req = new Request("https://auth.test.example/auth/woff-config?domain=ohishi");
    const res = await handleWoffConfig(req, env);
    expect(res.status).toBe(404);
  });

  it("returns 404 when woffId is empty", async () => {
    mockResolveSsoProvider.mockResolvedValueOnce({ available: true, woffId: "" });

    const req = new Request("https://auth.test.example/auth/woff-config?domain=ohishi");
    const res = await handleWoffConfig(req, env);
    expect(res.status).toBe(404);
  });

  it("returns 500 on ConnectError", async () => {
    const { ConnectError } = await import("@connectrpc/connect");
    mockResolveSsoProvider.mockRejectedValueOnce(new ConnectError("internal", 13));

    const req = new Request("https://auth.test.example/auth/woff-config?domain=ohishi");
    const res = await handleWoffConfig(req, env);
    expect(res.status).toBe(500);
  });

  it("throws non-ConnectError", async () => {
    mockResolveSsoProvider.mockRejectedValueOnce(new Error("boom"));

    const req = new Request("https://auth.test.example/auth/woff-config?domain=ohishi");
    await expect(handleWoffConfig(req, env)).rejects.toThrow("boom");
  });
});
