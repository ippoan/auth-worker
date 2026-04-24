import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";
import { handleEgovCallback } from "../../src/handlers/egov-callback";
import { generateOAuthState } from "../../src/lib/security";

const EGOV_ENV = {
  EGOV_CLIENT_ID: "test-egov-client-id",
  EGOV_CLIENT_SECRET: "test-egov-client-secret",
  EGOV_AUTH_BASE: "https://account2.sbx.e-gov.test/auth",
};

function buildCallbackUrl(params: Record<string, string>): string {
  const u = new URL("https://auth.test.example/oauth/egov/callback");
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return u.toString();
}

describe("handleEgovCallback", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 503 when e-Gov secrets missing", async () => {
    const env = createMockEnv({ ...EGOV_ENV, EGOV_CLIENT_SECRET: undefined });
    const req = new Request(buildCallbackUrl({ code: "x", state: "y" }));
    const res = await handleEgovCallback(req, env);
    expect(res.status).toBe(503);
  });

  it("returns 400 on oauth error param", async () => {
    const env = createMockEnv(EGOV_ENV);
    const req = new Request(buildCallbackUrl({ error: "access_denied" }));
    const res = await handleEgovCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("access_denied");
  });

  it("returns 400 when code or state missing", async () => {
    const env = createMockEnv(EGOV_ENV);
    const req = new Request(buildCallbackUrl({ code: "x" }));
    const res = await handleEgovCallback(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 400 on invalid HMAC state", async () => {
    const env = createMockEnv(EGOV_ENV);
    const req = new Request(buildCallbackUrl({ code: "x", state: "bogus" }));
    const res = await handleEgovCallback(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 400 when code_verifier missing from state", async () => {
    const env = createMockEnv(EGOV_ENV);
    // state built without code_verifier
    const state = await generateOAuthState(
      "https://app1.test.example/callback",
      env.OAUTH_STATE_SECRET,
    );
    const req = new Request(buildCallbackUrl({ code: "x", state }));
    const res = await handleEgovCallback(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Missing code_verifier");
  });

  it("returns 400 when state's redirect_uri is not allowed", async () => {
    const env = createMockEnv(EGOV_ENV);
    const state = await generateOAuthState(
      "https://evil.example.com/callback",
      env.OAUTH_STATE_SECRET,
      { code_verifier: "v1" },
    );
    const req = new Request(buildCallbackUrl({ code: "x", state }));
    const res = await handleEgovCallback(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 502 when e-Gov token exchange fails", async () => {
    const env = createMockEnv(EGOV_ENV);
    const state = await generateOAuthState(
      "https://app1.test.example/callback",
      env.OAUTH_STATE_SECRET,
      { code_verifier: "v1" },
    );
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response("invalid_grant", { status: 400 }),
    );
    const req = new Request(buildCallbackUrl({ code: "x", state }));
    const res = await handleEgovCallback(req, env);
    expect(res.status).toBe(502);
  });

  it("forwards tokens via fragment on successful exchange", async () => {
    const env = createMockEnv(EGOV_ENV);
    const state = await generateOAuthState(
      "https://app1.test.example/callback",
      env.OAUTH_STATE_SECRET,
      { code_verifier: "v1" },
    );
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: "AT",
          refresh_token: "RT",
          expires_in: 3600,
          token_type: "Bearer",
          id_token: "IT",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    const req = new Request(buildCallbackUrl({ code: "the-code", state }));
    const res = await handleEgovCallback(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location.startsWith("https://app1.test.example/callback#")).toBe(true);
    expect(location).toContain("access_token=AT");
    expect(location).toContain("refresh_token=RT");
    expect(location).toContain("expires_in=3600");
    expect(location).toContain("token_type=Bearer");
    expect(location).toContain("id_token=IT");
  });
});
