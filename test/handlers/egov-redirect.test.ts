import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";
import { handleEgovRedirect } from "../../src/handlers/egov-redirect";

const EGOV_ENV = {
  EGOV_CLIENT_ID: "test-egov-client-id",
  EGOV_CLIENT_SECRET: "test-egov-client-secret",
  EGOV_AUTH_BASE: "https://account2.sbx.e-gov.test/auth",
};

describe("handleEgovRedirect", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 503 when EGOV_CLIENT_ID is missing", async () => {
    const env = createMockEnv({ ...EGOV_ENV, EGOV_CLIENT_ID: undefined });
    const req = new Request(
      "https://auth.test.example/oauth/egov/redirect?redirect_uri=https://app1.test.example/callback",
    );
    const res = await handleEgovRedirect(req, env);
    expect(res.status).toBe(503);
    expect(await res.text()).toBe("e-Gov OAuth not configured");
  });

  it("returns 503 when EGOV_AUTH_BASE is missing", async () => {
    const env = createMockEnv({ ...EGOV_ENV, EGOV_AUTH_BASE: undefined });
    const req = new Request(
      "https://auth.test.example/oauth/egov/redirect?redirect_uri=https://app1.test.example/callback",
    );
    const res = await handleEgovRedirect(req, env);
    expect(res.status).toBe(503);
  });

  it("returns 400 when redirect_uri is missing", async () => {
    const env = createMockEnv(EGOV_ENV);
    const req = new Request("https://auth.test.example/oauth/egov/redirect");
    const res = await handleEgovRedirect(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid or missing redirect_uri");
  });

  it("returns 400 when redirect_uri origin is not allowed", async () => {
    const env = createMockEnv(EGOV_ENV);
    const req = new Request(
      "https://auth.test.example/oauth/egov/redirect?redirect_uri=https://evil.example.com/callback",
    );
    const res = await handleEgovRedirect(req, env);
    expect(res.status).toBe(400);
  });

  it("redirects 302 to e-Gov auth URL with PKCE + state", async () => {
    const env = createMockEnv(EGOV_ENV);
    const req = new Request(
      "https://auth.test.example/oauth/egov/redirect?redirect_uri=https://app1.test.example/callback",
    );
    const res = await handleEgovRedirect(req, env);
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain("account2.sbx.e-gov.test/auth/auth");
    expect(location).toContain("client_id=test-egov-client-id");
    expect(location).toContain("response_type=code");
    expect(location).toContain("code_challenge=");
    expect(location).toContain("code_challenge_method=S256");
    expect(location).toContain("state=");
    // our callback, not the client's
    expect(location).toContain(
      encodeURIComponent("https://auth.test.example/oauth/egov/callback"),
    );
  });

  it("appends kc_idp_hint when idp_hint is passed", async () => {
    const env = createMockEnv(EGOV_ENV);
    const req = new Request(
      "https://auth.test.example/oauth/egov/redirect?redirect_uri=https://app1.test.example/callback&idp_hint=gbiz",
    );
    const res = await handleEgovRedirect(req, env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")!).toContain("kc_idp_hint=gbiz");
  });

  it("does not emit kc_idp_hint when idp_hint is absent", async () => {
    const env = createMockEnv(EGOV_ENV);
    const req = new Request(
      "https://auth.test.example/oauth/egov/redirect?redirect_uri=https://app1.test.example/callback",
    );
    const res = await handleEgovRedirect(req, env);
    expect(res.headers.get("Location")!).not.toContain("kc_idp_hint");
  });
});
