import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

// #434 Phase 2: redirect は rust proxy ではなく auth-worker 内製。sso-config は
// rust internal 解決、state 署名 + authorize URL 構築は auth-worker 側で行う。
vi.mock("../../src/lib/security", () => ({
  isAllowedRedirectUri: vi.fn(),
  generateOAuthState: vi.fn(async () => "signed-state"),
}));
vi.mock("../../src/lib/alc-internal", () => ({
  resolveSsoConfig: vi.fn(),
}));

import { handleLineworksRedirect } from "../../src/handlers/lineworks-redirect";
import { isAllowedRedirectUri } from "../../src/lib/security";
import { resolveSsoConfig } from "../../src/lib/alc-internal";

const mockIsAllowed = vi.mocked(isAllowedRedirectUri);
const mockResolveSso = vi.mocked(resolveSsoConfig);

const ssoConfig = {
  tenant_id: "22222222-2222-2222-2222-222222222222",
  client_id: "client123",
  client_secret_encrypted: "enc",
  external_org_id: "ohishi",
  woff_id: null,
};

describe("handleLineworksRedirect", () => {
  const env = createMockEnv();
  beforeEach(() => vi.clearAllMocks());

  it("returns 400 when redirect_uri is missing", async () => {
    mockIsAllowed.mockReturnValue(false);
    const req = new Request(
      "https://auth.test.example/oauth/lineworks/redirect?address=tanaka@ohishi",
    );
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid or missing redirect_uri");
  });

  it("returns 400 when redirect_uri origin is not allowed", async () => {
    mockIsAllowed.mockReturnValue(false);
    const req = new Request(
      "https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://evil.example.com/cb&address=tanaka@ohishi",
    );
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 400 when domain/address is missing", async () => {
    mockIsAllowed.mockReturnValue(true);
    const req = new Request(
      "https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://app1.test.example/callback",
    );
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Missing domain or address parameter");
  });

  it("returns 404 when no SSO config for domain", async () => {
    mockIsAllowed.mockReturnValue(true);
    mockResolveSso.mockResolvedValue(null);
    const req = new Request(
      "https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://app1.test.example/callback&address=tanaka@ohishi",
    );
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(404);
  });

  it("302 to LINE WORKS authorize with client_id + signed state", async () => {
    mockIsAllowed.mockReturnValue(true);
    mockResolveSso.mockResolvedValue(ssoConfig);
    const req = new Request(
      "https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://app1.test.example/callback&address=tanaka@ohishi",
    );
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location")!;
    expect(loc).toContain("https://auth.worksmobile.com/oauth2/v2.0/authorize");
    expect(loc).toContain("client_id=client123");
    expect(loc).toContain("state=signed-state");
    expect(loc).toContain("scope=user.profile.read");
    // callback は auth-worker 自身 (encode 済みで含まれる)
    expect(decodeURIComponent(loc)).toContain("https://auth.test.example/oauth/lineworks/callback");
    expect(mockResolveSso).toHaveBeenCalledWith(env, "lineworks", "ohishi");
  });

  it("accepts explicit domain param without @", async () => {
    mockIsAllowed.mockReturnValue(true);
    mockResolveSso.mockResolvedValue(ssoConfig);
    const req = new Request(
      "https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://app1.test.example/callback&domain=ohishi",
    );
    const res = await handleLineworksRedirect(req, env);
    expect(res.status).toBe(302);
    expect(mockResolveSso).toHaveBeenCalledWith(env, "lineworks", "ohishi");
  });
});
