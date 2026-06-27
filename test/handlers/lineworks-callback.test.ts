import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

// #434 Phase 2: callback は rust proxy ではなく auth-worker 内製。code 交換 /
// profile / user upsert / JWT 発行を auth-worker で行うため、外部依存を mock する。
vi.mock("../../src/lib/security", () => ({
  verifyOAuthState: vi.fn(),
  isAllowedRedirectUri: vi.fn(),
}));
vi.mock("../../src/lib/alc-internal", () => ({
  resolveSsoConfig: vi.fn(),
  upsertLineworksUser: vi.fn(),
  saveRefreshToken: vi.fn(),
}));
vi.mock("../../src/lib/lineworks-oauth", () => ({
  exchangeCode: vi.fn(),
  fetchUserProfile: vi.fn(),
  displayName: vi.fn(() => "User Name"),
  emailOrId: vi.fn(() => "u1@example.com"),
}));
vi.mock("../../src/lib/lineworks-crypto", () => ({
  decryptBotSecret: vi.fn(async () => "decrypted-secret"),
}));
vi.mock("../../src/lib/acl", () => ({
  checkOrgAccess: vi.fn(async () => true),
  checkAppTenant: vi.fn(() => true),
}));

import { handleLineworksCallback } from "../../src/handlers/lineworks-callback";
import { verifyOAuthState, isAllowedRedirectUri } from "../../src/lib/security";
import { resolveSsoConfig, upsertLineworksUser, saveRefreshToken } from "../../src/lib/alc-internal";
import { exchangeCode, fetchUserProfile } from "../../src/lib/lineworks-oauth";
import { decryptBotSecret } from "../../src/lib/lineworks-crypto";
import { checkOrgAccess, checkAppTenant } from "../../src/lib/acl";

const mockVerify = vi.mocked(verifyOAuthState);
const mockIsAllowed = vi.mocked(isAllowedRedirectUri);
const mockResolveSso = vi.mocked(resolveSsoConfig);
const mockUpsert = vi.mocked(upsertLineworksUser);
const mockSaveRefresh = vi.mocked(saveRefreshToken);
const mockExchange = vi.mocked(exchangeCode);
const mockProfile = vi.mocked(fetchUserProfile);
const mockDecrypt = vi.mocked(decryptBotSecret);
const mockOrgAccess = vi.mocked(checkOrgAccess);
const mockAppTenant = vi.mocked(checkAppTenant);

const okState = {
  redirect_uri: "https://app1.test.example/page",
  provider: "lineworks",
  external_org_id: "org1",
};
const okUser = {
  id: "11111111-1111-1111-1111-111111111111",
  tenant_id: "22222222-2222-2222-2222-222222222222",
  email: "u1@example.com",
  name: "User Name",
  role: "admin",
  google_sub: null,
  lineworks_id: "lw1",
  line_user_id: null,
  slug: "ohishi",
};

function setupSuccess() {
  mockVerify.mockResolvedValue(okState);
  mockIsAllowed.mockReturnValue(true);
  mockResolveSso.mockResolvedValue({
    tenant_id: okUser.tenant_id,
    client_id: "c",
    client_secret_encrypted: "enc",
    external_org_id: "org1",
    woff_id: null,
  });
  mockDecrypt.mockResolvedValue("decrypted-secret");
  mockExchange.mockResolvedValue({ access_token: "at" });
  mockProfile.mockResolvedValue({ userId: "lw1" });
  mockUpsert.mockResolvedValue(okUser);
  mockSaveRefresh.mockResolvedValue(undefined);
  mockOrgAccess.mockResolvedValue(true);
  mockAppTenant.mockReturnValue(true);
}

function callbackReq(query = "code=abc&state=valid"): Request {
  return new Request(`https://auth.test.example/oauth/lineworks/callback?${query}`);
}

describe("handleLineworksCallback", () => {
  const env = createMockEnv();
  beforeEach(() => vi.clearAllMocks());

  it("returns 400 if error param present", async () => {
    const res = await handleLineworksCallback(callbackReq("error=access_denied"), env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("access_denied");
  });

  it("returns 400 if code missing", async () => {
    const res = await handleLineworksCallback(callbackReq("state=abc"), env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Missing code or state parameter");
  });

  it("returns 400 if state missing", async () => {
    const res = await handleLineworksCallback(callbackReq("code=abc"), env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Missing code or state parameter");
  });

  it("returns 400 if state verification fails", async () => {
    mockVerify.mockResolvedValue(null);
    const res = await handleLineworksCallback(callbackReq(), env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid state parameter");
  });

  it("returns 400 if redirect_uri not allowed", async () => {
    mockVerify.mockResolvedValue({ ...okState, redirect_uri: "https://evil.example/hack" });
    mockIsAllowed.mockReturnValue(false);
    const res = await handleLineworksCallback(callbackReq(), env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid redirect_uri in state");
  });

  it("returns 400 if externalOrgId missing", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: okState.redirect_uri, provider: "lineworks" });
    mockIsAllowed.mockReturnValue(true);
    const res = await handleLineworksCallback(callbackReq(), env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Missing external_org_id in state");
  });

  it("returns 400 if SSO config not found", async () => {
    mockVerify.mockResolvedValue(okState);
    mockIsAllowed.mockReturnValue(true);
    mockResolveSso.mockResolvedValue(null);
    const res = await handleLineworksCallback(callbackReq(), env);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("SSO config not found");
  });

  it("302 with cookie + #token & refresh_token on success", async () => {
    setupSuccess();
    const res = await handleLineworksCallback(callbackReq(), env);
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location")!;
    expect(loc).toContain("https://app1.test.example/page#");
    expect(loc).toContain("token=");
    expect(loc).toContain("refresh_token=rt_");
    expect(loc).toContain("expires_in=3600");
    expect(loc).toContain("lw_callback=1");
    expect(res.headers.get("Set-Cookie")).toContain("logi_auth_token=");
    expect(mockUpsert).toHaveBeenCalledWith(env, {
      tenant_id: okUser.tenant_id,
      lineworks_id: "lw1",
      email: "u1@example.com",
      name: "User Name",
    });
    expect(mockSaveRefresh).toHaveBeenCalled();
  });

  it("returns 403 when org ACL denies", async () => {
    setupSuccess();
    mockOrgAccess.mockResolvedValue(false);
    const res = await handleLineworksCallback(callbackReq(), env);
    expect(res.status).toBe(403);
  });

  it("returns 403 when app-tenant ACL denies", async () => {
    setupSuccess();
    mockAppTenant.mockReturnValue(false);
    const res = await handleLineworksCallback(callbackReq(), env);
    expect(res.status).toBe(403);
  });

  it("returns 502 on LINE WORKS upstream failure", async () => {
    setupSuccess();
    mockExchange.mockRejectedValue(new Error("token endpoint down"));
    const res = await handleLineworksCallback(callbackReq(), env);
    expect(res.status).toBe(502);
  });
});
