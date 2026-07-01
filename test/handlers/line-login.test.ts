import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

// #434 Phase 3: LINE Login (notify recipient OAuth) を auth-worker に内製化。
vi.mock("../../src/lib/security", () => ({
  verifyOAuthState: vi.fn(),
  isAllowedRedirectUri: vi.fn(),
  generateOAuthState: vi.fn(async () => "signed-state"),
}));
vi.mock("../../src/lib/line-oauth", () => ({
  authorizeUrl: vi.fn(
    (channelId: string, redir: string, state: string) =>
      `https://access.line.me/oauth2/v2.1/authorize?client_id=${channelId}&redirect_uri=${redir}&state=${state}`,
  ),
  exchangeCode: vi.fn(),
  fetchProfile: vi.fn(),
}));
vi.mock("../../src/lib/alc-internal", () => ({
  findUserByLineId: vi.fn(),
  upsertLineUser: vi.fn(),
  registerLineRecipient: vi.fn(async () => undefined),
  recipientsByLineId: vi.fn(),
  saveRefreshToken: vi.fn(async () => undefined),
}));

import { handleLineRedirect } from "../../src/handlers/line-redirect";
import { handleLineCallback } from "../../src/handlers/line-callback";
import { handleLineSelectTenant } from "../../src/handlers/line-select-tenant";
import { signSelectToken, verifySelectToken } from "../../src/lib/line-select-token";
import { isAllowedRedirectUri, verifyOAuthState } from "../../src/lib/security";
import { exchangeCode, fetchProfile } from "../../src/lib/line-oauth";
import {
  findUserByLineId,
  upsertLineUser,
  recipientsByLineId,
  registerLineRecipient,
} from "../../src/lib/alc-internal";

const mockIsAllowed = vi.mocked(isAllowedRedirectUri);
const mockVerify = vi.mocked(verifyOAuthState);
const mockExchange = vi.mocked(exchangeCode);
const mockProfile = vi.mocked(fetchProfile);
const mockFindUser = vi.mocked(findUserByLineId);
const mockUpsert = vi.mocked(upsertLineUser);
const mockRecipients = vi.mocked(recipientsByLineId);
const mockRegister = vi.mocked(registerLineRecipient);

const env = createMockEnv({ LINE_LOGIN_CHANNEL_ID: "ch1", LINE_LOGIN_CHANNEL_SECRET: "sec1" });
const REDIRECT = "https://app1.test.example/page";
const user = {
  id: "11111111-1111-1111-1111-111111111111",
  tenant_id: "22222222-2222-2222-2222-222222222222",
  email: "u1@example.com",
  name: "User",
  role: "viewer",
  google_sub: null,
  lineworks_id: null,
  line_user_id: "Uxxxx",
  slug: "ohishi",
};

function req(path: string): Request {
  return new Request(`https://auth.test.example${path}`);
}

beforeEach(() => vi.clearAllMocks());

describe("handleLineRedirect", () => {
  it("400 when redirect_uri missing/disallowed", async () => {
    mockIsAllowed.mockReturnValue(false);
    const res = await handleLineRedirect(req("/oauth/line/redirect?redirect_uri=https://evil/x"), env);
    expect(res.status).toBe(400);
  });

  it("503 when channel not configured", async () => {
    mockIsAllowed.mockReturnValue(true);
    const res = await handleLineRedirect(
      req(`/oauth/line/redirect?redirect_uri=${encodeURIComponent(REDIRECT)}`),
      createMockEnv(),
    );
    expect(res.status).toBe(503);
  });

  it("302 to LINE authorize", async () => {
    mockIsAllowed.mockReturnValue(true);
    const res = await handleLineRedirect(
      req(`/oauth/line/redirect?redirect_uri=${encodeURIComponent(REDIRECT)}&tenant_id=t1`),
      env,
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("access.line.me/oauth2/v2.1/authorize");
    expect(res.headers.get("Location")).toContain("client_id=ch1");
  });
});

describe("handleLineCallback", () => {
  function setupTokenProfile() {
    mockVerify.mockResolvedValue({ redirect_uri: REDIRECT, provider: "line", external_org_id: "" });
    mockIsAllowed.mockReturnValue(true);
    mockExchange.mockResolvedValue({ access_token: "at" });
    mockProfile.mockResolvedValue({ userId: "Uxxxx", displayName: "User" });
  }

  it("400 missing code/state", async () => {
    const res = await handleLineCallback(req("/oauth/line/callback?code=abc"), env);
    expect(res.status).toBe(400);
  });

  it("400 invalid state", async () => {
    mockVerify.mockResolvedValue(null);
    const res = await handleLineCallback(req("/oauth/line/callback?code=abc&state=x"), env);
    expect(res.status).toBe(400);
  });

  it("502 on upstream failure", async () => {
    setupTokenProfile();
    mockExchange.mockRejectedValue(new Error("down"));
    const res = await handleLineCallback(req("/oauth/line/callback?code=abc&state=x"), env);
    expect(res.status).toBe(502);
  });

  it("existing user → 302 + cookie + #token", async () => {
    setupTokenProfile();
    mockFindUser.mockResolvedValue(user);
    const res = await handleLineCallback(req("/oauth/line/callback?code=abc&state=x"), env);
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location")!;
    // lw_callback は server-side /top ゲート用に query string、token は fragment。
    expect(loc).toContain(`${REDIRECT}?lw_callback=1#`);
    expect(loc).toContain("refresh_token=rt_");
    expect(res.headers.get("Set-Cookie")).toContain("logi_auth_token=");
  });

  it("QR invite (tenant in state) → register + upsert + 302", async () => {
    mockVerify.mockResolvedValue({ redirect_uri: REDIRECT, provider: "line", external_org_id: "t-qr" });
    mockIsAllowed.mockReturnValue(true);
    mockExchange.mockResolvedValue({ access_token: "at" });
    mockProfile.mockResolvedValue({ userId: "Uxxxx", displayName: "User" });
    mockFindUser.mockResolvedValue(null);
    mockUpsert.mockResolvedValue(user);
    const res = await handleLineCallback(req("/oauth/line/callback?code=abc&state=x"), env);
    expect(res.status).toBe(302);
    expect(mockRegister).toHaveBeenCalled();
    expect(mockUpsert).toHaveBeenCalledWith(env, { tenant_id: "t-qr", line_user_id: "Uxxxx", name: "User" });
  });

  it("0 recipients → error redirect", async () => {
    setupTokenProfile();
    mockFindUser.mockResolvedValue(null);
    mockRecipients.mockResolvedValue([]);
    const res = await handleLineCallback(req("/oauth/line/callback?code=abc&state=x"), env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("error=");
  });

  it("1 recipient → auto login", async () => {
    setupTokenProfile();
    mockFindUser.mockResolvedValue(null);
    mockRecipients.mockResolvedValue([{ tenant_id: "t1", name: "T1" }]);
    mockUpsert.mockResolvedValue(user);
    const res = await handleLineCallback(req("/oauth/line/callback?code=abc&state=x"), env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Set-Cookie")).toContain("logi_auth_token=");
  });

  it("many recipients → select-tenant redirect", async () => {
    setupTokenProfile();
    mockFindUser.mockResolvedValue(null);
    mockRecipients.mockResolvedValue([
      { tenant_id: "t1", name: "T1" },
      { tenant_id: "t2", name: "T2" },
    ]);
    const res = await handleLineCallback(req("/oauth/line/callback?code=abc&state=x"), env);
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location")!;
    // 生 line_user_id ではなく署名済み select_token を fragment で渡す。
    expect(loc).toContain("#");
    expect(loc).toContain("select_token=");
    expect(loc).toContain("tenants=");
    expect(loc).not.toContain("Uxxxx");
  });
});

describe("handleLineSelectTenant", () => {
  function post(body: unknown): Request {
    return new Request("https://auth.test.example/oauth/line/select-tenant", {
      method: "POST",
      body: JSON.stringify(body),
    });
  }

  const SECRET = "test-oauth-state-secret-32chars!"; // createMockEnv の OAUTH_STATE_SECRET

  it("400 on missing fields", async () => {
    const res = await handleLineSelectTenant(post({ select_token: "x" }), env);
    expect(res.status).toBe(400);
  });

  it("401 on invalid/garbage select_token", async () => {
    const res = await handleLineSelectTenant(post({ select_token: "garbage.sig", tenant_id: "t1" }), env);
    expect(res.status).toBe(401);
  });

  it("403 when not a recipient of tenant", async () => {
    const token = await signSelectToken({ line_user_id: "U", line_name: "N" }, SECRET);
    mockRecipients.mockResolvedValue([{ tenant_id: "other", name: "O" }]);
    const res = await handleLineSelectTenant(post({ select_token: token, tenant_id: "t1" }), env);
    expect(res.status).toBe(403);
  });

  it("200 JSON on success (line_user_id from token, not body)", async () => {
    const token = await signSelectToken({ line_user_id: "U", line_name: "N" }, SECRET);
    mockRecipients.mockResolvedValue([{ tenant_id: "t1", name: "T1" }]);
    mockFindUser.mockResolvedValue(null);
    mockUpsert.mockResolvedValue(user);
    const res = await handleLineSelectTenant(post({ select_token: token, tenant_id: "t1" }), env);
    expect(res.status).toBe(200);
    const json = (await res.json()) as { access_token: string; refresh_token: string; expires_in: number };
    expect(json.refresh_token).toContain("rt_");
    expect(json.expires_in).toBe(3600);
    // token から復元した line_user_id "U" で recipient/upsert された。
    expect(mockRecipients).toHaveBeenCalledWith(env, "U");
  });
});

describe("line-select-token sign/verify", () => {
  const SECRET = "secret-32chars-padding-aaaaaaaaaa";

  it("roundtrips line_user_id / line_name", async () => {
    const t = await signSelectToken({ line_user_id: "U1", line_name: "田中" }, SECRET, 1000);
    const v = await verifySelectToken(t, SECRET, 1000);
    expect(v).toEqual({ line_user_id: "U1", line_name: "田中" });
  });

  it("rejects expired token (>600s)", async () => {
    const t = await signSelectToken({ line_user_id: "U1", line_name: "N" }, SECRET, 1000);
    expect(await verifySelectToken(t, SECRET, 1000 + 601)).toBeNull();
  });

  it("rejects tampered signature / wrong secret", async () => {
    const t = await signSelectToken({ line_user_id: "U1", line_name: "N" }, SECRET, 1000);
    expect(await verifySelectToken(t, "another-secret-padding-bbbbbbbb", 1000)).toBeNull();
    expect(await verifySelectToken(t.slice(0, -2) + "xx", SECRET, 1000)).toBeNull();
  });
});
