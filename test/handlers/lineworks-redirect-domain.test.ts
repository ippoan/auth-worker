import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";

// 会社 (ドメイン) だけを入力させる LINE WORKS ログイン (Refs ohishi-exp/rust-leave-worker#1)。
vi.mock("../../src/lib/security", () => ({
  isAllowedRedirectUri: vi.fn(() => true),
  generateOAuthState: vi.fn(async () => "signed-state"),
}));
vi.mock("../../src/lib/alc-internal", () => ({
  resolveSsoConfig: vi.fn(),
}));

import { handleLineworksRedirect } from "../../src/handlers/lineworks-redirect";
import { resolveSsoConfig } from "../../src/lib/alc-internal";

const mockResolveSso = vi.mocked(resolveSsoConfig);

const ssoConfig = {
  tenant_id: "22222222-2222-2222-2222-222222222222",
  client_id: "client123",
  client_secret_encrypted: "enc",
  external_org_id: "example",
  woff_id: null,
};

const base =
  "https://auth.test.example/oauth/lineworks/redirect?redirect_uri=https://app1.test.example/callback";

describe("handleLineworksRedirect (domain only)", () => {
  const env = createMockEnv();
  beforeEach(() => {
    vi.clearAllMocks();
    mockResolveSso.mockResolvedValue(ssoConfig);
  });

  it("address に @ が無ければ全体をドメインとして使う", async () => {
    const res = await handleLineworksRedirect(new Request(`${base}&address=example`), env);
    expect(res.status).toBe(302);
    expect(mockResolveSso).toHaveBeenCalledWith(env, "lineworks", "example");
  });

  it("user@domain は @ より後ろをドメインにする", async () => {
    const res = await handleLineworksRedirect(
      new Request(`${base}&address=tanaka@example`),
      env,
    );
    expect(res.status).toBe(302);
    expect(mockResolveSso).toHaveBeenCalledWith(env, "lineworks", "example");
  });

  it("形の合わないドメインは 400", async () => {
    const res = await handleLineworksRedirect(
      new Request(`${base}&address=${encodeURIComponent("bad domain/../x")}`),
      env,
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid domain");
    expect(mockResolveSso).not.toHaveBeenCalled();
  });

  it("authorize URL に domain が付き、前回の会社 cookie が host-only で張られる", async () => {
    const res = await handleLineworksRedirect(new Request(`${base}&address=example`), env);
    const loc = res.headers.get("Location")!;
    expect(new URL(loc).searchParams.get("domain")).toBe("example");
    const setCookie = res.headers.get("Set-Cookie")!;
    expect(setCookie).toContain("lw_last_domain=example");
    expect(setCookie).toContain("Path=/");
    expect(setCookie).toContain("Max-Age=31536000");
    expect(setCookie).toContain("Secure");
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Lax");
    expect(setCookie).not.toContain("Domain=");
  });

  it("SSO 設定が無ければ cookie は張らない", async () => {
    mockResolveSso.mockResolvedValue(null);
    const res = await handleLineworksRedirect(new Request(`${base}&address=example`), env);
    expect(res.status).toBe(404);
    expect(res.headers.get("Set-Cookie")).toBeNull();
  });
});
