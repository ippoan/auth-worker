import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv } from "../helpers/mock-env";
import { makeJwt } from "../helpers/live-env";
import { TEST_JWT_SECRET } from "../helpers/mock-env";

// OIDC mint は別ユニット (lib/oidc.test) でテスト済み。ここでは handler の
// flow (auth → SA key 有無 → mint 成否 → overall/status) を固定する。
vi.mock("../../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(),
}));
import { mintGoogleIdToken } from "../../src/lib/oidc";
import { handleHealthWif } from "../../src/handlers/health-wif";

function req(token?: string | null): Request {
  const headers: Record<string, string> = {};
  const t = token === undefined ? makeJwt(TEST_JWT_SECRET) : token;
  if (t) headers["Authorization"] = `Bearer ${t}`;
  return new Request("https://auth.test.example/health/wif", { headers });
}

function env(overrides: Record<string, unknown> = {}) {
  return createMockEnv({
    ALC_API_PROXY_SA_KEY: "{}", // resolveSecret が非空を返せばよい (oidc は mock)
    ...overrides,
  });
}

describe("handleHealthWif (rust-alc-api#434 step 3, WIF/OIDC mint 死活)", () => {
  beforeEach(() => vi.clearAllMocks());

  it("JWT_SECRET 未設定は 503", async () => {
    const res = await handleHealthWif(req(), env({ JWT_SECRET: undefined }));
    expect(res.status).toBe(503);
  });

  it("Bearer 無しは 401", async () => {
    const res = await handleHealthWif(req(null), env());
    expect(res.status).toBe(401);
  });

  it("署名不正な token は 401", async () => {
    const res = await handleHealthWif(req(makeJwt("wrong-secret")), env());
    expect(res.status).toBe(401);
  });

  it("SA key 未設定は skip (configured:false, overall=unknown, 200)", async () => {
    const res = await handleHealthWif(req(), env({ ALC_API_PROXY_SA_KEY: undefined }));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { overall: string; oidc_mint: { configured: boolean } };
    expect(body.overall).toBe("unknown");
    expect(body.oidc_mint.configured).toBe(false);
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });

  it("mint 成功は ok (overall=ok, 200)。token 値は出さない", async () => {
    vi.mocked(mintGoogleIdToken).mockResolvedValue("secret-id-token-value");
    const res = await handleHealthWif(req(), env());
    expect(res.status).toBe(200);
    const text = await res.text();
    const body = JSON.parse(text) as {
      overall: string;
      oidc_mint: { ok: boolean; audience: string };
    };
    expect(body.overall).toBe("ok");
    expect(body.oidc_mint.ok).toBe(true);
    expect(body.oidc_mint.audience).toBe("https://alc-api.test.example");
    // mint した id_token そのものは response に絶対出さない
    expect(text).not.toContain("secret-id-token-value");
    // noCache: true でフル経路を毎回走らせる
    expect(mintGoogleIdToken).toHaveBeenCalledWith(
      "{}",
      "https://alc-api.test.example",
      expect.objectContaining({ noCache: true }),
    );
  });

  it("mint 失敗は degraded (overall=degraded, 503) + hint", async () => {
    vi.mocked(mintGoogleIdToken).mockRejectedValue(
      new Error("mintGoogleIdToken: token endpoint 401"),
    );
    const res = await handleHealthWif(req(), env());
    expect(res.status).toBe(503);
    const body = (await res.json()) as {
      overall: string;
      oidc_mint: { ok: boolean; hint: string };
    };
    expect(body.overall).toBe("degraded");
    expect(body.oidc_mint.ok).toBe(false);
    expect(body.oidc_mint.hint).toContain("token endpoint 401");
  });

  it("SA key 有りだが ALC_API_ORIGIN 欠落は unknown (200)", async () => {
    const res = await handleHealthWif(req(), env({ ALC_API_ORIGIN: undefined }));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { overall: string; oidc_mint: Record<string, unknown> };
    expect(body.overall).toBe("unknown");
    expect(body.oidc_mint.unknown).toBe(true);
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });
});
