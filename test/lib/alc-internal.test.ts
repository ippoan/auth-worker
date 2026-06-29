import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/lib/internal-jwt", () => ({
  signInternalJWT: vi.fn(async () => "hs256-internal-jwt"),
}));
vi.mock("../../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async (_saKey: unknown, aud: string) => `oidc-token:${aud}`),
}));

import { internalAuthToken } from "../../src/lib/alc-internal";
import { signInternalJWT } from "../../src/lib/internal-jwt";
import { mintGoogleIdToken } from "../../src/lib/oidc";
import type { Env } from "../../src/index";

function env(overrides: Record<string, unknown> = {}): Env {
  return { ALC_API_ORIGIN: "https://alc-api.test", ...overrides } as unknown as Env;
}

describe("internalAuthToken (rust-alc-api#434 lockdown cutover)", () => {
  beforeEach(() => vi.clearAllMocks());

  it("flag 未設定は HS256 internal JWT (非破壊)", async () => {
    const tok = await internalAuthToken(env({ ALC_API_PROXY_SA_KEY: "{}" }));
    expect(tok).toBe("hs256-internal-jwt");
    expect(signInternalJWT).toHaveBeenCalledTimes(1);
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });

  it("INTERNAL_AUTH_OIDC=1 + SA key で Google OIDC (aud=alc-api-internal) を mint", async () => {
    const tok = await internalAuthToken(env({ INTERNAL_AUTH_OIDC: "1", ALC_API_PROXY_SA_KEY: "{}" }));
    expect(tok).toBe("oidc-token:alc-api-internal");
    expect(mintGoogleIdToken).toHaveBeenCalledTimes(1);
    expect(signInternalJWT).not.toHaveBeenCalled();
  });

  it("flag=1 でも SA key 無しは HS256 に fallback (fail-safe)", async () => {
    const tok = await internalAuthToken(env({ INTERNAL_AUTH_OIDC: "1" }));
    expect(tok).toBe("hs256-internal-jwt");
    expect(signInternalJWT).toHaveBeenCalledTimes(1);
    expect(mintGoogleIdToken).not.toHaveBeenCalled();
  });
});
