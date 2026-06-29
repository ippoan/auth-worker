import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/lib/secret", () => ({ resolveSecret: vi.fn() }));
vi.mock("../../src/lib/jwt", () => ({ verifyJwt: vi.fn() }));
vi.mock("../../src/lib/oidc", () => ({ mintGoogleIdToken: vi.fn() }));

import { alcOidcToken, alcIdentityHeaders } from "../../src/lib/alc-data-fetch";
import { resolveSecret } from "../../src/lib/secret";
import { verifyJwt } from "../../src/lib/jwt";
import { mintGoogleIdToken } from "../../src/lib/oidc";

const mResolve = resolveSecret as unknown as ReturnType<typeof vi.fn>;
const mVerify = verifyJwt as unknown as ReturnType<typeof vi.fn>;
const mMint = mintGoogleIdToken as unknown as ReturnType<typeof vi.fn>;

// 必要 field だけ持つ最小 env (resolveSecret は mock なので binding 値は素通り)。
const env = {
  ALC_API_PROXY_SA_KEY: "sa-binding",
  JWT_SECRET: "jwt-binding",
  ALC_API_ORIGIN: "https://alc-api.ippoan.org",
  WORKER_ENV: "prod",
} as unknown as Parameters<typeof alcOidcToken>[0];

beforeEach(() => {
  vi.clearAllMocks();
});

describe("alcOidcToken", () => {
  it("mints OIDC for aud=ALC_API_ORIGIN when SA key present", async () => {
    mResolve.mockResolvedValue("sa-json");
    mMint.mockResolvedValue("oidc-tok");
    const tok = await alcOidcToken(env);
    expect(tok).toBe("oidc-tok");
    expect(mMint).toHaveBeenCalledWith("sa-json", "https://alc-api.ippoan.org");
  });

  it("returns null when SA key binding unresolved", async () => {
    mResolve.mockResolvedValue(null);
    expect(await alcOidcToken(env)).toBeNull();
    expect(mMint).not.toHaveBeenCalled();
  });

  it("returns null when ALC_API_ORIGIN missing", async () => {
    mResolve.mockResolvedValue("sa-json");
    const e2 = { ...env, ALC_API_ORIGIN: "" } as typeof env;
    expect(await alcOidcToken(e2)).toBeNull();
  });

  it("returns null when mint throws", async () => {
    mResolve.mockResolvedValue("sa-json");
    mMint.mockRejectedValue(new Error("token endpoint 500"));
    expect(await alcOidcToken(env)).toBeNull();
  });
});

describe("alcIdentityHeaders", () => {
  it("injects OIDC + X-Tenant-ID + X-User-* from verified JWT", async () => {
    mResolve.mockResolvedValue("secret"); // jwtSecret then saKey 共に non-null
    mVerify.mockResolvedValue({
      tenant_id: "t1",
      sub: "u1",
      email: "a@b.c",
      role: "admin",
    });
    mMint.mockResolvedValue("oidc-tok");
    const h = await alcIdentityHeaders(env, "browser-jwt");
    expect(h).toEqual({
      Authorization: "Bearer oidc-tok",
      "X-Tenant-ID": "t1",
      "X-User-ID": "u1",
      "X-User-Email": "a@b.c",
      "X-User-Role": "admin",
    });
  });

  it("falls back to org claim for tenant and omits absent X-User-*", async () => {
    mResolve.mockResolvedValue("secret");
    mVerify.mockResolvedValue({ org: "t2" });
    mMint.mockResolvedValue("oidc-tok");
    const h = await alcIdentityHeaders(env, "browser-jwt");
    expect(h).toEqual({ Authorization: "Bearer oidc-tok", "X-Tenant-ID": "t2" });
  });

  it("returns null when jwtSecret unresolved", async () => {
    mResolve.mockResolvedValue(null);
    expect(await alcIdentityHeaders(env, "browser-jwt")).toBeNull();
    expect(mVerify).not.toHaveBeenCalled();
  });

  it("returns null when JWT verification fails", async () => {
    mResolve.mockResolvedValue("secret");
    mVerify.mockResolvedValue(null);
    expect(await alcIdentityHeaders(env, "bad")).toBeNull();
  });

  it("returns null when OIDC mint unavailable", async () => {
    // jwtSecret resolve → non-null, then saKey resolve → null (mint 不可)
    mResolve.mockResolvedValueOnce("secret").mockResolvedValueOnce(null);
    mVerify.mockResolvedValue({ tenant_id: "t1", sub: "u1" });
    expect(await alcIdentityHeaders(env, "browser-jwt")).toBeNull();
  });
});
