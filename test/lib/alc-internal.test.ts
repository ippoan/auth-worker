import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("../../src/lib/internal-jwt", () => ({
  signInternalJWT: vi.fn(async () => "hs256-internal-jwt"),
}));
vi.mock("../../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async (_saKey: unknown, aud: string) => `oidc-token:${aud}`),
}));

import { internalAuthToken, resolveActiveDeviceTenant } from "../../src/lib/alc-internal";
import { signInternalJWT } from "../../src/lib/internal-jwt";
import { mintGoogleIdToken } from "../../src/lib/oidc";
import type { Env } from "../../src/index";

function env(overrides: Record<string, unknown> = {}): Env {
  return { ALC_API_ORIGIN: "https://alc-api.test", ...overrides } as unknown as Env;
}

const originalFetch = globalThis.fetch;

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

describe("resolveActiveDeviceTenant (Refs #544)", () => {
  beforeEach(() => vi.clearAllMocks());
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("200 + tenant_id で ok", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        expect(url).toBe("https://alc-api.test/api/internal/devices/dev-1/pairing-tenant");
        return new Response(JSON.stringify({ tenant_id: "tenant-9" }), { status: 200 });
      }),
    );
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: true, tenantId: "tenant-9" });
  });

  it("device_id を path に URL-encode する", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ tenant_id: "t" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await resolveActiveDeviceTenant(env(), "a/b c");
    expect(fetchMock).toHaveBeenCalledWith(
      "https://alc-api.test/api/internal/devices/a%2Fb%20c/pairing-tenant",
      expect.anything(),
    );
  });

  it("404 は not_found", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 404 })));
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: false, reason: "not_found" });
  });

  it("401 は unavailable (SA key 未設定で HS256 に落ちた場合の rust 401 を含む)", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 401 })));
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: false, reason: "unavailable" });
  });

  it("5xx は unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 500 })));
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: false, reason: "unavailable" });
  });

  it("200 だが JSON 不正は unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{not json", { status: 200 })));
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: false, reason: "unavailable" });
  });

  it("200 だが tenant_id 欠落は unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({}), { status: 200 })));
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: false, reason: "unavailable" });
  });

  it("200 だが tenant_id が空文字は unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ tenant_id: "" }), { status: 200 })),
    );
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: false, reason: "unavailable" });
  });

  it("fetch の例外は unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );
    const res = await resolveActiveDeviceTenant(env(), "dev-1");
    expect(res).toEqual({ ok: false, reason: "unavailable" });
  });
});
