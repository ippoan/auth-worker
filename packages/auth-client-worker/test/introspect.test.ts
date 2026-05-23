import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { getGitHubToken } from "../src/introspect";
import { makeKv, fakeSecretsStoreSecret } from "./_helpers";

const DCR_KEY = "auth-client-worker:dcr-client";
const TOKENS_KEY = "auth-client-worker:oauth-tokens";
const GH_TOKEN_KEY = "auth-client-worker:gh-token";

function makeEnv() {
  const kv = makeKv();
  return {
    env: {
      CI_STATUS: kv,
      INTERNAL_SHARED_SECRET: fakeSecretsStoreSecret("test-internal"),
    },
    kv,
  };
}

async function seedDcr(kv: KVNamespace) {
  await kv.put(DCR_KEY, JSON.stringify({
    client_id: "dcr-1",
    redirect_uri: "https://ci-dashboard.ippoan.org/oauth/callback",
    issued_at_ms: Date.now(),
  }));
}

async function seedTokens(kv: KVNamespace, overrides: Partial<{ access_expires_at_ms: number }> = {}) {
  await kv.put(TOKENS_KEY, JSON.stringify({
    access_token: "stored-access",
    refresh_token: "stored-refresh",
    access_expires_at_ms: overrides.access_expires_at_ms ?? Date.now() + 30 * 60_000,
  }));
}

describe("getGitHubToken", () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it("returns the cached github_token when fresh (no introspect roundtrip)", async () => {
    const { env, kv } = makeEnv();
    await kv.put(GH_TOKEN_KEY, JSON.stringify({
      token: "ghs_cached",
      expires_at_ms: Date.now() + 30 * 60_000,
    }));
    const spy = vi.spyOn(globalThis, "fetch");

    expect(await getGitHubToken(env)).toBe("ghs_cached");
    expect(spy).not.toHaveBeenCalled();
  });

  it("throws clearly when no DCR client has been registered yet", async () => {
    const { env, kv } = makeEnv();
    await seedTokens(kv);
    await expect(getGitHubToken(env))
      .rejects.toThrow(/No DCR client registered.*\/oauth\/login/);
  });

  it("calls /mcp/introspect with the stored access_token and caches the result", async () => {
    const { env, kv } = makeEnv();
    await seedDcr(kv);
    await seedTokens(kv);
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({
        active: true,
        github_token: "ghs_from_introspect",
        github_login: "yhonda-ohishi",
        exp,
        scope: "mcp.write",
      }),
    );

    expect(await getGitHubToken(env)).toBe("ghs_from_introspect");

    const call = spy.mock.calls[0]!;
    expect(call[0]).toBe("https://auth.ippoan.org/mcp/introspect");
    const init = call[1] as RequestInit;
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).Authorization).toBe("test-internal");
    expect(init.body).toContain("stored-access");

    const cached = await kv.get(GH_TOKEN_KEY, "json") as { token: string };
    expect(cached.token).toBe("ghs_from_introspect");
  });

  it("throws with a clear message when auth-worker reports active:false", async () => {
    const { env, kv } = makeEnv();
    await seedDcr(kv);
    await seedTokens(kv);
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({ active: false, error: "token_expired" }),
    );

    await expect(getGitHubToken(env))
      .rejects.toThrow(/JWT inactive.*token_expired.*\/oauth\/login/);
  });

  it("surfaces /mcp/introspect HTTP errors verbosely (e.g. server_error 503)", async () => {
    const { env, kv } = makeEnv();
    await seedDcr(kv);
    await seedTokens(kv);
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("server_error", { status: 503 }),
    );

    await expect(getGitHubToken(env))
      .rejects.toThrow(/\/mcp\/introspect failed \(503\).*server_error/);
  });
});
