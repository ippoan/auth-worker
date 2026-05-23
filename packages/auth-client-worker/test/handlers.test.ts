import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleOAuthLogin, handleOAuthCallback } from "../src/handlers";
import { makeKv, fakeSecretsStoreSecret } from "./_helpers";

const OPTS = {
  authWorkerOrigin: "https://auth.ippoan.org",
  redirectUri: "https://ci-dashboard.ippoan.org/oauth/callback",
  scope: "mcp.write mcp.workflow mcp.project",
  clientName: "ci-dashboard",
};
const DCR_KEY = "auth-client-worker:dcr-client";
const TOKENS_KEY = "auth-client-worker:oauth-tokens";

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

describe("handleOAuthLogin", () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it("redirects to /mcp/authorize with PKCE params and persists state in KV", async () => {
    const { env, kv } = makeEnv();
    await kv.put(DCR_KEY, JSON.stringify({
      client_id: "dcr-1",
      redirect_uri: OPTS.redirectUri,
      issued_at_ms: Date.now(),
    }));

    const req = new Request("https://ci-dashboard.ippoan.org/oauth/login");
    const res = await handleOAuthLogin(req, env, OPTS);

    expect(res.status).toBe(302);
    const url = new URL(res.headers.get("Location")!);
    expect(url.origin + url.pathname).toBe("https://auth.ippoan.org/mcp/authorize");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe("dcr-1");
    expect(url.searchParams.get("redirect_uri")).toBe(OPTS.redirectUri);
    expect(url.searchParams.get("scope")).toBe(OPTS.scope);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]+$/);

    const state = url.searchParams.get("state")!;
    expect(state).toMatch(/^[A-Za-z0-9_-]+$/);
    const pkce = await kv.get(`auth-client-worker:oauth-pkce:${state}`, "json") as {
      code_verifier: string;
      return_to: string;
    };
    expect(pkce.code_verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(pkce.return_to).toBe("/");
  });

  it("honors ?return_to=/safe-path", async () => {
    const { env, kv } = makeEnv();
    await kv.put(DCR_KEY, JSON.stringify({
      client_id: "dcr-1", redirect_uri: OPTS.redirectUri, issued_at_ms: Date.now(),
    }));
    const req = new Request("https://ci-dashboard.ippoan.org/oauth/login?return_to=/issues");
    const res = await handleOAuthLogin(req, env, OPTS);
    const state = new URL(res.headers.get("Location")!).searchParams.get("state")!;
    const pkce = await kv.get(`auth-client-worker:oauth-pkce:${state}`, "json") as {
      return_to: string;
    };
    expect(pkce.return_to).toBe("/issues");
  });

  it("rejects open-redirect attempts in return_to → fallback to /", async () => {
    const { env, kv } = makeEnv();
    await kv.put(DCR_KEY, JSON.stringify({
      client_id: "dcr-1", redirect_uri: OPTS.redirectUri, issued_at_ms: Date.now(),
    }));
    const req = new Request("https://ci-dashboard.ippoan.org/oauth/login?return_to=https://evil.example.com/x");
    const res = await handleOAuthLogin(req, env, OPTS);
    const state = new URL(res.headers.get("Location")!).searchParams.get("state")!;
    const pkce = await kv.get(`auth-client-worker:oauth-pkce:${state}`, "json") as {
      return_to: string;
    };
    expect(pkce.return_to).toBe("/");
  });

  it("rejects protocol-relative URLs (//foo) as return_to → fallback to /", async () => {
    const { env, kv } = makeEnv();
    await kv.put(DCR_KEY, JSON.stringify({
      client_id: "dcr-1", redirect_uri: OPTS.redirectUri, issued_at_ms: Date.now(),
    }));
    const req = new Request("https://ci-dashboard.ippoan.org/oauth/login?return_to=//evil.example.com/x");
    const res = await handleOAuthLogin(req, env, OPTS);
    const state = new URL(res.headers.get("Location")!).searchParams.get("state")!;
    const pkce = await kv.get(`auth-client-worker:oauth-pkce:${state}`, "json") as {
      return_to: string;
    };
    expect(pkce.return_to).toBe("/");
  });
});

describe("handleOAuthCallback", () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it("exchanges code + verifier for tokens and persists them to KV", async () => {
    const { env, kv } = makeEnv();
    await kv.put(DCR_KEY, JSON.stringify({
      client_id: "dcr-1", redirect_uri: OPTS.redirectUri, issued_at_ms: Date.now(),
    }));
    const state = "state-abc";
    await kv.put(`auth-client-worker:oauth-pkce:${state}`, JSON.stringify({
      code_verifier: "verifier-43chars-or-more-padded-pad-pad",
      return_to: "/issues",
    }));

    const spy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({
        access_token: "access-from-callback",
        refresh_token: "refresh-from-callback",
        expires_in: 3600,
        scope: OPTS.scope,
      }),
    );

    const req = new Request(`https://ci-dashboard.ippoan.org/oauth/callback?code=auth-code&state=${state}`);
    const res = await handleOAuthCallback(req, env, OPTS);
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toContain("/issues");

    const stored = await kv.get(TOKENS_KEY, "json") as { access_token: string };
    expect(stored.access_token).toBe("access-from-callback");

    expect(await kv.get(`auth-client-worker:oauth-pkce:${state}`)).toBeNull();

    const body = spy.mock.calls[0]![1]!.body as string;
    expect(body).toContain("grant_type=authorization_code");
    expect(body).toContain("code=auth-code");
  });

  it("returns 400 on unknown state (replay / CSRF defense)", async () => {
    const { env, kv } = makeEnv();
    await kv.put(DCR_KEY, JSON.stringify({
      client_id: "dcr-1", redirect_uri: OPTS.redirectUri, issued_at_ms: Date.now(),
    }));
    const req = new Request("https://ci-dashboard.ippoan.org/oauth/callback?code=x&state=does-not-exist");
    const res = await handleOAuthCallback(req, env, OPTS);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Invalid or expired state");
  });

  it("surfaces auth-worker error params (e.g. user-denied consent)", async () => {
    const { env } = makeEnv();
    const req = new Request("https://ci-dashboard.ippoan.org/oauth/callback?error=access_denied&error_description=User%20denied");
    const res = await handleOAuthCallback(req, env, OPTS);
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(text).toContain("access_denied");
    expect(text).toContain("User denied");
  });

  it("returns 400 when code or state is missing", async () => {
    const { env } = makeEnv();
    const req = new Request("https://ci-dashboard.ippoan.org/oauth/callback?code=only-code");
    const res = await handleOAuthCallback(req, env, OPTS);
    expect(res.status).toBe(400);
  });
});
