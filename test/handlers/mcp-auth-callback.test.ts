/**
 * `handleMcpAuthCallback` (Phase 5 / #128) — Authorization Code GitHub OAuth callback test。
 *
 * device_callback と同方針で `globalThis.fetch` を stub して GitHub OAuth round-trip を
 * 模擬する。成功 case と error case (token exchange / user fetch / ACL deny) を網羅。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleMcpAuthCallback } from "../../src/handlers/mcp-auth-callback";
import { putAuthRequest, type AuthRequestRecord } from "../../src/lib/mcp-authcode";
import { generateOAuthState } from "../../src/lib/security";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth.test.example";
const TEST_OAUTH_STATE_SECRET = "test-oauth-state-secret-32chars!";
const TEST_SSO_KEY = "test-sso-encryption-key-material!";

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    GITHUB_MCP_CLIENT_ID: "Iv1.test-github-client",
    GITHUB_MCP_CLIENT_SECRET: "test-github-client-secret",
    OAUTH_STATE_SECRET: TEST_OAUTH_STATE_SECRET,
    SSO_ENCRYPTION_KEY: TEST_SSO_KEY,
    GITHUB_MCP_USER_ALLOWLIST: '["alice"]',
    ...overrides,
  });
  return { env, kv };
}

async function seedAuthRequest(env: Env, id = "ar-1"): Promise<AuthRequestRecord> {
  const rec: AuthRequestRecord = {
    id,
    client_id: "c-1",
    redirect_uri: "https://claude.ai/cb",
    code_challenge: "abc",
    code_challenge_method: "S256",
    client_state: "csrf-1",
    scope: "mcp.read",
    expires_at: Date.now() + 60_000,
  };
  await putAuthRequest(env, rec);
  return rec;
}

async function buildState(authReqId: string): Promise<string> {
  return generateOAuthState(`${ISSUER}/mcp/auth_callback`, TEST_OAUTH_STATE_SECRET, {
    provider: "github_mcp_authcode",
    auth_request_id: authReqId,
  });
}

function callbackReq(opts: { code?: string; state?: string; error?: string }): Request {
  const u = new URL(`${ISSUER}/mcp/auth_callback`);
  if (opts.code !== undefined) u.searchParams.set("code", opts.code);
  if (opts.state !== undefined) u.searchParams.set("state", opts.state);
  if (opts.error !== undefined) u.searchParams.set("error", opts.error);
  return new Request(u.toString());
}

function jsonResp(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("handleMcpAuthCallback — env / state / request guards", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("503 when MCP_OAUTH_KV not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined, AUTH_WORKER_ORIGIN: ISSUER });
    const res = await handleMcpAuthCallback(callbackReq({}), env);
    expect(res.status).toBe(503);
  });

  it("503 when GITHUB_MCP_CLIENT_ID missing", async () => {
    const { env } = envWithKv({ GITHUB_MCP_CLIENT_ID: undefined });
    const res = await handleMcpAuthCallback(callbackReq({}), env);
    expect(res.status).toBe(503);
  });

  it("503 when GITHUB_MCP_CLIENT_SECRET missing", async () => {
    const { env } = envWithKv({ GITHUB_MCP_CLIENT_SECRET: undefined });
    const res = await handleMcpAuthCallback(callbackReq({}), env);
    expect(res.status).toBe(503);
  });

  it("503 when SSO_ENCRYPTION_KEY missing", async () => {
    const { env } = envWithKv({ SSO_ENCRYPTION_KEY: "" });
    const res = await handleMcpAuthCallback(callbackReq({}), env);
    expect(res.status).toBe(503);
  });

  it("503 when OAUTH_STATE_SECRET missing", async () => {
    const { env } = envWithKv({ OAUTH_STATE_SECRET: "" });
    const res = await handleMcpAuthCallback(callbackReq({}), env);
    expect(res.status).toBe(503);
  });

  it("503 when AUTH_WORKER_ORIGIN missing", async () => {
    const { env } = envWithKv({ AUTH_WORKER_ORIGIN: "" });
    const res = await handleMcpAuthCallback(callbackReq({}), env);
    expect(res.status).toBe(503);
  });

  it("400 when state missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpAuthCallback(callbackReq({}), env);
    expect(res.status).toBe(400);
  });

  it("400 when state HMAC invalid", async () => {
    const { env } = envWithKv();
    const res = await handleMcpAuthCallback(callbackReq({ state: "bad.state" }), env);
    expect(res.status).toBe(400);
  });

  it("400 when state has wrong provider", async () => {
    const { env } = envWithKv();
    const wrong = await generateOAuthState(`${ISSUER}/mcp/auth_callback`, TEST_OAUTH_STATE_SECRET, {
      provider: "github_mcp",
      device_code: "dc",
    });
    const res = await handleMcpAuthCallback(callbackReq({ state: wrong }), env);
    expect(res.status).toBe(400);
  });

  it("400 when auth request not found", async () => {
    const { env } = envWithKv();
    const state = await buildState("missing");
    const res = await handleMcpAuthCallback(callbackReq({ state }), env);
    expect(res.status).toBe(400);
  });

  it("400 when state valid but no code (and no error)", async () => {
    const { env } = envWithKv();
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallback(callbackReq({ state }), env);
    expect(res.status).toBe(400);
  });
});

describe("handleMcpAuthCallback — GitHub user cancelled", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("redirects with error=access_denied to client redirect_uri", async () => {
    const { env } = envWithKv();
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallback(
      callbackReq({ state, error: "access_denied" }),
      env,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.origin).toBe("https://claude.ai");
    expect(loc.searchParams.get("error")).toBe("access_denied");
    expect(loc.searchParams.get("state")).toBe("csrf-1");
  });
});

describe("handleMcpAuthCallback — GitHub fetch error paths", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("redirects with server_error when GitHub token exchange fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response("err", { status: 500 })));
    const { env } = envWithKv();
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallback(callbackReq({ state, code: "ghc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("server_error");
  });

  it("redirects with server_error when token response has no access_token", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(jsonResp({ error: "bad_verification_code" })),
    );
    const { env } = envWithKv();
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallback(callbackReq({ state, code: "ghc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("server_error");
  });

  it("redirects with server_error when GitHub user fetch fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockResolvedValueOnce(new Response("err", { status: 500 })),
    );
    const { env } = envWithKv();
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallback(callbackReq({ state, code: "ghc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("server_error");
  });

  it("redirects with server_error when GitHub user has no login field", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockResolvedValueOnce(jsonResp({})),
    );
    const { env } = envWithKv();
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallback(callbackReq({ state, code: "ghc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("server_error");
  });
});

describe("handleMcpAuthCallback — ACL deny (parseAllowlist edge cases)", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  async function expectDenyForAllowlist(allowlist: string | undefined): Promise<void> {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockResolvedValueOnce(jsonResp({ login: "alice" })),
    );
    const { env } = envWithKv({ GITHUB_MCP_USER_ALLOWLIST: allowlist });
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallback(callbackReq({ state, code: "ghc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("access_denied");
  }

  it("redirects with access_denied when github_login not in allowlist", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockResolvedValueOnce(jsonResp({ login: "intruder" })),
    );
    const { env } = envWithKv({ GITHUB_MCP_USER_ALLOWLIST: '["alice"]' });
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallback(callbackReq({ state, code: "ghc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("access_denied");
  });

  it("denies all when GITHUB_MCP_USER_ALLOWLIST is undefined (fail-closed)", async () => {
    await expectDenyForAllowlist(undefined);
  });

  it("denies all when GITHUB_MCP_USER_ALLOWLIST is JSON but not an array", async () => {
    await expectDenyForAllowlist('{"alice": true}');
  });

  it("denies all when GITHUB_MCP_USER_ALLOWLIST is malformed JSON", async () => {
    await expectDenyForAllowlist("{not json");
  });

  it("denies all when GITHUB_MCP_USER_ALLOWLIST array contains non-string", async () => {
    await expectDenyForAllowlist('["alice", 42]');
  });
});

describe("handleMcpAuthCallback — success", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("issues auth code, stores github_token, redirects with code+state", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat-success" }))
        .mockResolvedValueOnce(jsonResp({ login: "alice" })),
    );
    const { env, kv } = envWithKv();
    await seedAuthRequest(env);
    const state = await buildState("ar-1");

    const res = await handleMcpAuthCallback(callbackReq({ state, code: "ghc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.origin).toBe("https://claude.ai");
    expect(loc.searchParams.get("code")).toMatch(/^[0-9a-f-]{36}$/);
    expect(loc.searchParams.get("state")).toBe("csrf-1");

    // KV: github_token:github:alice が暗号化保存、auth:code:* が 1 件、auth:request:ar-1 削除
    expect(kv._data["github_token:github:alice"]).toBeDefined();
    const codeKeys = Object.keys(kv._data).filter((k) => k.startsWith("auth:code:"));
    expect(codeKeys).toHaveLength(1);
    expect(kv._data["auth:request:ar-1"]).toBeUndefined();
  });

  // L196 (success) と L57 (redirectError) の `if (clientState)` else branch カバー
  it("redirects without state param when client_state is empty (success path)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockResolvedValueOnce(jsonResp({ login: "alice" })),
    );
    const { env } = envWithKv();
    // client_state を空にして seed
    await env.MCP_OAUTH_KV!.put(
      "auth:request:ar-empty",
      JSON.stringify({
        id: "ar-empty",
        client_id: "c-1",
        redirect_uri: "https://claude.ai/cb",
        code_challenge: "abc",
        code_challenge_method: "S256",
        client_state: "", // ← 空
        scope: "",
        expires_at: Date.now() + 60_000,
      }),
    );
    const state = await buildState("ar-empty");
    const res = await handleMcpAuthCallback(callbackReq({ state, code: "ghc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.has("state")).toBe(false);
    expect(loc.searchParams.get("code")).toMatch(/^[0-9a-f-]{36}$/);
  });

  // GH token resp が {} (error も access_token も無し) → fallback "no access_token in response"
  it("redirects with server_error when GitHub token response is empty object (?? fallback branch)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(jsonResp({})), // error も access_token も無い
    );
    const { env } = envWithKv();
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallback(callbackReq({ state, code: "ghc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("server_error");
  });

  // RFC 8707 Resource Indicator (MCP Authorization spec 2025-06-18) の伝播。
  // `/authorize` で bind した resource を AuthCodeRecord に propagate する。
  it("propagates resource from AuthRequestRecord to AuthCodeRecord", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockResolvedValueOnce(jsonResp({ login: "alice" })),
    );
    const { env, kv } = envWithKv();
    await env.MCP_OAUTH_KV!.put(
      "auth:request:ar-resource",
      JSON.stringify({
        id: "ar-resource",
        client_id: "c-1",
        redirect_uri: "https://claude.ai/cb",
        code_challenge: "abc",
        code_challenge_method: "S256",
        client_state: "csrf-1",
        scope: "mcp.read",
        resource: "https://mcp.test.example",
        expires_at: Date.now() + 60_000,
      }),
    );
    const state = await buildState("ar-resource");
    const res = await handleMcpAuthCallback(callbackReq({ state, code: "ghc" }), env);
    expect(res.status).toBe(302);
    const codeKey = Object.keys(kv._data).find((k) => k.startsWith("auth:code:"))!;
    const codeRec = JSON.parse(kv._data[codeKey]!) as { resource?: string };
    expect(codeRec.resource).toBe("https://mcp.test.example");
  });

  // redirectError 内 `if (clientState)` else branch (error path で client_state 空)
  it("redirects with error params but no state when client_state is empty (error path)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("err", { status: 500 })),
    );
    const { env } = envWithKv();
    await env.MCP_OAUTH_KV!.put(
      "auth:request:ar-empty-err",
      JSON.stringify({
        id: "ar-empty-err",
        client_id: "c-1",
        redirect_uri: "https://claude.ai/cb",
        code_challenge: "abc",
        code_challenge_method: "S256",
        client_state: "",
        scope: "",
        expires_at: Date.now() + 60_000,
      }),
    );
    const state = await buildState("ar-empty-err");
    const res = await handleMcpAuthCallback(callbackReq({ state, code: "ghc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("server_error");
    expect(loc.searchParams.has("state")).toBe(false);
  });
});

// RFC 9207 (issue #449): callback の redirect back (成功・error 両方) に `iss` を載せる。
describe("handleMcpAuthCallback — RFC 9207 iss parameter (issue #449)", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("success redirect carries iss recorded on the AuthRequestRecord", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockResolvedValueOnce(jsonResp({ login: "alice" })),
    );
    const { env } = envWithKv();
    await env.MCP_OAUTH_KV!.put(
      "auth:request:ar-iss",
      JSON.stringify({
        id: "ar-iss",
        client_id: "c-1",
        redirect_uri: "https://claude.ai/cb",
        code_challenge: "abc",
        code_challenge_method: "S256",
        client_state: "csrf-1",
        scope: "",
        iss: "https://auth.test.example",
        expires_at: Date.now() + 60_000,
      }),
    );
    const state = await buildState("ar-iss");
    const res = await handleMcpAuthCallback(callbackReq({ state, code: "ghc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("iss")).toBe("https://auth.test.example");
  });

  it("falls back to AUTH_WORKER_ORIGIN for legacy records without iss (success path)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockResolvedValueOnce(jsonResp({ login: "alice" })),
    );
    const { env } = envWithKv();
    await seedAuthRequest(env); // iss を記録しない旧 record
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallback(callbackReq({ state, code: "ghc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("iss")).toBe(ISSUER);
  });

  it("error redirect (user cancelled) also carries iss", async () => {
    const { env } = envWithKv();
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallback(callbackReq({ state, error: "access_denied" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("access_denied");
    expect(loc.searchParams.get("iss")).toBe(ISSUER);
  });
});
