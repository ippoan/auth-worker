/**
 * `handleMcpAuthCallbackGoogle` (MCP OAuth に Google IdP を追加) test。
 *
 * `mcp-auth-callback.test.ts` (GitHub 版) と同方針で `globalThis.fetch` を stub
 * して Google OAuth round-trip を模擬する。id_token の decode は署名検証をしない
 * (`google-callback.test.ts` の `makeIdToken` と同じ dummy JWT パターン)。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleMcpAuthCallbackGoogle } from "../../src/handlers/mcp-auth-callback-google";
import { putAuthRequest, type AuthRequestRecord } from "../../src/lib/mcp-authcode";
import { generateOAuthState } from "../../src/lib/security";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth.test.example";
const TEST_OAUTH_STATE_SECRET = "test-oauth-state-secret-32chars!";

/** Default seed for AUTH_CONFIG KV's `google-mcp-user-allowlist` key, used by
 *  every test that doesn't care about the exact allowlist contents. */
const DEFAULT_ALLOWLIST_RAW = '["alice@example.com"]';

/**
 * `allowlistRaw` seeds AUTH_CONFIG KV's `google-mcp-user-allowlist` key
 * (issue: MCP OAuth に Google IdP を追加 — KV allowlist, not Secrets Store;
 * see `src/lib/config.ts::getGoogleMcpUserAllowlist`). Pass `undefined`
 * explicitly to simulate the key being unset (fail-closed) — this parameter
 * has **no default**, since a JS default parameter also fires on an
 * explicitly-passed `undefined`, which would silently defeat that case.
 */
function envWithKv(
  overrides: Partial<Env>,
  allowlistRaw: string | undefined,
): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const authConfig = createMockKV(
    allowlistRaw !== undefined ? { "google-mcp-user-allowlist": allowlistRaw } : {},
  );
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_CONFIG: authConfig,
    AUTH_WORKER_ORIGIN: ISSUER,
    OAUTH_STATE_SECRET: TEST_OAUTH_STATE_SECRET,
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
  return generateOAuthState(`${ISSUER}/mcp/auth_callback_google`, TEST_OAUTH_STATE_SECRET, {
    provider: "google_mcp_authcode",
    auth_request_id: authReqId,
  });
}

function callbackReq(opts: { code?: string; state?: string; error?: string }): Request {
  const u = new URL(`${ISSUER}/mcp/auth_callback_google`);
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

/** base64url で JWT 形式の id_token を組む (署名はダミー — handler は decode のみ)。 */
function makeIdToken(payload: Record<string, unknown>): string {
  const b64 = (o: unknown) =>
    btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${b64({ alg: "RS256" })}.${b64(payload)}.sig`;
}

const VERIFIED_ID_TOKEN = makeIdToken({
  sub: "google-sub-1",
  email: "alice@example.com",
  email_verified: true,
});

describe("handleMcpAuthCallbackGoogle — env / state / request guards", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("503 when MCP_OAUTH_KV not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined, AUTH_WORKER_ORIGIN: ISSUER });
    const res = await handleMcpAuthCallbackGoogle(callbackReq({}), env);
    expect(res.status).toBe(503);
  });

  it("503 when GOOGLE_CLIENT_ID missing", async () => {
    const { env } = envWithKv({ GOOGLE_CLIENT_ID: undefined }, DEFAULT_ALLOWLIST_RAW);
    const res = await handleMcpAuthCallbackGoogle(callbackReq({}), env);
    expect(res.status).toBe(503);
  });

  it("503 when GOOGLE_CLIENT_SECRET missing", async () => {
    const { env } = envWithKv({ GOOGLE_CLIENT_SECRET: undefined }, DEFAULT_ALLOWLIST_RAW);
    const res = await handleMcpAuthCallbackGoogle(callbackReq({}), env);
    expect(res.status).toBe(503);
  });

  it("503 when OAUTH_STATE_SECRET missing", async () => {
    const { env } = envWithKv({ OAUTH_STATE_SECRET: "" }, DEFAULT_ALLOWLIST_RAW);
    const res = await handleMcpAuthCallbackGoogle(callbackReq({}), env);
    expect(res.status).toBe(503);
  });

  it("503 when AUTH_WORKER_ORIGIN missing", async () => {
    const { env } = envWithKv({ AUTH_WORKER_ORIGIN: "" }, DEFAULT_ALLOWLIST_RAW);
    const res = await handleMcpAuthCallbackGoogle(callbackReq({}), env);
    expect(res.status).toBe(503);
  });

  it("400 when state missing", async () => {
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
    const res = await handleMcpAuthCallbackGoogle(callbackReq({}), env);
    expect(res.status).toBe(400);
  });

  it("400 when state HMAC invalid", async () => {
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state: "bad.state" }), env);
    expect(res.status).toBe(400);
  });

  it("400 when state has wrong provider", async () => {
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
    const wrong = await generateOAuthState(
      `${ISSUER}/mcp/auth_callback_google`,
      TEST_OAUTH_STATE_SECRET,
      { provider: "github_mcp_authcode", auth_request_id: "ar-1" },
    );
    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state: wrong }), env);
    expect(res.status).toBe(400);
  });

  it("400 when auth request not found", async () => {
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
    const state = await buildState("missing");
    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state }), env);
    expect(res.status).toBe(400);
  });

  it("400 when state valid but no code (and no error)", async () => {
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state }), env);
    expect(res.status).toBe(400);
  });
});

describe("handleMcpAuthCallbackGoogle — Google user cancelled", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("redirects with error=access_denied to client redirect_uri", async () => {
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallbackGoogle(
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

describe("handleMcpAuthCallbackGoogle — Google fetch / id_token error paths", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("redirects with server_error when Google token exchange fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response("err", { status: 500 })));
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state, code: "gc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("server_error");
  });

  it("redirects with server_error when token response has no id_token", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResp({ error: "invalid_grant" })));
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state, code: "gc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("server_error");
  });

  it("redirects with server_error when token response is empty object (?? fallback branch)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResp({})));
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state, code: "gc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("server_error");
  });

  it("redirects with server_error when id_token is not decodable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(jsonResp({ id_token: "not-a-jwt" })),
    );
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state, code: "gc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("server_error");
  });

  it("redirects with server_error when email_verified is false", async () => {
    const unverified = makeIdToken({ email: "alice@example.com", email_verified: false });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResp({ id_token: unverified })));
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state, code: "gc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("server_error");
  });

  it("redirects with server_error when id_token has no email", async () => {
    const noEmail = makeIdToken({ email_verified: true });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResp({ id_token: noEmail })));
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state, code: "gc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("server_error");
  });
});

describe("handleMcpAuthCallbackGoogle — ACL deny (parseAllowlist edge cases)", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  async function expectDenyForAllowlist(allowlistRaw: string | undefined): Promise<void> {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResp({ id_token: VERIFIED_ID_TOKEN })));
    const { env } = envWithKv({}, allowlistRaw);
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state, code: "gc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("access_denied");
  }

  it("redirects with access_denied when email not in allowlist", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        jsonResp({ id_token: makeIdToken({ email: "intruder@example.com", email_verified: true }) }),
      ),
    );
    const { env } = envWithKv({}, '["alice@example.com"]');
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state, code: "gc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("access_denied");
  });

  it("denies all when google-mcp-user-allowlist KV key is unset (fail-closed)", async () => {
    await expectDenyForAllowlist(undefined);
  });

  it("denies all when google-mcp-user-allowlist is JSON but not an array", async () => {
    await expectDenyForAllowlist('{"alice@example.com": true}');
  });

  it("denies all when google-mcp-user-allowlist is malformed JSON", async () => {
    await expectDenyForAllowlist("{not json");
  });

  it("denies all when google-mcp-user-allowlist array contains non-string", async () => {
    await expectDenyForAllowlist('["alice@example.com", 42]');
  });
});

describe("handleMcpAuthCallbackGoogle — success", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("issues auth code with email, does NOT store a github_token, redirects with code+state", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResp({ id_token: VERIFIED_ID_TOKEN })));
    const { env, kv } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
    await seedAuthRequest(env);
    const state = await buildState("ar-1");

    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state, code: "gc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.origin).toBe("https://claude.ai");
    expect(loc.searchParams.get("code")).toMatch(/^[0-9a-f-]{36}$/);
    expect(loc.searchParams.get("state")).toBe("csrf-1");

    // KV: github_token:* は一切書かれない、auth:code:* が 1 件で email を保持、
    // auth:request:ar-1 は削除される。
    const githubTokenKeys = Object.keys(kv._data).filter((k) => k.startsWith("github_token:"));
    expect(githubTokenKeys).toHaveLength(0);
    const codeKeys = Object.keys(kv._data).filter((k) => k.startsWith("auth:code:"));
    expect(codeKeys).toHaveLength(1);
    const codeRec = JSON.parse(kv._data[codeKeys[0]!]!) as { email?: string; github_login?: string };
    expect(codeRec.email).toBe("alice@example.com");
    expect(codeRec.github_login).toBeUndefined();
    expect(kv._data["auth:request:ar-1"]).toBeUndefined();
  });

  // email は小文字正規化する
  it("normalizes email to lowercase before ACL check and storage", async () => {
    const mixedCaseToken = makeIdToken({ email: "Alice@Example.com", email_verified: true });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResp({ id_token: mixedCaseToken })));
    const { env, kv } = envWithKv({}, '["alice@example.com"]');
    await seedAuthRequest(env);
    const state = await buildState("ar-1");

    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state, code: "gc" }), env);
    expect(res.status).toBe(302);
    const codeKeys = Object.keys(kv._data).filter((k) => k.startsWith("auth:code:"));
    const codeRec = JSON.parse(kv._data[codeKeys[0]!]!) as { email?: string };
    expect(codeRec.email).toBe("alice@example.com");
  });

  // L196 (success) と L57 (redirectError) の `if (clientState)` else branch カバー
  it("redirects without state param when client_state is empty (success path)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResp({ id_token: VERIFIED_ID_TOKEN })));
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
    await env.MCP_OAUTH_KV!.put(
      "auth:request:ar-empty",
      JSON.stringify({
        id: "ar-empty",
        client_id: "c-1",
        redirect_uri: "https://claude.ai/cb",
        code_challenge: "abc",
        code_challenge_method: "S256",
        client_state: "",
        scope: "",
        expires_at: Date.now() + 60_000,
      }),
    );
    const state = await buildState("ar-empty");
    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state, code: "gc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.has("state")).toBe(false);
    expect(loc.searchParams.get("code")).toMatch(/^[0-9a-f-]{36}$/);
  });

  // RFC 8707 Resource Indicator の伝播。
  it("propagates resource from AuthRequestRecord to AuthCodeRecord", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResp({ id_token: VERIFIED_ID_TOKEN })));
    const { env, kv } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
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
        resource: "https://kyuyo-mcp.test.example",
        expires_at: Date.now() + 60_000,
      }),
    );
    const state = await buildState("ar-resource");
    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state, code: "gc" }), env);
    expect(res.status).toBe(302);
    const codeKey = Object.keys(kv._data).find((k) => k.startsWith("auth:code:"))!;
    const codeRec = JSON.parse(kv._data[codeKey]!) as { resource?: string };
    expect(codeRec.resource).toBe("https://kyuyo-mcp.test.example");
  });

  // redirectError 内 `if (clientState)` else branch (error path で client_state 空)
  it("redirects with error params but no state when client_state is empty (error path)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response("err", { status: 500 })));
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
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
    const res = await handleMcpAuthCallbackGoogle(callbackReq({ state, code: "gc" }), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("error")).toBe("server_error");
    expect(loc.searchParams.has("state")).toBe(false);
  });
});

// RFC 9207 (issue #449): Google callback も redirect back に `iss` を載せる。
// Google IdP surface (issue #438) 発の record は iss = <origin>/mcp/google。
describe("handleMcpAuthCallbackGoogle — RFC 9207 iss parameter (issue #449)", () => {
  it("error redirect carries the surface iss recorded on the AuthRequestRecord", async () => {
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
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
        iss: `${ISSUER}/mcp/google`,
        expires_at: Date.now() + 60_000,
      }),
    );
    const state = await buildState("ar-iss");
    const res = await handleMcpAuthCallbackGoogle(
      callbackReq({ state, error: "access_denied" }),
      env,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("iss")).toBe(`${ISSUER}/mcp/google`);
  });

  it("falls back to AUTH_WORKER_ORIGIN for legacy records without iss", async () => {
    const { env } = envWithKv({}, DEFAULT_ALLOWLIST_RAW);
    await seedAuthRequest(env);
    const state = await buildState("ar-1");
    const res = await handleMcpAuthCallbackGoogle(
      callbackReq({ state, error: "access_denied" }),
      env,
    );
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("iss")).toBe(ISSUER);
  });
});
