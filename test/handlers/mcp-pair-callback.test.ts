/**
 * `handleMcpPairCallback` (issue #144) — `GET /mcp/pair_callback?code&state` テスト。
 * GitHub OAuth round-trip を `globalThis.fetch` stub で模擬。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleMcpPairCallback } from "../../src/handlers/mcp-pair-callback";
import {
  PAIR_SESSION_COOKIE_NAME,
  verifyPairSession,
} from "../../src/lib/mcp-session";
import { generateOAuthState } from "../../src/lib/security";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth.test.example";
const STATE_SECRET = "test-oauth-state-secret-32chars!";
const SESSION_SECRET = "test-session-cookie-secret-32!!!!";

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    GITHUB_MCP_CLIENT_ID: "Iv1.test",
    GITHUB_MCP_CLIENT_SECRET: "ghs_test",
    OAUTH_STATE_SECRET: STATE_SECRET,
    SESSION_COOKIE_SECRET: SESSION_SECRET,
    GITHUB_MCP_USER_ALLOWLIST: '["alice"]',
    ...overrides,
  });
  return { env, kv };
}

async function buildState(pair_code: string): Promise<string> {
  return generateOAuthState(`${ISSUER}/mcp/pair_callback`, STATE_SECRET, {
    provider: "github_mcp_pair",
    pair_code,
  });
}

function req(opts: { code?: string; state?: string; error?: string }): Request {
  const u = new URL(`${ISSUER}/mcp/pair_callback`);
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

describe("handleMcpPairCallback — env guards", () => {
  it.each([
    ["MCP_OAUTH_KV", { MCP_OAUTH_KV: undefined as unknown as undefined }],
    ["GITHUB_MCP_CLIENT_ID", { GITHUB_MCP_CLIENT_ID: undefined }],
    ["GITHUB_MCP_CLIENT_SECRET", { GITHUB_MCP_CLIENT_SECRET: undefined }],
    ["OAUTH_STATE_SECRET", { OAUTH_STATE_SECRET: "" }],
    ["SESSION_COOKIE_SECRET", { SESSION_COOKIE_SECRET: "" }],
    ["AUTH_WORKER_ORIGIN", { AUTH_WORKER_ORIGIN: "" }],
  ])("503 when %s missing", async (_label, overrides) => {
    const { env } = envWithKv(overrides as Partial<Env>);
    const res = await handleMcpPairCallback(req({}), env);
    expect(res.status).toBe(503);
  });
});

describe("handleMcpPairCallback — state / request validation", () => {
  it("400 when state missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpPairCallback(req({}), env);
    expect(res.status).toBe(400);
  });

  it("400 when state HMAC invalid", async () => {
    const { env } = envWithKv();
    const res = await handleMcpPairCallback(req({ state: "bad.state" }), env);
    expect(res.status).toBe(400);
  });

  it("400 when state has wrong provider", async () => {
    const { env } = envWithKv();
    const wrong = await generateOAuthState(`${ISSUER}/mcp/pair_callback`, STATE_SECRET, {
      provider: "github_mcp",
      device_code: "dc",
    });
    const res = await handleMcpPairCallback(req({ state: wrong }), env);
    expect(res.status).toBe(400);
  });

  it("400 when state lacks pair_code", async () => {
    const { env } = envWithKv();
    // provider 一致だが pair_code 無し
    const wrong = await generateOAuthState(`${ISSUER}/mcp/pair_callback`, STATE_SECRET, {
      provider: "github_mcp_pair",
    });
    const res = await handleMcpPairCallback(req({ state: wrong }), env);
    expect(res.status).toBe(400);
  });

  it("400 when github error=access_denied", async () => {
    const { env } = envWithKv();
    const state = await buildState("PC1");
    const res = await handleMcpPairCallback(req({ state, error: "access_denied" }), env);
    expect(res.status).toBe(400);
  });

  it("400 when no code and no error", async () => {
    const { env } = envWithKv();
    const state = await buildState("PC1");
    const res = await handleMcpPairCallback(req({ state }), env);
    expect(res.status).toBe(400);
  });
});

describe("handleMcpPairCallback — GitHub fetch error paths", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("502 when GitHub token exchange returns non-OK", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response("err", { status: 500 })));
    const { env } = envWithKv();
    const state = await buildState("PC1");
    const res = await handleMcpPairCallback(req({ state, code: "ghc" }), env);
    expect(res.status).toBe(502);
  });

  it("502 when token response has no access_token", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(jsonResp({ error: "bad_verification_code" })),
    );
    const { env } = envWithKv();
    const state = await buildState("PC1");
    const res = await handleMcpPairCallback(req({ state, code: "ghc" }), env);
    expect(res.status).toBe(502);
  });

  it("502 when token response is empty object (?? fallback branch)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResp({})));
    const { env } = envWithKv();
    const state = await buildState("PC1");
    const res = await handleMcpPairCallback(req({ state, code: "ghc" }), env);
    expect(res.status).toBe(502);
  });

  it("502 when GitHub /user fetch fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockResolvedValueOnce(new Response("err", { status: 500 })),
    );
    const { env } = envWithKv();
    const state = await buildState("PC1");
    const res = await handleMcpPairCallback(req({ state, code: "ghc" }), env);
    expect(res.status).toBe(502);
  });

  it("502 when /user returns no login field", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockResolvedValueOnce(jsonResp({})),
    );
    const { env } = envWithKv();
    const state = await buildState("PC1");
    const res = await handleMcpPairCallback(req({ state, code: "ghc" }), env);
    expect(res.status).toBe(502);
  });
});

describe("handleMcpPairCallback — ACL", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  async function expectDeny(allowlist: string | undefined): Promise<void> {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockResolvedValueOnce(jsonResp({ login: "alice" })),
    );
    const { env } = envWithKv({ GITHUB_MCP_USER_ALLOWLIST: allowlist });
    const state = await buildState("PC1");
    const res = await handleMcpPairCallback(req({ state, code: "ghc" }), env);
    expect(res.status).toBe(403);
  }

  it("403 when login not in allowlist", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockResolvedValueOnce(jsonResp({ login: "intruder" })),
    );
    const { env } = envWithKv({ GITHUB_MCP_USER_ALLOWLIST: '["alice"]' });
    const state = await buildState("PC1");
    const res = await handleMcpPairCallback(req({ state, code: "ghc" }), env);
    expect(res.status).toBe(403);
  });

  it("denies all when allowlist undefined", async () => {
    await expectDeny(undefined);
  });

  it("denies all when allowlist is not an array", async () => {
    await expectDeny('{"alice": true}');
  });

  it("denies all when allowlist JSON malformed", async () => {
    await expectDeny("{not json");
  });

  it("denies all when allowlist array contains non-string", async () => {
    await expectDeny('["alice", 42]');
  });
});

describe("handleMcpPairCallback — success", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("sets session cookie and redirects back to /mcp/pair/<code>", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockResolvedValueOnce(jsonResp({ login: "alice" })),
    );
    const { env } = envWithKv();
    const state = await buildState("PC1");
    const res = await handleMcpPairCallback(req({ state, code: "ghc" }), env);
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe(`${ISSUER}/mcp/pair/PC1`);
    const sc = res.headers.get("Set-Cookie")!;
    expect(sc).toContain(`${PAIR_SESSION_COOKIE_NAME}=`);
    expect(sc).toContain("Secure");
    expect(sc).toContain("HttpOnly");
    expect(sc).toContain("SameSite=Lax");
    // cookie 値が verifyPairSession で alice として読める
    const cookieValue = sc.split(";")[0]!.split("=")[1]!;
    const payload = await verifyPairSession(cookieValue, SESSION_SECRET);
    expect(payload?.github_login).toBe("alice");
  });
});
