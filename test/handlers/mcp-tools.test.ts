import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { handleMcpTools } from "../../src/handlers/mcp-tools";
import {
  createMockEnv,
  createMockKV,
  type MockKV,
} from "../helpers/mock-env";
import type { Env } from "../../src/index";
import { signMcpJwt } from "../../src/lib/mcp-jwt";
import { encryptWithKey } from "../../src/lib/mcp-crypto";
import { DEV_LOGIN_ALLOWED_SUBJECTS_KV_KEY } from "../../src/lib/dev-login";

const ISSUER = "https://auth.test.example";
const TEST_MCP_JWT_SECRET = "test-mcp-jwt-secret-32chars!";
const TEST_SSO_KEY = "test-sso-encryption-key-material!";
const TEST_INTERNAL_SECRET = "test-internal-shared-secret-32chr";
const AUD = "github-mcp-server-rs";

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    MCP_JWT_SECRET: TEST_MCP_JWT_SECRET,
    SSO_ENCRYPTION_KEY: TEST_SSO_KEY,
    INTERNAL_SHARED_SECRET: TEST_INTERNAL_SECRET,
    ...overrides,
  });
  return { env, kv };
}

async function userJwt(opts: {
  login?: string;
  scope?: string;
  aud?: string;
  ttl?: number;
} = {}): Promise<string> {
  const login = opts.login ?? "alice";
  return signMcpJwt(
    {
      sub: `github:${login}`,
      github_login: login,
      scope: opts.scope ?? "mcp.read mcp.write",
      aud: opts.aud ?? AUD,
    },
    TEST_MCP_JWT_SECRET,
    opts.ttl ?? 3600,
  );
}

/** Google IdP MCP session (issue #414) — dev-login tools 用 (no github_login). */
async function googleUserJwt(opts: {
  email?: string;
  scope?: string;
} = {}): Promise<string> {
  const email = opts.email ?? "dev@example.com";
  return signMcpJwt(
    {
      sub: `google:${email}`,
      email,
      scope: opts.scope ?? "mcp.read mcp.write",
      aud: AUD,
    },
    TEST_MCP_JWT_SECRET,
    3600,
  );
}

async function authedReq(jwt: string, body: unknown): Promise<Request> {
  return new Request(`${ISSUER}/mcp/tools`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${jwt}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

async function seedUserToken(kv: MockKV, login: string, ghToken: string): Promise<void> {
  const enc = await encryptWithKey(ghToken, TEST_SSO_KEY);
  kv._data[`github_token:github:${login}`] = enc;
}

// ────────────────────────────────────────────────────────────────────────
// fetch mocking — we replace globalThis.fetch per-test to return controlled
// responses from api.github.com without hitting the real internet.
// ────────────────────────────────────────────────────────────────────────
const realFetch = globalThis.fetch;
let lastFetchInput: { url: string; init?: RequestInit } | null = null;

function mockGhFetch(
  routes: Record<string, { status: number; body: unknown }>,
): void {
  lastFetchInput = null;
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    lastFetchInput = { url, init };
    for (const [pattern, resp] of Object.entries(routes)) {
      if (url.startsWith(pattern)) {
        return new Response(JSON.stringify(resp.body), {
          status: resp.status,
          headers: { "Content-Type": "application/json" },
        });
      }
    }
    throw new Error(`unmocked fetch: ${url}`);
  }) as typeof fetch;
}

beforeEach(() => {
  lastFetchInput = null;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("POST /mcp/tools — env guards", () => {
  it("returns 503 when MCP_OAUTH_KV missing", async () => {
    const env = createMockEnv({
      MCP_OAUTH_KV: undefined,
      MCP_JWT_SECRET: TEST_MCP_JWT_SECRET,
      SSO_ENCRYPTION_KEY: TEST_SSO_KEY,
    });
    const res = await handleMcpTools(
      await authedReq("x", { jsonrpc: "2.0", method: "ping" }),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("returns 503 when MCP_JWT_SECRET missing", async () => {
    const { env } = envWithKv({ MCP_JWT_SECRET: undefined });
    const res = await handleMcpTools(
      await authedReq("x", { jsonrpc: "2.0", method: "ping" }),
      env,
    );
    expect(res.status).toBe(503);
  });
});

describe("POST /mcp/tools — auth", () => {
  it("returns 401 without Bearer header", async () => {
    const { env } = envWithKv();
    const req = new Request(`${ISSUER}/mcp/tools`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", method: "ping" }),
    });
    const res = await handleMcpTools(req, env);
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toContain("Bearer realm=");
  });

  it("returns 401 for malformed JWT", async () => {
    const { env } = envWithKv();
    const res = await handleMcpTools(await authedReq("not.a.jwt", { jsonrpc: "2.0", method: "ping" }), env);
    expect(res.status).toBe(401);
  });

  it("returns 401 for expired JWT", async () => {
    const { env } = envWithKv();
    const expired = await userJwt({ ttl: -10 });
    const res = await handleMcpTools(await authedReq(expired, { jsonrpc: "2.0", method: "ping" }), env);
    expect(res.status).toBe(401);
  });

  it("ping does not require a stored github_token (JWT-only auth gate)", async () => {
    // JWT 検証は authenticate() で全メソッド共通だが、github_token 解決は
    // requiresGithubToken: true なツール呼び出し時にのみ行う (dev-login 系
    // ツールは github_token を持たない Google IdP セッションからも呼べる必要
    // があるため)。ping はどちらの github_token にも依存しない。
    const { env } = envWithKv();
    const jwt = await userJwt({ login: "noone" });
    const res = await handleMcpTools(await authedReq(jwt, { jsonrpc: "2.0", id: 1, method: "ping" }), env);
    expect(res.status).toBe(200);
    const body = await res.json() as { result: unknown };
    expect(body.result).toEqual({});
  });

  it("tools/call on a github_* tool returns JSON-RPC error when github_token KV missing", async () => {
    const { env } = envWithKv();
    const jwt = await userJwt({ login: "noone" });
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "github_get_authenticated_user", arguments: {} },
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { error: { code: number; message: string } };
    expect(body.error.code).toBe(-32001);
    expect(body.error.message).toContain("no_github_token");
  });

  it("tools/call on a github_* tool returns JSON-RPC error when SSO_ENCRYPTION_KEY is unset", async () => {
    const { env, kv } = envWithKv({ SSO_ENCRYPTION_KEY: undefined });
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "github_get_authenticated_user", arguments: {} },
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { error: { code: number; message: string } };
    expect(body.error.code).toBe(-32603);
    expect(body.error.message).toContain("SSO_ENCRYPTION_KEY not configured");
  });

  it("tools/call on a github_* tool returns JSON-RPC error when github_token decryption fails", async () => {
    const { env, kv } = envWithKv();
    kv._data["github_token:github:alice"] = "not-valid-base64-encrypted-payload";
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "github_get_authenticated_user", arguments: {} },
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { error: { code: number; message: string } };
    expect(body.error.code).toBe(-32603);
    expect(body.error.message).toContain("decrypt");
  });
});

describe("POST /mcp/tools — JSON-RPC framing", () => {
  it("returns parse error on invalid JSON body", async () => {
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const req = new Request(`${ISSUER}/mcp/tools`, {
      method: "POST",
      headers: { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" },
      body: "not-json{",
    });
    const res = await handleMcpTools(req, env);
    expect(res.status).toBe(200);
    const body = await res.json() as { error: { code: number } };
    expect(body.error.code).toBe(-32700);
  });

  it("returns invalid-request error when jsonrpc is missing", async () => {
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const res = await handleMcpTools(await authedReq(jwt, { method: "ping" }), env);
    const body = await res.json() as { error: { code: number } };
    expect(body.error.code).toBe(-32600);
  });

  it("returns invalid-request error when method is missing", async () => {
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const res = await handleMcpTools(await authedReq(jwt, { jsonrpc: "2.0" }), env);
    const body = await res.json() as { error: { code: number } };
    expect(body.error.code).toBe(-32600);
  });

  it("returns method-not-found error for unknown method", async () => {
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, { jsonrpc: "2.0", id: 1, method: "unknown" }),
      env,
    );
    const body = await res.json() as { error: { code: number } };
    expect(body.error.code).toBe(-32601);
  });

  it("handles batched requests", async () => {
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, [
        { jsonrpc: "2.0", id: 1, method: "ping" },
        { jsonrpc: "2.0", id: 2, method: "initialize" },
      ]),
      env,
    );
    const body = await res.json() as Array<{ id: number; result: unknown }>;
    expect(Array.isArray(body)).toBe(true);
    expect(body).toHaveLength(2);
    expect(body[0]!.id).toBe(1);
    expect(body[1]!.id).toBe(2);
  });

  it("invalid batch entries produce per-item errors", async () => {
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, [
        { jsonrpc: "2.0", id: 1, method: "ping" },
        { jsonrpc: "1.0", id: 2, method: "ping" },
      ]),
      env,
    );
    const body = await res.json() as Array<{ id: number | null; result?: unknown; error?: { code: number } }>;
    expect(body[0]!.result).toBeDefined();
    expect(body[1]!.error?.code).toBe(-32600);
  });
});

describe("POST /mcp/tools — built-in methods", () => {
  it("initialize returns protocol version + capabilities", async () => {
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, { jsonrpc: "2.0", id: "init-1", method: "initialize" }),
      env,
    );
    const body = await res.json() as {
      id: string;
      result: {
        protocolVersion: string;
        serverInfo: { name: string; version: string };
        capabilities: { tools: unknown };
      };
    };
    expect(body.id).toBe("init-1");
    expect(body.result.protocolVersion).toBe("2025-06-18");
    expect(body.result.serverInfo.name).toBe("auth-worker-github-bridge");
    expect(body.result.capabilities.tools).toBeDefined();
  });

  it("ping returns empty result", async () => {
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, { jsonrpc: "2.0", id: 1, method: "ping" }),
      env,
    );
    const body = await res.json() as { result: unknown };
    expect(body.result).toEqual({});
  });

  it("tools/list filters by scope (mcp.read alone hides create tools)", async () => {
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt({ scope: "mcp.read" });
    const res = await handleMcpTools(
      await authedReq(jwt, { jsonrpc: "2.0", id: 1, method: "tools/list" }),
      env,
    );
    const body = await res.json() as { result: { tools: Array<{ name: string }> } };
    const names = body.result.tools.map((t) => t.name);
    expect(names).toContain("github_get_repo");
    expect(names).toContain("github_list_issues");
    expect(names).not.toContain("github_create_issue");
  });

  it("tools/list includes write tools when scope=mcp.write", async () => {
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt({ scope: "mcp.write" });
    const res = await handleMcpTools(
      await authedReq(jwt, { jsonrpc: "2.0", id: 1, method: "tools/list" }),
      env,
    );
    const body = await res.json() as { result: { tools: Array<{ name: string }> } };
    expect(body.result.tools.map((t) => t.name)).toContain("github_create_issue");
  });
});

describe("POST /mcp/tools — tools/call (mocked GitHub)", () => {
  it("github_get_authenticated_user proxies /user with bearer github_token", async () => {
    mockGhFetch({
      "https://api.github.com/user": { status: 200, body: { login: "alice", id: 42 } },
    });
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_secret");
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "github_get_authenticated_user", arguments: {} },
      }),
      env,
    );
    const body = await res.json() as {
      result: { content: Array<{ type: string; text: string }>; isError: boolean };
    };
    expect(body.result.isError).toBe(false);
    expect(body.result.content[0]!.text).toContain('"login"');
    expect(body.result.content[0]!.text).toContain("alice");
    // Verify the call carried the user's GitHub token (not the MCP JWT).
    const auth = (lastFetchInput?.init?.headers as Record<string, string>)?.["Authorization"];
    expect(auth).toBe("Bearer gho_secret");
  });

  it("github_get_repo encodes path parts and proxies", async () => {
    mockGhFetch({
      "https://api.github.com/repos/ippoan/auth-worker": {
        status: 200,
        body: { name: "auth-worker", private: false },
      },
    });
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "github_get_repo",
          arguments: { owner: "ippoan", repo: "auth-worker" },
        },
      }),
      env,
    );
    const body = await res.json() as {
      result: { isError: boolean; content: Array<{ text: string }> };
    };
    expect(body.result.isError).toBe(false);
    expect(body.result.content[0]!.text).toContain("auth-worker");
  });

  it("github_list_issues clamps per_page", async () => {
    mockGhFetch({
      "https://api.github.com/repos/o/r/issues": {
        status: 200,
        body: [{ number: 1, title: "x" }],
      },
    });
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "github_list_issues",
          arguments: { owner: "o", repo: "r", per_page: 9999, state: "all" },
        },
      }),
      env,
    );
    expect(lastFetchInput?.url).toContain("per_page=100");
    expect(lastFetchInput?.url).toContain("state=all");
  });

  it("github_list_pull_requests proxies with default state=open", async () => {
    mockGhFetch({
      "https://api.github.com/repos/o/r/pulls": { status: 200, body: [] },
    });
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "github_list_pull_requests",
          arguments: { owner: "o", repo: "r" },
        },
      }),
      env,
    );
    expect(lastFetchInput?.url).toContain("state=open");
  });

  it("github_create_issue POSTs JSON body and requires mcp.write", async () => {
    mockGhFetch({
      "https://api.github.com/repos/o/r/issues": {
        status: 201,
        body: { number: 42, html_url: "https://github.com/o/r/issues/42" },
      },
    });
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt({ scope: "mcp.write" });
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "github_create_issue",
          arguments: { owner: "o", repo: "r", title: "hello", body: "world" },
        },
      }),
      env,
    );
    expect(lastFetchInput?.init?.method).toBe("POST");
    const bodyStr = (lastFetchInput?.init?.body) as string;
    expect(JSON.parse(bodyStr)).toEqual({ title: "hello", body: "world" });
    const body = await res.json() as {
      result: { isError: boolean; content: Array<{ text: string }> };
    };
    expect(body.result.isError).toBe(false);
    expect(body.result.content[0]!.text).toContain("42");
  });

  it("github_create_issue without `body` arg omits body field", async () => {
    mockGhFetch({
      "https://api.github.com/repos/o/r/issues": { status: 201, body: { number: 1 } },
    });
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt({ scope: "mcp.write" });
    await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "github_create_issue",
          arguments: { owner: "o", repo: "r", title: "t" },
        },
      }),
      env,
    );
    const sent = JSON.parse((lastFetchInput?.init?.body) as string) as Record<string, unknown>;
    expect(sent).toEqual({ title: "t" });
  });

  it("create_issue rejected when scope=mcp.read", async () => {
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt({ scope: "mcp.read" });
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "github_create_issue",
          arguments: { owner: "o", repo: "r", title: "t" },
        },
      }),
      env,
    );
    const body = await res.json() as { error: { code: number; message: string } };
    expect(body.error.code).toBe(-32000);
    expect(body.error.message).toContain("scope");
  });

  it("tools/call with missing required arg returns isError", async () => {
    mockGhFetch({}); // unused
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "github_get_repo", arguments: { owner: "o" } },
      }),
      env,
    );
    const body = await res.json() as {
      result: { isError: boolean; content: Array<{ text: string }> };
    };
    expect(body.result.isError).toBe(true);
    expect(body.result.content[0]!.text).toContain("required");
  });

  it("tools/call returns isError with GitHub message on non-2xx", async () => {
    mockGhFetch({
      "https://api.github.com/repos/x/y": {
        status: 404,
        body: { message: "Not Found" },
      },
    });
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "github_get_repo",
          arguments: { owner: "x", repo: "y" },
        },
      }),
      env,
    );
    const body = await res.json() as {
      result: { isError: boolean; content: Array<{ text: string }> };
    };
    expect(body.result.isError).toBe(true);
    expect(body.result.content[0]!.text).toContain("404");
    expect(body.result.content[0]!.text).toContain("Not Found");
  });

  it("tools/call returns method-not-found for unknown tool name", async () => {
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "does_not_exist", arguments: {} },
      }),
      env,
    );
    const body = await res.json() as { error: { code: number } };
    expect(body.error.code).toBe(-32601);
  });

  it("tools/call rejects non-object params", async () => {
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: "wrong",
      }),
      env,
    );
    const body = await res.json() as { error: { code: number } };
    expect(body.error.code).toBe(-32602);
  });

  it("tools/call rejects missing name", async () => {
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {},
      }),
      env,
    );
    const body = await res.json() as { error: { code: number } };
    expect(body.error.code).toBe(-32602);
  });
});

describe("POST /mcp/tools — dev-login tools (issue #423/#424)", () => {
  const ALLOWLIST = JSON.stringify(["google:dev@example.com"]);

  function internalUserResponse(overrides: Record<string, unknown> = {}): Response {
    return new Response(
      JSON.stringify({
        id: "user-uuid-1",
        tenant_id: "tenant-uuid-1",
        email: "dev@example.com",
        name: "Dev User",
        role: "admin",
        google_sub: "google-sub-xyz",
        lineworks_id: null,
        line_user_id: null,
        slug: "acme",
        ...overrides,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  }

  it("tools/list includes dev-login tools and does not require a github_token", async () => {
    const { env, kv } = envWithKv();
    kv._data[DEV_LOGIN_ALLOWED_SUBJECTS_KV_KEY] = ALLOWLIST;
    const jwt = await googleUserJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, { jsonrpc: "2.0", id: 1, method: "tools/list" }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { result: { tools: Array<{ name: string }> } };
    const names = body.result.tools.map((t) => t.name);
    expect(names).toContain("issue_dev_token");
    expect(names).toContain("issue_dev_login_url");
    // Refs #438: github_login が無いGoogle IdP セッションでは、呼んでも必ず
    // no_github_token で失敗するrequiresGithubToken系ツールを一覧に出さない
    // ("一覧にあるのに呼べない" 体験の防止)。
    expect(names).not.toContain("github_get_authenticated_user");
    expect(names).not.toContain("github_create_issue");
  });

  it("tools/list includes github tools for a GitHub-IdP session (unchanged)", async () => {
    const { env } = envWithKv();
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, { jsonrpc: "2.0", id: 1, method: "tools/list" }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { result: { tools: Array<{ name: string }> } };
    const names = body.result.tools.map((t) => t.name);
    expect(names).toContain("github_get_authenticated_user");
    expect(names).toContain("github_create_issue");
  });

  it("issue_dev_token mints a dev JWT for an allowed Google-IdP subject", async () => {
    const { env, kv } = envWithKv();
    kv._data[DEV_LOGIN_ALLOWED_SUBJECTS_KV_KEY] = ALLOWLIST;
    kv._data["google_sub:dev@example.com"] = "google-sub-xyz";
    globalThis.fetch = vi.fn().mockResolvedValue(internalUserResponse());
    const jwt = await googleUserJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "issue_dev_token", arguments: {} },
      }),
      env,
    );
    const body = await res.json() as {
      result: { isError: boolean; content: Array<{ text: string }> };
    };
    expect(body.result.isError).toBe(false);
    const parsed = JSON.parse(body.result.content[0]!.text) as { access_token: string; expires_in: number };
    expect(typeof parsed.access_token).toBe("string");
    expect(parsed.expires_in).toBe(1800);
  });

  it("issue_dev_login_url returns a localhost callback URL with a one-time code", async () => {
    const { env, kv } = envWithKv();
    kv._data[DEV_LOGIN_ALLOWED_SUBJECTS_KV_KEY] = ALLOWLIST;
    kv._data["google_sub:dev@example.com"] = "google-sub-xyz";
    globalThis.fetch = vi.fn().mockResolvedValue(internalUserResponse());
    const jwt = await googleUserJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "issue_dev_login_url", arguments: { port: 8787 } },
      }),
      env,
    );
    const body = await res.json() as {
      result: { isError: boolean; content: Array<{ text: string }> };
    };
    expect(body.result.isError).toBe(false);
    const parsed = JSON.parse(body.result.content[0]!.text) as { url: string };
    expect(parsed.url).toMatch(/^http:\/\/localhost:8787\/__dev\/callback\?code=[0-9a-f]{64}$/);
  });

  it("issue_dev_login_url rejects an out-of-range port", async () => {
    const { env, kv } = envWithKv();
    kv._data[DEV_LOGIN_ALLOWED_SUBJECTS_KV_KEY] = ALLOWLIST;
    const jwt = await googleUserJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "issue_dev_login_url", arguments: { port: 80 } },
      }),
      env,
    );
    const body = await res.json() as {
      result: { isError: boolean; content: Array<{ text: string }> };
    };
    expect(body.result.isError).toBe(true);
    expect(body.result.content[0]!.text).toContain("port must be");
  });

  it("issue_dev_token rejects a subject not in the allowlist", async () => {
    const { env, kv } = envWithKv();
    kv._data[DEV_LOGIN_ALLOWED_SUBJECTS_KV_KEY] = ALLOWLIST;
    const jwt = await googleUserJwt({ email: "someone-else@example.com" });
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "issue_dev_token", arguments: {} },
      }),
      env,
    );
    const body = await res.json() as {
      result: { isError: boolean; content: Array<{ text: string }> };
    };
    expect(body.result.isError).toBe(true);
    expect(body.result.content[0]!.text).toContain("not_in_allowlist");
  });

  it("issue_dev_token rejects a GitHub-IdP session (no email)", async () => {
    const { env, kv } = envWithKv();
    kv._data[DEV_LOGIN_ALLOWED_SUBJECTS_KV_KEY] = JSON.stringify(["github:alice"]);
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "issue_dev_token", arguments: {} },
      }),
      env,
    );
    const body = await res.json() as {
      result: { isError: boolean; content: Array<{ text: string }> };
    };
    expect(body.result.isError).toBe(true);
    expect(body.result.content[0]!.text).toContain("google_login_required");
  });
});

describe("POST /mcp/tools — verify_screenshot", () => {
  async function callVerify(env: Env, args: unknown): Promise<{
    isError: boolean;
    content: Array<{ text: string }>;
  }> {
    const jwt = await googleUserJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "verify_screenshot", arguments: args },
      }),
      env,
    );
    const body = await res.json() as {
      result: { isError: boolean; content: Array<{ text: string }> };
    };
    return body.result;
  }

  it("tools/list includes verify_screenshot for a Google-IdP session", async () => {
    const { env } = envWithKv();
    const jwt = await googleUserJwt();
    const res = await handleMcpTools(
      await authedReq(jwt, { jsonrpc: "2.0", id: 1, method: "tools/list" }),
      env,
    );
    const body = await res.json() as { result: { tools: Array<{ name: string }> } };
    expect(body.result.tools.map((t) => t.name)).toContain("verify_screenshot");
  });

  it("requires mcp.write scope", async () => {
    const { env } = envWithKv();
    const jwt = await googleUserJwt({ scope: "mcp.read" });
    const res = await handleMcpTools(
      await authedReq(jwt, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "verify_screenshot", arguments: { urls: ["https://dtako.ippoan.org/"] } },
      }),
      env,
    );
    const body = await res.json() as { error: { code: number } };
    expect(body.error.code).toBe(-32000);
  });

  it("rejects a missing / non-array urls argument", async () => {
    const { env } = envWithKv();
    const result = await callVerify(env, {});
    expect(result.isError).toBe(true);
    expect(result.content[0]!.text).toContain("urls must be");
  });

  it("rejects more than 5 urls", async () => {
    const { env } = envWithKv();
    const urls = Array.from({ length: 6 }, (_, i) => `https://dtako.ippoan.org/${i}`);
    const result = await callVerify(env, { urls });
    expect(result.isError).toBe(true);
    expect(result.content[0]!.text).toContain("urls must be");
  });

  it("rejects a URL outside *.ippoan.org (fail-closed SSRF boundary)", async () => {
    const { env } = envWithKv();
    for (const bad of [
      "https://evil.example.com/",
      "https://evil-ippoan.org/",
      "http://dtako.ippoan.org/",
    ]) {
      const result = await callVerify(env, { urls: [bad] });
      expect(result.isError).toBe(true);
      expect(result.content[0]!.text).toContain("url not allowed");
    }
  });

  it("rejects an unknown engine value", async () => {
    const { env } = envWithKv();
    const result = await callVerify(env, {
      urls: ["https://dtako.ippoan.org/"],
      engine: "firefox",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0]!.text).toContain("engine must be");
  });

  it("503s when the browser binding is not configured (before minting a dev JWT)", async () => {
    const { env } = envWithKv(); // BROWSER 未設定 (mock env に無い)
    const result = await callVerify(env, { urls: ["https://dtako.ippoan.org/"] });
    expect(result.isError).toBe(true);
    expect(result.content[0]!.text).toContain("browser_binding_not_configured");
  });
});

describe("POST /mcp/tools — relay-origin aud", () => {
  it("accepts JWT whose aud is the relay origin (Authorization Code flow)", async () => {
    const relayOrigin = ISSUER.replace(/auth\./, "mcp.");
    const { env, kv } = envWithKv();
    await seedUserToken(kv, "alice", "gho_x");
    const jwt = await userJwt({ aud: relayOrigin });
    const res = await handleMcpTools(
      await authedReq(jwt, { jsonrpc: "2.0", id: 1, method: "ping" }),
      env,
    );
    const body = await res.json() as { result: unknown };
    expect(body.result).toEqual({});
  });

  // issue #438: Google IdP surface の PRM は resource `<auth origin>/mcp/google`
  // を advertise するので、その URL が aud で焼かれた JWT も受理する。
  it("accepts JWT whose aud is <auth origin>/mcp/google (issue #438)", async () => {
    const { env } = envWithKv();
    const jwt = await userJwt({ aud: `${ISSUER}/mcp/google` });
    const res = await handleMcpTools(
      await authedReq(jwt, { jsonrpc: "2.0", id: 1, method: "ping" }),
      env,
    );
    const body = await res.json() as { result: unknown };
    expect(body.result).toEqual({});
  });

  it("still rejects JWT with an unrelated origin aud", async () => {
    const { env } = envWithKv();
    const jwt = await userJwt({ aud: "https://attacker.example/mcp" });
    const res = await handleMcpTools(
      await authedReq(jwt, { jsonrpc: "2.0", id: 1, method: "ping" }),
      env,
    );
    expect(res.status).toBe(401);
  });
});

// issue #438: Google IdP surface (`POST /mcp/google`) の 401 は surface 専用 PRM
// (`/.well-known/oauth-protected-resource/mcp/google`) へ誘導する。
describe("POST /mcp/google — google-surface WWW-Authenticate", () => {
  it("401 without Bearer points resource_metadata at the /mcp/google PRM", async () => {
    const { env } = envWithKv();
    const req = new Request(`${ISSUER}/mcp/google`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", method: "ping" }),
    });
    const res = await handleMcpTools(req, env);
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBe(
      `Bearer realm="MCP", resource_metadata="${ISSUER}/.well-known/oauth-protected-resource/mcp/google"`,
    );
  });

  it("401 on the default /mcp/tools path keeps the base PRM URL", async () => {
    const { env } = envWithKv();
    const req = new Request(`${ISSUER}/mcp/tools`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", method: "ping" }),
    });
    const res = await handleMcpTools(req, env);
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toBe(
      `Bearer realm="MCP", resource_metadata="${ISSUER}/.well-known/oauth-protected-resource"`,
    );
  });

  it("tools work identically on /mcp/google once authenticated (same handler)", async () => {
    const { env } = envWithKv();
    const jwt = await googleUserJwt();
    const req = new Request(`${ISSUER}/mcp/google`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwt}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    const res = await handleMcpTools(req, env);
    expect(res.status).toBe(200);
    const body = await res.json() as { result: { tools: Array<{ name: string }> } };
    const names = body.result.tools.map((t) => t.name);
    expect(names).toContain("issue_dev_login_url");
  });
});
