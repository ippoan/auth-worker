/**
 * `handleMcpAdminExec` (Phase 1 admin auth) — `POST /mcp/admin/exec` テスト。
 * MCP JWT は実 sign し、`INSTALLATION_TOKEN_DO` は test 用 stub で差し替え、
 * GitHub REST は `globalThis.fetch` を vi.stubGlobal で差し替える。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleMcpAdminExec } from "../../src/handlers/mcp-admin-exec";
import { signMcpJwt } from "../../src/lib/mcp-jwt";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth.test.example";
const MCP_JWT_SECRET = "test-mcp-jwt-secret-32chars!";
const INSTALLATION_ID = "111222";

interface DoStubOptions {
  status?: number;
  body?: unknown;
  throwOnFetch?: Error;
}

function makeInstallationDo(opts: DoStubOptions = {}): DurableObjectNamespace {
  const status = opts.status ?? 200;
  const body = opts.body ?? { token: "ghs_installation_test", expires_at_epoch_sec: 9_999_999_999 };
  const stub = {
    fetch: async (_url: string) => {
      if (opts.throwOnFetch) throw opts.throwOnFetch;
      return new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      });
    },
  };
  return {
    idFromName: (name: string) => ({ name }) as unknown as DurableObjectId,
    idFromString: (s: string) => ({ name: s }) as unknown as DurableObjectId,
    newUniqueId: () => ({ name: "unique" }) as unknown as DurableObjectId,
    get: () => stub as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    MCP_JWT_SECRET,
    INSTALLATION_TOKEN_DO: makeInstallationDo(),
    GITHUB_APP_INSTALLATION_ID: INSTALLATION_ID,
    ...overrides,
  });
  return { env, kv };
}

const MCP_AUD_LEGACY = "github-mcp-server-rs";

async function makeJwt(login = "alice"): Promise<string> {
  return signMcpJwt(
    { sub: `github:${login}`, github_login: login, scope: "mcp.read", aud: MCP_AUD_LEGACY },
    MCP_JWT_SECRET,
    3600,
  );
}

async function seedElevate(kv: MockKV, login: string, opts: { expired?: boolean } = {}): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const expires = opts.expired ? now - 10 : now + 900;
  await kv.put(
    `elevate:${login}`,
    JSON.stringify({ elevated_at: now, expires_at: expires }),
    { expirationTtl: 900 },
  );
}

function makeRequest(body: unknown, opts: { auth?: string; rawAuth?: string } = {}): Request {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.rawAuth !== undefined) headers["Authorization"] = opts.rawAuth;
  else if (opts.auth) headers["Authorization"] = `Bearer ${opts.auth}`;
  return new Request(`${ISSUER}/mcp/admin/exec`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

describe("handleMcpAdminExec — env guards", () => {
  it("503 when MCP_OAUTH_KV unbound", async () => {
    const { env } = envWithKv({ MCP_OAUTH_KV: undefined });
    const res = await handleMcpAdminExec(makeRequest({}), env);
    expect(res.status).toBe(503);
  });
  it("503 when MCP_JWT_SECRET missing", async () => {
    const { env } = envWithKv({ MCP_JWT_SECRET: undefined });
    const res = await handleMcpAdminExec(makeRequest({}), env);
    expect(res.status).toBe(503);
  });
  it("503 when INSTALLATION_TOKEN_DO missing", async () => {
    const { env } = envWithKv({ INSTALLATION_TOKEN_DO: undefined });
    const res = await handleMcpAdminExec(makeRequest({}), env);
    expect(res.status).toBe(503);
  });
  it("503 when GITHUB_APP_INSTALLATION_ID missing", async () => {
    const { env } = envWithKv({ GITHUB_APP_INSTALLATION_ID: undefined });
    const res = await handleMcpAdminExec(makeRequest({}), env);
    expect(res.status).toBe(503);
  });
});

describe("handleMcpAdminExec — auth gates", () => {
  it("401 when Authorization header missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpAdminExec(makeRequest({}), env);
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false, error: "missing_authorization" });
  });

  it("401 when Authorization header is not Bearer", async () => {
    const { env } = envWithKv();
    const res = await handleMcpAdminExec(makeRequest({}, { rawAuth: "Basic xxx" }), env);
    expect(res.status).toBe(401);
  });

  it("401 when JWT is invalid", async () => {
    const { env } = envWithKv();
    const res = await handleMcpAdminExec(makeRequest({}, { auth: "not.a.valid.jwt" }), env);
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false, error: "invalid_jwt" });
  });

  it("403 when elevate flag missing", async () => {
    const { env } = envWithKv();
    const jwt = await makeJwt("alice");
    const res = await handleMcpAdminExec(makeRequest({}, { auth: jwt }), env);
    expect(res.status).toBe(403);
    const body = await res.json() as { ok: boolean; error: string; elevate_url: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("not_elevated");
    expect(body.elevate_url).toBe(`${ISSUER}/mcp/elevate`);
  });

  it("403 when elevate flag expired", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice", { expired: true });
    const jwt = await makeJwt("alice");
    const res = await handleMcpAdminExec(makeRequest({}, { auth: jwt }), env);
    expect(res.status).toBe(403);
  });

  it("403 when elevate flag value is malformed JSON", async () => {
    const { env, kv } = envWithKv();
    await kv.put("elevate:alice", "{not-json", { expirationTtl: 900 });
    const jwt = await makeJwt("alice");
    const res = await handleMcpAdminExec(makeRequest({}, { auth: jwt }), env);
    expect(res.status).toBe(403);
  });
});

describe("handleMcpAdminExec — request validation", () => {
  async function withElevated(): Promise<{ env: Env; kv: MockKV; jwt: string }> {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    const jwt = await makeJwt("alice");
    return { env, kv, jwt };
  }

  it("400 when body JSON parse fails", async () => {
    const { env, jwt } = await withElevated();
    const req = new Request(`${ISSUER}/mcp/admin/exec`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${jwt}` },
      body: "{not json",
    });
    const res = await handleMcpAdminExec(req, env);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ ok: false, error: "invalid_request", details: "json_parse" });
  });

  it("400 when body is JSON null", async () => {
    const { env, jwt } = await withElevated();
    const req = new Request(`${ISSUER}/mcp/admin/exec`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${jwt}` },
      body: "null",
    });
    const res = await handleMcpAdminExec(req, env);
    expect(res.status).toBe(400);
  });

  it("400 when tool is unknown", async () => {
    const { env, jwt } = await withElevated();
    const res = await handleMcpAdminExec(
      makeRequest({ tool: "rm_rf_branch", args: { owner: "ippoan", repo: "x", branch: "main" } }, { auth: jwt }),
      env,
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ ok: false, error: "unknown_tool" });
  });

  it("400 when args missing required fields", async () => {
    const { env, jwt } = await withElevated();
    const res = await handleMcpAdminExec(
      makeRequest({ tool: "get_branch_protection", args: { owner: "ippoan" } }, { auth: jwt }),
      env,
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ ok: false, error: "invalid_request", details: "missing_fields" });
  });

  it("400 when args is array (not object)", async () => {
    const { env, jwt } = await withElevated();
    const res = await handleMcpAdminExec(
      makeRequest({ tool: "get_branch_protection", args: ["ippoan"] }, { auth: jwt }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when owner is not in ALLOWED_ADMIN_ORGS", async () => {
    const { env, jwt } = await withElevated();
    const res = await handleMcpAdminExec(
      makeRequest({ tool: "get_branch_protection", args: { owner: "stranger", repo: "x", branch: "main" } }, { auth: jwt }),
      env,
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ ok: false, error: "forbidden_owner" });
  });
});

describe("handleMcpAdminExec — DO and GitHub dispatch", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  async function withElevated(do_?: DurableObjectNamespace): Promise<{ env: Env; jwt: string }> {
    const kv = createMockKV() as MockKV;
    const env = createMockEnv({
      MCP_OAUTH_KV: kv,
      AUTH_WORKER_ORIGIN: ISSUER,
      MCP_JWT_SECRET,
      INSTALLATION_TOKEN_DO: do_ ?? makeInstallationDo(),
      GITHUB_APP_INSTALLATION_ID: INSTALLATION_ID,
    });
    await seedElevate(kv, "alice");
    const jwt = await makeJwt("alice");
    return { env, jwt };
  }

  it("502 when DO returns non-OK", async () => {
    const { env, jwt } = await withElevated(makeInstallationDo({ status: 503, body: { error: "down" } }));
    const res = await handleMcpAdminExec(
      makeRequest({ tool: "get_branch_protection", args: { owner: "ippoan", repo: "r", branch: "main" } }, { auth: jwt }),
      env,
    );
    expect(res.status).toBe(502);
    const body = await res.json() as { ok: boolean; error: string };
    expect(body.error).toBe("installation_token_failed");
  });

  it("502 when DO returns 200 but no token field", async () => {
    const { env, jwt } = await withElevated(makeInstallationDo({ status: 200, body: { expires_at_epoch_sec: 1 } }));
    const res = await handleMcpAdminExec(
      makeRequest({ tool: "get_branch_protection", args: { owner: "ippoan", repo: "r", branch: "main" } }, { auth: jwt }),
      env,
    );
    expect(res.status).toBe(502);
  });

  it("502 when DO fetch throws", async () => {
    const { env, jwt } = await withElevated(makeInstallationDo({ throwOnFetch: new Error("do-down") }));
    const res = await handleMcpAdminExec(
      makeRequest({ tool: "get_branch_protection", args: { owner: "ippoan", repo: "r", branch: "main" } }, { auth: jwt }),
      env,
    );
    expect(res.status).toBe(502);
  });

  it("200 ok with parsed result on successful set_branch_protection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        expect(url).toBe("https://api.github.com/repos/ippoan/r/branches/main/protection");
        expect(init?.method).toBe("PUT");
        const headers = init?.headers as Record<string, string>;
        expect(headers["Authorization"]).toBe("Bearer ghs_installation_test");
        expect(headers["Accept"]).toBe("application/vnd.github+json");
        expect(headers["User-Agent"]).toBe("ippoan-auth-worker");
        expect(headers["X-GitHub-Api-Version"]).toBe("2022-11-28");
        // body forwarded minus owner/repo/branch
        const sent = JSON.parse(init!.body as string);
        expect(sent).toEqual({ required_status_checks: null, enforce_admins: true });
        return new Response(JSON.stringify({ url: "...", enforce_admins: { enabled: true } }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );
    const { env, jwt } = await withElevated();
    const res = await handleMcpAdminExec(
      makeRequest({
        tool: "set_branch_protection",
        args: {
          owner: "ippoan",
          repo: "r",
          branch: "main",
          required_status_checks: null,
          enforce_admins: true,
        },
      }, { auth: jwt }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { ok: boolean; result: { enforce_admins: { enabled: boolean } } };
    expect(body.ok).toBe(true);
    expect(body.result.enforce_admins.enabled).toBe(true);
  });

  it("200 ok with null result on successful delete_branch_protection (empty body)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
        expect(init?.method).toBe("DELETE");
        // 200 + empty body instead of 204; undici Response constructor rejects
        // 204 because the spec requires no body for 1xx/204/304.
        return new Response("", { status: 200 });
      }),
    );
    const { env, jwt } = await withElevated();
    const res = await handleMcpAdminExec(
      makeRequest({
        tool: "delete_branch_protection",
        args: { owner: "ippoan", repo: "r", branch: "main" },
      }, { auth: jwt }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { ok: boolean; result: unknown };
    expect(body.ok).toBe(true);
    expect(body.result).toBeNull();
  });

  it("200 ok with raw text result on successful get_branch_protection when body is non-JSON", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
        expect(init?.method).toBe("GET");
        return new Response("hello-not-json", { status: 200 });
      }),
    );
    const { env, jwt } = await withElevated();
    const res = await handleMcpAdminExec(
      makeRequest({
        tool: "get_branch_protection",
        args: { owner: "ippoan", repo: "r", branch: "main" },
      }, { auth: jwt }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { ok: boolean; result: string };
    expect(body.result).toBe("hello-not-json");
  });

  it("502 github_api_error when GitHub returns 422", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response('{"message":"validation failed"}', { status: 422 })),
    );
    const { env, jwt } = await withElevated();
    const res = await handleMcpAdminExec(
      makeRequest({
        tool: "set_branch_protection",
        args: { owner: "ippoan", repo: "r", branch: "main", required_pull_request_reviews: null },
      }, { auth: jwt }),
      env,
    );
    expect(res.status).toBe(502);
    const body = await res.json() as { ok: boolean; error: string; status: number; body: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("github_api_error");
    expect(body.status).toBe(422);
    expect(body.body).toContain("validation failed");
  });
});
