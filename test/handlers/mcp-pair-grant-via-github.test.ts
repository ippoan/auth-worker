/**
 * `handleMcpPairGrantViaGithub` — `POST /mcp/pair/grant-via-github` テスト。
 *
 * - env guard (503)
 * - MCP_HEADLESS_GRANT_ENABLED kill switch (503、issue #432 regression test)
 * - Authorization header parsing (400)
 * - body invalid JSON (400)
 * - audience allowlist (403)
 * - GITHUB_MCP_USER_ALLOWLIST ACL (403 access_denied、2026-07-24 修正の regression test)
 * - forbidden scope (mcp.admin) (403)
 * - rate limit (10/min) (429)
 * - GitHub token rejected by api.github.com (401)
 * - api.github.com 5xx / network (502)
 * - api.github.com response missing login/id (502)
 * - 正常系: binding_jwt mint + verify、mcp_url、github_id echo、aud / scope echo
 * - audience override: ref-files-mcp-server-rs
 * - aud allowlist env override
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { handleMcpPairGrantViaGithub } from "../../src/handlers/mcp-pair-grant-via-github";
import { verifyMcpJwt } from "../../src/lib/mcp-jwt";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth-staging.test.example";
const RELAY = "https://mcp-staging.test.example";
const MCP_JWT_SECRET = "test-mcp-jwt-secret-32chars!!!!!";
const GITHUB_TOKEN = "ghp_testtoken_43chars_xxxxxxxxxxxxxxxxxxxx";
const ALICE = { login: "alice", id: 12345 } as const;

function envWith(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    MCP_JWT_SECRET,
    // 2026-07-24: ACL 修正後は allowlist が無いと全て 403 になるため、既存
    // happy-path テスト (login=alice) が通るよう default で alice を含める。
    // ACL 自体のテストは明示的に上書きする (下の describe ブロック参照)。
    GITHUB_MCP_USER_ALLOWLIST: '["alice"]',
    // issue #432: kill switch 未設定だと全て 503 になるため、既存テストが
    // 通るよう default で有効化する。kill switch 自体のテストは明示的に
    // 上書きする (下の describe ブロック参照)。
    MCP_HEADLESS_GRANT_ENABLED: "1",
    ...overrides,
  });
  return { env, kv };
}

function buildReq(opts: {
  auth?: string | null;
  body?: string;
  contentType?: string;
  contentLength?: string;
} = {}): Request {
  const headers: Record<string, string> = {};
  if (opts.auth) headers.Authorization = opts.auth;
  if (opts.contentType !== undefined) headers["Content-Type"] = opts.contentType;
  if (opts.contentLength !== undefined) headers["Content-Length"] = opts.contentLength;
  return new Request(`${ISSUER}/mcp/pair/grant-via-github`, {
    method: "POST",
    headers,
    body: opts.body,
  });
}

function mockGithubUser(
  user: { login: string; id: number } = ALICE,
  status = 200,
): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url === "https://api.github.com/user") {
        return new Response(JSON.stringify(user), {
          status,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    }),
  );
}

function mockGithubReject(status = 401): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response('{"message":"Bad credentials"}', {
          status,
          headers: { "content-type": "application/json" },
        }),
    ),
  );
}

function mockGithubThrow(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new Error("network down");
    }),
  );
}

beforeEach(() => {
  // 各 test 開始時に fetch stub をリセット (stubGlobal は describe 外でも leak する)
  vi.unstubAllGlobals();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("handleMcpPairGrantViaGithub — env guards", () => {
  it.each([
    ["MCP_JWT_SECRET", { MCP_JWT_SECRET: "" }],
    ["AUTH_WORKER_ORIGIN", { AUTH_WORKER_ORIGIN: "" }],
  ])("503 when %s missing", async (_label, overrides) => {
    const { env } = envWith(overrides as Partial<Env>);
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("server_error");
  });
});

describe("handleMcpPairGrantViaGithub — MCP_HEADLESS_GRANT_ENABLED kill switch (issue #432)", () => {
  it("503 when unset (fail-closed)", async () => {
    const { env } = envWith({ MCP_HEADLESS_GRANT_ENABLED: undefined });
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("server_error");
  });

  it("503 when set to a truthy-looking but non-'1' value (fail-closed)", async () => {
    const { env } = envWith({ MCP_HEADLESS_GRANT_ENABLED: "true" } as Partial<Env>);
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("does not call api.github.com when kill switch is off (fails closed before upstream)", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const { env } = envWith({ MCP_HEADLESS_GRANT_ENABLED: undefined });
    await handleMcpPairGrantViaGithub(buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }), env);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("200 when explicitly set to '1'", async () => {
    mockGithubUser(ALICE);
    const { env } = envWith({ MCP_HEADLESS_GRANT_ENABLED: "1" });
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(200);
  });
});

describe("handleMcpPairGrantViaGithub — Authorization parsing", () => {
  it("400 when Authorization header missing", async () => {
    const { env } = envWith();
    const res = await handleMcpPairGrantViaGithub(buildReq(), env);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_request");
  });

  it("400 when Authorization is not Bearer scheme", async () => {
    const { env } = envWith();
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: "Basic foo" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("accepts case-insensitive Bearer prefix", async () => {
    mockGithubUser();
    const { env } = envWith();
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(200);
  });
});

describe("handleMcpPairGrantViaGithub — body parsing", () => {
  it("400 when body is invalid JSON", async () => {
    const { env } = envWith();
    const res = await handleMcpPairGrantViaGithub(
      buildReq({
        auth: `Bearer ${GITHUB_TOKEN}`,
        body: "not-json",
        contentType: "application/json",
      }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("ignores non-JSON content-type body silently", async () => {
    mockGithubUser();
    const { env } = envWith();
    const res = await handleMcpPairGrantViaGithub(
      buildReq({
        auth: `Bearer ${GITHUB_TOKEN}`,
        body: "ignored",
        contentType: "text/plain",
      }),
      env,
    );
    expect(res.status).toBe(200);
  });

  it("Content-Length: 0 → skip body parse", async () => {
    mockGithubUser();
    const { env } = envWith();
    const res = await handleMcpPairGrantViaGithub(
      buildReq({
        auth: `Bearer ${GITHUB_TOKEN}`,
        contentLength: "0",
      }),
      env,
    );
    expect(res.status).toBe(200);
  });
});

describe("handleMcpPairGrantViaGithub — audience allowlist", () => {
  it("403 when aud is outside MCP_JWT_AUDIENCE_ALLOWLIST", async () => {
    mockGithubUser();
    const { env } = envWith({
      MCP_JWT_AUDIENCE_ALLOWLIST: "github-mcp-server-rs",
    } as Partial<Env>);
    const res = await handleMcpPairGrantViaGithub(
      buildReq({
        auth: `Bearer ${GITHUB_TOKEN}`,
        body: JSON.stringify({ aud: "rogue-binary" }),
        contentType: "application/json",
      }),
      env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("forbidden_scope");
  });

  it("uses default allowlist when env unset", async () => {
    mockGithubUser();
    const { env } = envWith();
    const res = await handleMcpPairGrantViaGithub(
      buildReq({
        auth: `Bearer ${GITHUB_TOKEN}`,
        body: JSON.stringify({ aud: "ref-files-mcp-server-rs" }),
        contentType: "application/json",
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { aud: string };
    expect(body.aud).toBe("ref-files-mcp-server-rs");
  });
});

describe("handleMcpPairGrantViaGithub — GITHUB_MCP_USER_ALLOWLIST ACL (2026-07-24 修正)", () => {
  it("403 access_denied when allowlist is unset (fail-closed)", async () => {
    mockGithubUser(ALICE);
    const { env } = envWith({ GITHUB_MCP_USER_ALLOWLIST: undefined });
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("access_denied");
  });

  it("403 access_denied when allowlist is malformed JSON (fail-closed)", async () => {
    mockGithubUser(ALICE);
    const { env } = envWith({ GITHUB_MCP_USER_ALLOWLIST: "not-json" } as Partial<Env>);
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("access_denied");
  });

  it("403 access_denied when login is not in allowlist", async () => {
    mockGithubUser(ALICE);
    const { env } = envWith({ GITHUB_MCP_USER_ALLOWLIST: '["bob","carol"]' } as Partial<Env>);
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("access_denied");
  });

  it("does not mint a binding_jwt when denied (no upstream leak of a valid token)", async () => {
    mockGithubUser(ALICE);
    const { env } = envWith({ GITHUB_MCP_USER_ALLOWLIST: '["bob"]' } as Partial<Env>);
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.binding_jwt).toBeUndefined();
  });

  it("200 when login is included among multiple allowlist entries", async () => {
    mockGithubUser(ALICE);
    const { env } = envWith({ GITHUB_MCP_USER_ALLOWLIST: '["bob","alice","carol"]' } as Partial<Env>);
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(200);
  });
});

describe("handleMcpPairGrantViaGithub — forbidden scope", () => {
  it("403 when scope includes mcp.admin", async () => {
    mockGithubUser();
    const { env } = envWith();
    const res = await handleMcpPairGrantViaGithub(
      buildReq({
        auth: `Bearer ${GITHUB_TOKEN}`,
        body: JSON.stringify({ scope: "mcp.read mcp.admin" }),
        contentType: "application/json",
      }),
      env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("forbidden_scope");
  });
});

describe("handleMcpPairGrantViaGithub — GitHub token verification", () => {
  it("401 when api.github.com returns 401", async () => {
    mockGithubReject(401);
    const { env } = envWith();
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_token");
  });

  it("401 when api.github.com returns 403", async () => {
    mockGithubReject(403);
    const { env } = envWith();
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("502 when api.github.com returns 5xx", async () => {
    mockGithubReject(503);
    const { env } = envWith();
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("upstream_error");
  });

  it("502 when network fetch throws", async () => {
    mockGithubThrow();
    const { env } = envWith();
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(502);
  });

  it("502 when /user response missing login/id", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ name: "missing-required" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
      ),
    );
    const { env } = envWith();
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(502);
  });
});

describe("handleMcpPairGrantViaGithub — happy path", () => {
  it("mints binding_jwt with verified login + default aud / scope", async () => {
    mockGithubUser(ALICE);
    const { env } = envWith();
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      binding_jwt: string;
      mcp_url: string;
      github_login: string;
      github_id: number;
      aud: string;
      scope: string;
      expires_in: number;
    };
    expect(body.github_login).toBe("alice");
    expect(body.github_id).toBe(12345);
    expect(body.aud).toBe("github-mcp-server-rs");
    expect(body.scope).toBe("mcp.read mcp.write");
    expect(body.expires_in).toBe(60 * 60 * 24);
    expect(body.mcp_url).toMatch(/\/u\/alice\/mcp$/);
    expect(body.binding_jwt).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);

    // verify the minted JWT round-trips
    const claims = await verifyMcpJwt(
      body.binding_jwt,
      MCP_JWT_SECRET,
      "github-mcp-server-rs",
    );
    expect(claims).not.toBeNull();
    expect(claims!.github_login).toBe("alice");
    expect(claims!.scope).toBe("mcp.read mcp.write");
    expect(claims!.sub).toBe("github:alice");
  });

  it("honors body-supplied aud + scope", async () => {
    mockGithubUser(ALICE);
    const { env } = envWith();
    const res = await handleMcpPairGrantViaGithub(
      buildReq({
        auth: `Bearer ${GITHUB_TOKEN}`,
        body: JSON.stringify({ aud: "ref-files-mcp-server-rs", scope: "mcp.read" }),
        contentType: "application/json",
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { aud: string; scope: string; binding_jwt: string };
    expect(body.aud).toBe("ref-files-mcp-server-rs");
    expect(body.scope).toBe("mcp.read");
    const claims = await verifyMcpJwt(
      body.binding_jwt,
      MCP_JWT_SECRET,
      "ref-files-mcp-server-rs",
    );
    expect(claims).not.toBeNull();
    expect(claims!.scope).toBe("mcp.read");
  });
});

describe("handleMcpPairGrantViaGithub — rate limit", () => {
  it("429 after 10 grants in same minute (per token hash)", async () => {
    mockGithubUser(ALICE);
    const { env } = envWith();
    // Burn 10 successful grants.
    for (let i = 0; i < 10; i += 1) {
      const res = await handleMcpPairGrantViaGithub(
        buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
        env,
      );
      expect(res.status).toBe(200);
    }
    // 11th attempt rate-limited.
    const res = await handleMcpPairGrantViaGithub(
      buildReq({ auth: `Bearer ${GITHUB_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(429);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("rate_limited");
  });
});
