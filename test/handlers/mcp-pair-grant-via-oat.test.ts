/**
 * `handleMcpPairGrantViaOat` — `POST /mcp/pair/grant-via-oat` テスト
 * (issue ippoan/auth-worker#174)。
 *
 * - env / KV guard (503)
 * - Authorization header parsing (400)
 * - body invalid JSON (400)
 * - audience allowlist (403)
 * - forbidden scope (mcp.admin) (403)
 * - rate limit (10/min per OAT hash) (429)
 * - Anthropic API rejects OAT (401)
 * - Anthropic API 5xx / network (502)
 * - OAT not bound in KV → 404 with register_endpoint
 * - happy path: binding_jwt mint、JWT round-trip、mcp_url、aud / scope echo
 * - audience override: ref-files-mcp-server-rs
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { handleMcpPairGrantViaOat } from "../../src/handlers/mcp-pair-grant-via-oat";
import { verifyMcpJwt } from "../../src/lib/mcp-jwt";
import {
  OAT_BINDING_TTL_SEC,
  hashOat,
  putOatBinding,
} from "../../src/lib/mcp-oat-binding";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth-staging.test.example";
const MCP_JWT_SECRET = "test-mcp-jwt-secret-32chars!!!!!";
const OAT = "sk-ant-oat01-test-token-xxxxxxxxxxxxxxxxxxxx";

function envWith(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    MCP_JWT_SECRET,
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
  return new Request(`${ISSUER}/mcp/pair/grant-via-oat`, {
    method: "POST",
    headers,
    body: opts.body,
  });
}

function mockAnthropic(status = 200): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url === "https://api.anthropic.com/v1/models") {
        if (status >= 200 && status < 300) {
          return new Response(JSON.stringify({ data: [{ id: "claude" }] }), {
            status,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(JSON.stringify({ error: { message: "fail" } }), {
          status,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    }),
  );
}

function mockAnthropicThrow(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new Error("network down");
    }),
  );
}

async function bindAlice(env: Env): Promise<string> {
  const h = await hashOat(OAT);
  const now = Date.now();
  await putOatBinding(env, h, {
    github_login: "alice",
    bound_at: now,
    expires_at: now + OAT_BINDING_TTL_SEC * 1000,
  });
  return h;
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("handleMcpPairGrantViaOat — env guards", () => {
  it.each([
    ["MCP_JWT_SECRET", { MCP_JWT_SECRET: "" }],
    ["AUTH_WORKER_ORIGIN", { AUTH_WORKER_ORIGIN: "" }],
  ])("503 when %s missing", async (_label, overrides) => {
    const { env } = envWith(overrides as Partial<Env>);
    const res = await handleMcpPairGrantViaOat(
      buildReq({ auth: `Bearer ${OAT}` }),
      env,
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("server_error");
  });

  it("503 when MCP_OAUTH_KV not bound", async () => {
    const env = createMockEnv({
      AUTH_WORKER_ORIGIN: ISSUER,
      MCP_JWT_SECRET,
    });
    delete (env as { MCP_OAUTH_KV?: unknown }).MCP_OAUTH_KV;
    const res = await handleMcpPairGrantViaOat(
      buildReq({ auth: `Bearer ${OAT}` }),
      env,
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error_description: string };
    expect(body.error_description).toMatch(/MCP_OAUTH_KV/);
  });
});

describe("handleMcpPairGrantViaOat — Authorization parsing", () => {
  it("400 when Authorization header missing", async () => {
    const { env } = envWith();
    const res = await handleMcpPairGrantViaOat(buildReq(), env);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_request");
  });

  it("400 when Authorization is not Bearer scheme", async () => {
    const { env } = envWith();
    const res = await handleMcpPairGrantViaOat(
      buildReq({ auth: "Basic foo" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("accepts case-insensitive Bearer prefix", async () => {
    mockAnthropic();
    const { env } = envWith();
    await bindAlice(env);
    const res = await handleMcpPairGrantViaOat(
      buildReq({ auth: `bearer ${OAT}` }),
      env,
    );
    expect(res.status).toBe(200);
  });
});

describe("handleMcpPairGrantViaOat — body parsing", () => {
  it("400 when body is invalid JSON", async () => {
    const { env } = envWith();
    const res = await handleMcpPairGrantViaOat(
      buildReq({
        auth: `Bearer ${OAT}`,
        body: "not-json",
        contentType: "application/json",
      }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("ignores non-JSON content-type body silently", async () => {
    mockAnthropic();
    const { env } = envWith();
    await bindAlice(env);
    const res = await handleMcpPairGrantViaOat(
      buildReq({
        auth: `Bearer ${OAT}`,
        body: "ignored",
        contentType: "text/plain",
      }),
      env,
    );
    expect(res.status).toBe(200);
  });

  it("Content-Length: 0 → skip body parse", async () => {
    mockAnthropic();
    const { env } = envWith();
    await bindAlice(env);
    const res = await handleMcpPairGrantViaOat(
      buildReq({
        auth: `Bearer ${OAT}`,
        contentLength: "0",
      }),
      env,
    );
    expect(res.status).toBe(200);
  });
});

describe("handleMcpPairGrantViaOat — audience allowlist", () => {
  it("403 when aud is outside MCP_JWT_AUDIENCE_ALLOWLIST", async () => {
    const { env } = envWith({
      MCP_JWT_AUDIENCE_ALLOWLIST: "github-mcp-server-rs",
    } as Partial<Env>);
    const res = await handleMcpPairGrantViaOat(
      buildReq({
        auth: `Bearer ${OAT}`,
        body: JSON.stringify({ aud: "rogue-binary" }),
        contentType: "application/json",
      }),
      env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("forbidden_scope");
  });

  it("uses default allowlist when MCP_JWT_AUDIENCE_ALLOWLIST is empty string", async () => {
    mockAnthropic();
    const { env } = envWith({
      MCP_JWT_AUDIENCE_ALLOWLIST: ",,, ,",
    } as Partial<Env>);
    await bindAlice(env);
    const res = await handleMcpPairGrantViaOat(
      buildReq({
        auth: `Bearer ${OAT}`,
        body: JSON.stringify({ aud: "ref-files-mcp-server-rs" }),
        contentType: "application/json",
      }),
      env,
    );
    expect(res.status).toBe(200);
  });

  it("uses default allowlist when env unset (ref-files-mcp-server-rs passes)", async () => {
    mockAnthropic();
    const { env } = envWith();
    await bindAlice(env);
    const res = await handleMcpPairGrantViaOat(
      buildReq({
        auth: `Bearer ${OAT}`,
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

describe("handleMcpPairGrantViaOat — forbidden scope", () => {
  it("403 when scope includes mcp.admin", async () => {
    const { env } = envWith();
    const res = await handleMcpPairGrantViaOat(
      buildReq({
        auth: `Bearer ${OAT}`,
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

describe("handleMcpPairGrantViaOat — OAT validity check", () => {
  it("401 when Anthropic API returns 401", async () => {
    mockAnthropic(401);
    const { env } = envWith();
    await bindAlice(env);
    const res = await handleMcpPairGrantViaOat(
      buildReq({ auth: `Bearer ${OAT}` }),
      env,
    );
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_token");
  });

  it("401 when Anthropic API returns 403", async () => {
    mockAnthropic(403);
    const { env } = envWith();
    await bindAlice(env);
    const res = await handleMcpPairGrantViaOat(
      buildReq({ auth: `Bearer ${OAT}` }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("502 when Anthropic API returns 5xx", async () => {
    mockAnthropic(503);
    const { env } = envWith();
    await bindAlice(env);
    const res = await handleMcpPairGrantViaOat(
      buildReq({ auth: `Bearer ${OAT}` }),
      env,
    );
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("upstream_error");
  });

  it("502 when network fetch throws", async () => {
    mockAnthropicThrow();
    const { env } = envWith();
    await bindAlice(env);
    const res = await handleMcpPairGrantViaOat(
      buildReq({ auth: `Bearer ${OAT}` }),
      env,
    );
    expect(res.status).toBe(502);
  });
});

describe("handleMcpPairGrantViaOat — KV lookup", () => {
  it("404 not_bound with register_endpoint hint when oat_hash missing", async () => {
    mockAnthropic();
    const { env } = envWith();
    const res = await handleMcpPairGrantViaOat(
      buildReq({ auth: `Bearer ${OAT}` }),
      env,
    );
    expect(res.status).toBe(404);
    const body = (await res.json()) as {
      error: string;
      register_endpoint: string;
    };
    expect(body.error).toBe("not_bound");
    expect(body.register_endpoint).toBe(
      "/mcp/pair/register-via-github-comment",
    );
  });
});

describe("handleMcpPairGrantViaOat — happy path", () => {
  it("mints binding_jwt for bound OAT with default aud / scope", async () => {
    mockAnthropic();
    const { env } = envWith();
    await bindAlice(env);
    const res = await handleMcpPairGrantViaOat(
      buildReq({ auth: `Bearer ${OAT}` }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      binding_jwt: string;
      mcp_url: string;
      github_login: string;
      aud: string;
      scope: string;
      expires_in: number;
    };
    expect(body.github_login).toBe("alice");
    expect(body.aud).toBe("github-mcp-server-rs");
    expect(body.scope).toBe("mcp.read mcp.write");
    expect(body.expires_in).toBe(60 * 60 * 24);
    expect(body.mcp_url).toMatch(/\/u\/alice\/mcp$/);
    expect(body.binding_jwt).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);

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

  it("honors body-supplied aud + scope (ref-files binding)", async () => {
    mockAnthropic();
    const { env } = envWith();
    await bindAlice(env);
    const res = await handleMcpPairGrantViaOat(
      buildReq({
        auth: `Bearer ${OAT}`,
        body: JSON.stringify({
          aud: "ref-files-mcp-server-rs",
          scope: "mcp.read",
          binary_version: "v0.0.1",
        }),
        contentType: "application/json",
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      aud: string;
      scope: string;
      binding_jwt: string;
    };
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

describe("handleMcpPairGrantViaOat — rate limit", () => {
  it("429 after 10 grants in same minute (per OAT hash)", async () => {
    mockAnthropic();
    const { env } = envWith();
    await bindAlice(env);
    for (let i = 0; i < 10; i += 1) {
      const res = await handleMcpPairGrantViaOat(
        buildReq({ auth: `Bearer ${OAT}` }),
        env,
      );
      expect(res.status).toBe(200);
    }
    const res = await handleMcpPairGrantViaOat(
      buildReq({ auth: `Bearer ${OAT}` }),
      env,
    );
    expect(res.status).toBe(429);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("rate_limited");
  });
});
