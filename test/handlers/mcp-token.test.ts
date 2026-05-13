import { describe, it, expect } from "vitest";
import { handleMcpToken } from "../../src/handlers/mcp-token";
import {
  createMockEnv,
  createMockKV,
  type MockKV,
} from "../helpers/mock-env";
import type { Env } from "../../src/index";
import type { DeviceCodeRecord } from "../../src/lib/mcp-kv";
import { verifyMcpJwt } from "../../src/lib/mcp-jwt";
import { issueRefreshToken } from "../../src/lib/mcp-refresh";

const ISSUER = "https://auth.test.example";
const TEST_MCP_JWT_SECRET = "test-mcp-jwt-secret-32chars!";
const AUD = "github-mcp-server-rs";

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    MCP_JWT_SECRET: TEST_MCP_JWT_SECRET,
    ...overrides,
  });
  return { env, kv };
}

function rec(overrides: Partial<DeviceCodeRecord> = {}): DeviceCodeRecord {
  const now = Date.now();
  return {
    device_code: "d".repeat(64),
    user_code: "BCDF-GHJK",
    client_id: "github-mcp-server-rs",
    scope: "read:user",
    status: "pending",
    created_at: now,
    expires_at: now + 900_000,
    ...overrides,
  };
}

function postForm(
  fields: Record<string, string>,
  opts: { contentType?: string; body?: BodyInit } = {},
): Request {
  const headers: Record<string, string> = {};
  if (opts.contentType) headers["Content-Type"] = opts.contentType;
  const body =
    opts.body ??
    (opts.contentType?.includes("json")
      ? JSON.stringify(fields)
      : new URLSearchParams(fields));
  return new Request(`${ISSUER}/mcp/token`, { method: "POST", headers, body });
}

describe("POST /mcp/token — env guards", () => {
  it("returns 503 server_error when MCP_OAUTH_KV not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined, MCP_JWT_SECRET: TEST_MCP_JWT_SECRET });
    const res = await handleMcpToken(postForm({}), env);
    expect(res.status).toBe(503);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("server_error");
  });

  it("returns 503 server_error when MCP_JWT_SECRET missing", async () => {
    const kv = createMockKV() as MockKV;
    const env = createMockEnv({ MCP_OAUTH_KV: kv, MCP_JWT_SECRET: undefined });
    const res = await handleMcpToken(postForm({}), env);
    expect(res.status).toBe(503);
  });
});

describe("POST /mcp/token — form parsing", () => {
  it("returns 400 invalid_request when body is not form-encoded", async () => {
    const { env } = envWithKv();
    const req = new Request(`${ISSUER}/mcp/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not-form-{",
    });
    const res = await handleMcpToken(req, env);
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("invalid_request");
  });

  it("returns 400 unsupported_grant_type for unknown grant_type", async () => {
    const { env } = envWithKv();
    const res = await handleMcpToken(postForm({ grant_type: "password" }), env);
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("unsupported_grant_type");
  });

  it("returns 400 unsupported_grant_type when grant_type missing (empty)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpToken(postForm({}), env);
    expect(res.status).toBe(400);
  });
});

describe("POST /mcp/token — device_code grant", () => {
  const GRANT = "urn:ietf:params:oauth:grant-type:device_code";

  it("400 invalid_request when device_code missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpToken(
      postForm({ grant_type: GRANT, client_id: "x" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("invalid_request");
  });

  it("400 invalid_request when client_id missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpToken(
      postForm({ grant_type: GRANT, device_code: "d" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 expired_token when device_code not found", async () => {
    const { env } = envWithKv();
    const res = await handleMcpToken(
      postForm({ grant_type: GRANT, device_code: "nonexistent", client_id: "x" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("expired_token");
  });

  it("400 expired_token when expires_at < now", async () => {
    const { env, kv } = envWithKv();
    const r = rec({ expires_at: Date.now() - 1000 });
    kv._data[`device_code:${r.device_code}`] = JSON.stringify(r);
    const res = await handleMcpToken(
      postForm({ grant_type: GRANT, device_code: r.device_code, client_id: "x" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("expired_token");
  });

  it("400 authorization_pending when status=pending", async () => {
    const { env, kv } = envWithKv();
    const r = rec({ status: "pending" });
    kv._data[`device_code:${r.device_code}`] = JSON.stringify(r);
    const res = await handleMcpToken(
      postForm({ grant_type: GRANT, device_code: r.device_code, client_id: "x" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("authorization_pending");
  });

  it("400 access_denied when status=denied", async () => {
    const { env, kv } = envWithKv();
    const r = rec({ status: "denied" });
    kv._data[`device_code:${r.device_code}`] = JSON.stringify(r);
    const res = await handleMcpToken(
      postForm({ grant_type: GRANT, device_code: r.device_code, client_id: "x" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("access_denied");
  });

  it("500 server_error when approved but github_login missing (defensive)", async () => {
    const { env, kv } = envWithKv();
    const r = rec({ status: "approved" }); // github_login intentionally not set
    kv._data[`device_code:${r.device_code}`] = JSON.stringify(r);
    const res = await handleMcpToken(
      postForm({ grant_type: GRANT, device_code: r.device_code, client_id: "x" }),
      env,
    );
    expect(res.status).toBe(500);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("server_error");
  });

  it("200 with JWT + refresh_token on approved; device_code is deleted", async () => {
    const { env, kv } = envWithKv();
    const r = rec({ status: "approved", github_login: "alice" });
    kv._data[`device_code:${r.device_code}`] = JSON.stringify(r);
    const res = await handleMcpToken(
      postForm({
        grant_type: GRANT,
        device_code: r.device_code,
        client_id: "github-mcp-server-rs",
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as {
      access_token: string;
      token_type: string;
      expires_in: number;
      refresh_token: string;
      scope: string;
    };
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(3600);
    expect(body.scope).toBe("read:user");
    expect(body.refresh_token).toMatch(/^[0-9a-f]{64}$/);

    // JWT verifiable
    const payload = await verifyMcpJwt(body.access_token, TEST_MCP_JWT_SECRET, AUD);
    expect(payload).not.toBeNull();
    expect(payload!.sub).toBe("github:alice");
    expect(payload!.github_login).toBe("alice");

    // device_code deleted
    expect(kv._data[`device_code:${r.device_code}`]).toBeUndefined();
  });
});

describe("POST /mcp/token — refresh_token grant", () => {
  it("400 invalid_request when refresh_token missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpToken(
      postForm({ grant_type: "refresh_token" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("invalid_request");
  });

  it("400 invalid_grant when refresh_token unknown", async () => {
    const { env } = envWithKv();
    const res = await handleMcpToken(
      postForm({ grant_type: "refresh_token", refresh_token: "unknown" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("invalid_grant");
  });

  it("200 with new tokens on success; rotation enforced (2nd use fails)", async () => {
    const { env } = envWithKv();
    const refresh = await issueRefreshToken(env, {
      sub: "github:bob",
      scope: "read:user",
      github_login: "bob",
    });

    const res = await handleMcpToken(
      postForm({ grant_type: "refresh_token", refresh_token: refresh }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as {
      access_token: string;
      refresh_token: string;
      scope: string;
    };
    expect(body.scope).toBe("read:user");
    expect(body.refresh_token).not.toBe(refresh);

    // verify access_token
    const payload = await verifyMcpJwt(body.access_token, TEST_MCP_JWT_SECRET, AUD);
    expect(payload!.sub).toBe("github:bob");
    expect(payload!.github_login).toBe("bob");

    // second use of old refresh → invalid_grant
    const res2 = await handleMcpToken(
      postForm({ grant_type: "refresh_token", refresh_token: refresh }),
      env,
    );
    expect(res2.status).toBe(400);
    expect((await res2.json() as { error: string }).error).toBe("invalid_grant");
  });
});
