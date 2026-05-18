import { describe, it, expect } from "vitest";
import { handleMcpRevoke } from "../../src/handlers/mcp-revoke";
import {
  createMockEnv,
  createMockKV,
  type MockKV,
} from "../helpers/mock-env";
import type { Env } from "../../src/index";
import { signMcpJwt } from "../../src/lib/mcp-jwt";

const ISSUER = "https://auth.test.example";
const TEST_MCP_JWT_SECRET = "test-mcp-jwt-secret-32chars!";
const TEST_SSO_KEY = "test-sso-encryption-key-material!";
const AUD = "github-mcp-server-rs";

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    MCP_JWT_SECRET: TEST_MCP_JWT_SECRET,
    SSO_ENCRYPTION_KEY: TEST_SSO_KEY,
    INTERNAL_SHARED_SECRET: "x".repeat(33),
    ...overrides,
  });
  return { env, kv };
}

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

function formReq(body: string): Request {
  return new Request(`${ISSUER}/mcp/revoke`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
}

function jsonReq(body: unknown): Request {
  return new Request(`${ISSUER}/mcp/revoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("POST /mcp/revoke — env guards", () => {
  it("returns 503 when MCP_OAUTH_KV missing", async () => {
    const env = createMockEnv({
      MCP_OAUTH_KV: undefined,
      MCP_JWT_SECRET: TEST_MCP_JWT_SECRET,
    });
    const res = await handleMcpRevoke(formReq("token=abc"), env);
    expect(res.status).toBe(503);
  });

  it("returns 503 when MCP_JWT_SECRET missing", async () => {
    const { env } = envWithKv({ MCP_JWT_SECRET: undefined });
    const res = await handleMcpRevoke(formReq("token=abc"), env);
    expect(res.status).toBe(503);
  });
});

describe("POST /mcp/revoke — body parsing", () => {
  it("returns 400 when token is missing in form body", async () => {
    const { env } = envWithKv();
    const res = await handleMcpRevoke(formReq(""), env);
    expect(res.status).toBe(400);
  });

  it("returns 400 when token is missing in JSON body", async () => {
    const { env } = envWithKv();
    const res = await handleMcpRevoke(jsonReq({}), env);
    expect(res.status).toBe(400);
  });

  it("returns 400 when JSON body unparseable", async () => {
    const { env } = envWithKv();
    const req = new Request(`${ISSUER}/mcp/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not-json{",
    });
    const res = await handleMcpRevoke(req, env);
    expect(res.status).toBe(400);
  });
});

describe("POST /mcp/revoke — refresh_token path", () => {
  it("deletes the refresh KV entry when present", async () => {
    const { env, kv } = envWithKv();
    const raw = "rf_secret_value";
    const hash = await sha256Hex(raw);
    kv._data[`refresh:${hash}`] = JSON.stringify({
      sub: "github:alice",
      scope: "mcp.read",
      github_login: "alice",
      expires_at: Date.now() + 10000,
    });

    const res = await handleMcpRevoke(
      formReq(`token=${encodeURIComponent(raw)}&token_type_hint=refresh_token`),
      env,
    );
    expect(res.status).toBe(200);
    expect(kv._data[`refresh:${hash}`]).toBeUndefined();
  });

  it("returns 200 even when the refresh token is unknown (RFC 7009 §2.2)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpRevoke(
      formReq(`token=unknown&token_type_hint=refresh_token`),
      env,
    );
    expect(res.status).toBe(200);
  });
});

describe("POST /mcp/revoke — access_token (JWT) path", () => {
  it("deletes github_token:{sub} for a valid JWT", async () => {
    const { env, kv } = envWithKv();
    kv._data["github_token:github:alice"] = "encrypted-placeholder";
    const jwt = await signMcpJwt(
      { sub: "github:alice", github_login: "alice", scope: "mcp.read", aud: AUD },
      TEST_MCP_JWT_SECRET,
      3600,
    );

    const res = await handleMcpRevoke(
      formReq(`token=${encodeURIComponent(jwt)}&token_type_hint=access_token`),
      env,
    );
    expect(res.status).toBe(200);
    expect(kv._data["github_token:github:alice"]).toBeUndefined();
  });

  it("returns 200 when JWT signature is invalid (best-effort revoke)", async () => {
    const { env, kv } = envWithKv();
    kv._data["github_token:github:alice"] = "encrypted-placeholder";
    const res = await handleMcpRevoke(formReq(`token=a.b.c&token_type_hint=access_token`), env);
    expect(res.status).toBe(200);
    // bad sig → no deletion happens
    expect(kv._data["github_token:github:alice"]).toBeDefined();
  });

  it("returns 200 when no token_type_hint and token looks like a JWT", async () => {
    const { env, kv } = envWithKv();
    kv._data["github_token:github:alice"] = "x";
    const jwt = await signMcpJwt(
      { sub: "github:alice", github_login: "alice", scope: "", aud: AUD },
      TEST_MCP_JWT_SECRET,
      3600,
    );
    const res = await handleMcpRevoke(formReq(`token=${encodeURIComponent(jwt)}`), env);
    expect(res.status).toBe(200);
    expect(kv._data["github_token:github:alice"]).toBeUndefined();
  });
});

describe("POST /mcp/revoke — wrong hint falls back to other shape", () => {
  it("hint=access_token on a refresh-shaped token still deletes refresh KV", async () => {
    const { env, kv } = envWithKv();
    const raw = "rfopaque";
    const hash = await sha256Hex(raw);
    kv._data[`refresh:${hash}`] = "{}";
    const res = await handleMcpRevoke(
      formReq(`token=${encodeURIComponent(raw)}&token_type_hint=access_token`),
      env,
    );
    expect(res.status).toBe(200);
    expect(kv._data[`refresh:${hash}`]).toBeUndefined();
  });
});

describe("POST /mcp/revoke — JSON body equivalent", () => {
  it("accepts token via JSON body", async () => {
    const { env, kv } = envWithKv();
    const raw = "rfvalue";
    const hash = await sha256Hex(raw);
    kv._data[`refresh:${hash}`] = "{}";
    const res = await handleMcpRevoke(
      jsonReq({ token: raw, token_type_hint: "refresh_token" }),
      env,
    );
    expect(res.status).toBe(200);
    expect(kv._data[`refresh:${hash}`]).toBeUndefined();
  });
});
