import { describe, it, expect } from "vitest";
import { handleMcpIntrospect } from "../../src/handlers/mcp-introspect";
import {
  createMockEnv,
  createMockKV,
  type MockKV,
} from "../helpers/mock-env";
import type { Env } from "../../src/index";
import { signMcpJwt } from "../../src/lib/mcp-jwt";
import { encryptWithKey } from "../../src/lib/mcp-crypto";

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

function req(opts: { auth?: string | null; body?: BodyInit | null; contentType?: string }): Request {
  const headers: Record<string, string> = {};
  if (opts.auth !== null && opts.auth !== undefined) headers.Authorization = opts.auth;
  if (opts.contentType !== undefined) headers["Content-Type"] = opts.contentType;
  else headers["Content-Type"] = "application/json";
  return new Request(`${ISSUER}/mcp/introspect`, {
    method: "POST",
    headers,
    body: opts.body ?? null,
  });
}

async function makeValidJwt(login = "alice", scope = "read:user"): Promise<string> {
  return signMcpJwt(
    { sub: `github:${login}`, github_login: login, scope, aud: AUD },
    TEST_MCP_JWT_SECRET,
    3600,
  );
}

describe("POST /mcp/introspect — env guards", () => {
  it("returns 503 active:false when MCP_OAUTH_KV not bound", async () => {
    const env = createMockEnv({
      MCP_OAUTH_KV: undefined,
      MCP_JWT_SECRET: TEST_MCP_JWT_SECRET,
      SSO_ENCRYPTION_KEY: TEST_SSO_KEY,
      INTERNAL_SHARED_SECRET: TEST_INTERNAL_SECRET,
    });
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(503);
    const body = await res.json() as { active: boolean };
    expect(body.active).toBe(false);
  });

  it("returns 503 when MCP_JWT_SECRET missing", async () => {
    const { env } = envWithKv({ MCP_JWT_SECRET: undefined });
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("returns 503 when SSO_ENCRYPTION_KEY missing", async () => {
    const { env } = envWithKv({ SSO_ENCRYPTION_KEY: "" });
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("returns 503 when INTERNAL_SHARED_SECRET missing", async () => {
    const { env } = envWithKv({ INTERNAL_SHARED_SECRET: undefined });
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(503);
  });
});

describe("POST /mcp/introspect — internal auth", () => {
  it("returns 401 when Authorization header missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpIntrospect(
      req({ auth: null, body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 401 when Authorization value mismatches (different length)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpIntrospect(
      req({ auth: "wrong", body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 401 when Authorization value mismatches (same length)", async () => {
    const { env } = envWithKv();
    const wrong = "x".repeat(TEST_INTERNAL_SECRET.length);
    const res = await handleMcpIntrospect(
      req({ auth: wrong, body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(401);
  });
});

describe("POST /mcp/introspect — body parsing", () => {
  it("returns active:false when body is not JSON", async () => {
    const { env } = envWithKv();
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: "not-json{" }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { active: boolean };
    expect(body.active).toBe(false);
  });

  it("returns active:false when token field missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({}) }),
      env,
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });

  it("returns active:false when token is not a string", async () => {
    const { env } = envWithKv();
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: 123 }) }),
      env,
    );
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });

  it("returns active:false when token is empty string", async () => {
    const { env } = envWithKv();
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: "" }) }),
      env,
    );
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });
});

describe("POST /mcp/introspect — JWT verification", () => {
  it("returns active:false for invalid JWT (wrong signature)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: "a.b.c" }) }),
      env,
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });

  it("returns active:false for expired JWT", async () => {
    const { env } = envWithKv();
    const expired = await signMcpJwt(
      { sub: "github:alice", github_login: "alice", scope: "", aud: AUD },
      TEST_MCP_JWT_SECRET,
      -10,
    );
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: expired }) }),
      env,
    );
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });
});

describe("POST /mcp/introspect — github_token recovery", () => {
  it("returns active:false when github_token:{sub} missing from KV", async () => {
    const { env } = envWithKv();
    const jwt = await makeValidJwt("alice");
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: jwt }) }),
      env,
    );
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });

  it("returns active:false when decrypt fails (wrong key in KV)", async () => {
    const { env, kv } = envWithKv();
    const jwt = await makeValidJwt("alice");
    // poison KV: encrypted with a *different* key
    const poisoned = await encryptWithKey("gho_real_token", "different-key-material-junk!");
    kv._data["github_token:github:alice"] = poisoned;
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: jwt }) }),
      env,
    );
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });

  it("returns active:true + claims + decrypted github_token on success", async () => {
    const { env, kv } = envWithKv();
    const jwt = await makeValidJwt("yhonda-ohishi", "read:user");
    const encrypted = await encryptWithKey("gho_real_github_token", TEST_SSO_KEY);
    kv._data["github_token:github:yhonda-ohishi"] = encrypted;

    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: jwt }) }),
      env,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = await res.json() as {
      active: boolean;
      scope: string;
      sub: string;
      github_login: string;
      github_token: string;
      exp: number;
    };
    expect(body.active).toBe(true);
    expect(body.scope).toBe("read:user");
    expect(body.sub).toBe("github:yhonda-ohishi");
    expect(body.github_login).toBe("yhonda-ohishi");
    expect(body.github_token).toBe("gho_real_github_token");
    expect(typeof body.exp).toBe("number");
  });
});
