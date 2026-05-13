import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleMcpDeviceCallback } from "../../src/handlers/mcp-device-callback";
import {
  createMockEnv,
  createMockKV,
  type MockKV,
} from "../helpers/mock-env";
import type { Env } from "../../src/index";
import type { DeviceCodeRecord } from "../../src/lib/mcp-kv";
import { generateOAuthState } from "../../src/lib/security";
import { decryptWithKey } from "../../src/lib/mcp-crypto";

const ISSUER = "https://auth.test.example";
const TEST_OAUTH_STATE_SECRET = "test-oauth-state-secret-32chars!";
const TEST_SSO_KEY = "test-sso-encryption-key-material!";

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

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    GITHUB_MCP_CLIENT_ID: "Iv1.test-github-client",
    GITHUB_MCP_CLIENT_SECRET: "test-github-client-secret",
    OAUTH_STATE_SECRET: TEST_OAUTH_STATE_SECRET,
    MCP_JWT_SECRET: "test-mcp-jwt-secret-32chars!",
    SSO_ENCRYPTION_KEY: TEST_SSO_KEY,
    GITHUB_MCP_USER_ALLOWLIST: '["yhonda-ohishi"]',
    ...overrides,
  });
  return { env, kv };
}

function seedRecord(kv: MockKV, r: DeviceCodeRecord) {
  kv._data[`device_code:${r.device_code}`] = JSON.stringify(r);
  kv._data[`user_code:${r.user_code}`] = r.device_code;
}

async function buildState(deviceCode: string): Promise<string> {
  return generateOAuthState(
    `${ISSUER}/mcp/device_callback`,
    TEST_OAUTH_STATE_SECRET,
    { device_code: deviceCode, provider: "github_mcp" },
  );
}

function callbackReq(opts: { code?: string; state?: string; error?: string }): Request {
  const u = new URL(`${ISSUER}/mcp/device_callback`);
  if (opts.code) u.searchParams.set("code", opts.code);
  if (opts.state) u.searchParams.set("state", opts.state);
  if (opts.error) u.searchParams.set("error", opts.error);
  return new Request(u.toString());
}

function jsonResp(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("handleMcpDeviceCallback — env guards", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("returns 503 when MCP_OAUTH_KV not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined, AUTH_WORKER_ORIGIN: ISSUER });
    const res = await handleMcpDeviceCallback(callbackReq({ code: "x", state: "y" }), env);
    expect(res.status).toBe(503);
  });

  it("returns 503 when GITHUB_MCP_CLIENT_ID missing", async () => {
    const { env } = envWithKv({ GITHUB_MCP_CLIENT_ID: undefined });
    const res = await handleMcpDeviceCallback(callbackReq({ code: "x", state: "y" }), env);
    expect(res.status).toBe(503);
  });

  it("returns 503 when GITHUB_MCP_CLIENT_SECRET missing", async () => {
    const { env } = envWithKv({ GITHUB_MCP_CLIENT_SECRET: undefined });
    const res = await handleMcpDeviceCallback(callbackReq({ code: "x", state: "y" }), env);
    expect(res.status).toBe(503);
  });

  it("returns 503 when MCP_JWT_SECRET missing", async () => {
    const { env } = envWithKv({ MCP_JWT_SECRET: undefined });
    const res = await handleMcpDeviceCallback(callbackReq({ code: "x", state: "y" }), env);
    expect(res.status).toBe(503);
  });

  it("returns 503 when SSO_ENCRYPTION_KEY missing", async () => {
    const { env } = envWithKv({ SSO_ENCRYPTION_KEY: "" });
    const res = await handleMcpDeviceCallback(callbackReq({ code: "x", state: "y" }), env);
    expect(res.status).toBe(503);
  });

  it("returns 503 when OAUTH_STATE_SECRET missing", async () => {
    const { env } = envWithKv({ OAUTH_STATE_SECRET: "" });
    const res = await handleMcpDeviceCallback(callbackReq({ code: "x", state: "y" }), env);
    expect(res.status).toBe(503);
  });

  it("falls back to auth.ippoan.org issuer when AUTH_WORKER_ORIGIN empty", async () => {
    const { env } = envWithKv({ AUTH_WORKER_ORIGIN: "" });
    const res = await handleMcpDeviceCallback(callbackReq({}), env);
    expect(res.status).toBe(400); // missing code/state
    expect(await res.text()).toContain("auth.ippoan.org");
  });
});

describe("handleMcpDeviceCallback — request validation", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("returns 400 with 'Authorization denied' when ?error= is present", async () => {
    const { env } = envWithKv();
    const res = await handleMcpDeviceCallback(callbackReq({ error: "access_denied" }), env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Authorization denied");
  });

  it("returns 400 when code missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpDeviceCallback(callbackReq({ state: "x" }), env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Invalid request");
  });

  it("returns 400 when state missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpDeviceCallback(callbackReq({ code: "x" }), env);
    expect(res.status).toBe(400);
  });

  it("returns 400 when state signature invalid (tampered)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpDeviceCallback(
      callbackReq({ code: "x", state: "tampered.signature" }),
      env,
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Invalid state");
  });

  it("returns 400 when state.provider !== 'github_mcp'", async () => {
    const { env } = envWithKv();
    const state = await generateOAuthState(
      `${ISSUER}/mcp/device_callback`,
      TEST_OAUTH_STATE_SECRET,
      { device_code: "d".repeat(64), provider: "google" },
    );
    const res = await handleMcpDeviceCallback(
      callbackReq({ code: "x", state }),
      env,
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Invalid state");
  });

  it("returns 400 when state has no device_code", async () => {
    const { env } = envWithKv();
    const state = await generateOAuthState(
      `${ISSUER}/mcp/device_callback`,
      TEST_OAUTH_STATE_SECRET,
      { provider: "github_mcp" },
    );
    const res = await handleMcpDeviceCallback(
      callbackReq({ code: "x", state }),
      env,
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Invalid state");
  });
});

describe("handleMcpDeviceCallback — GitHub fetch failures", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("returns 502 + sets denied when GitHub token exchange returns non-200", async () => {
    const { env, kv } = envWithKv();
    const r = rec();
    seedRecord(kv, r);
    const state = await buildState(r.device_code);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      new Response("server error", { status: 500 }),
    ));
    const res = await handleMcpDeviceCallback(callbackReq({ code: "abc", state }), env);
    expect(res.status).toBe(502);
    expect(await res.text()).toContain("GitHub error");
    const stored = JSON.parse(kv._data[`device_code:${r.device_code}`]!);
    expect(stored.status).toBe("denied");
  });

  it("returns 502 + denied when GitHub token exchange response lacks access_token", async () => {
    const { env, kv } = envWithKv();
    const r = rec();
    seedRecord(kv, r);
    const state = await buildState(r.device_code);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      jsonResp({ error: "bad_verification_code" }),
    ));
    const res = await handleMcpDeviceCallback(callbackReq({ code: "abc", state }), env);
    expect(res.status).toBe(502);
    const stored = JSON.parse(kv._data[`device_code:${r.device_code}`]!);
    expect(stored.status).toBe("denied");
  });

  it("returns 502 when GitHub token exchange JSON has neither access_token nor error", async () => {
    // covers the `ghBody.error ?? "no access_token..."` right-side branch
    const { env, kv } = envWithKv();
    const r = rec();
    seedRecord(kv, r);
    const state = await buildState(r.device_code);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResp({})));
    const res = await handleMcpDeviceCallback(callbackReq({ code: "abc", state }), env);
    expect(res.status).toBe(502);
  });

  it("returns 502 + denied when GitHub /user returns non-200", async () => {
    const { env, kv } = envWithKv();
    const r = rec();
    seedRecord(kv, r);
    const state = await buildState(r.device_code);
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "gho_x" }))
        .mockResolvedValueOnce(new Response("", { status: 401 })),
    );
    const res = await handleMcpDeviceCallback(callbackReq({ code: "abc", state }), env);
    expect(res.status).toBe(502);
  });

  it("returns 502 + denied when GitHub /user response lacks login", async () => {
    const { env, kv } = envWithKv();
    const r = rec();
    seedRecord(kv, r);
    const state = await buildState(r.device_code);
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "gho_x" }))
        .mockResolvedValueOnce(jsonResp({ id: 123 })),
    );
    const res = await handleMcpDeviceCallback(callbackReq({ code: "abc", state }), env);
    expect(res.status).toBe(502);
    const stored = JSON.parse(kv._data[`device_code:${r.device_code}`]!);
    expect(stored.status).toBe("denied");
  });
});

describe("handleMcpDeviceCallback — ACL fail-closed", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  async function setup(allowlist: string | undefined) {
    const { env, kv } = envWithKv({ GITHUB_MCP_USER_ALLOWLIST: allowlist });
    const r = rec();
    seedRecord(kv, r);
    const state = await buildState(r.device_code);
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "gho_x" }))
        .mockResolvedValueOnce(jsonResp({ login: "intruder" })),
    );
    return { env, kv, r, state };
  }

  it("denies when ALLOWLIST env is missing", async () => {
    const { env, kv, r, state } = await setup(undefined);
    const res = await handleMcpDeviceCallback(callbackReq({ code: "abc", state }), env);
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("Access denied");
    expect(JSON.parse(kv._data[`device_code:${r.device_code}`]!).status).toBe("denied");
  });

  it("denies when ALLOWLIST is malformed JSON", async () => {
    const { env } = await setup("not-json{");
    const res = await handleMcpDeviceCallback(
      callbackReq({ code: "abc", state: await buildState(rec().device_code) }),
      env,
    );
    expect(res.status).toBe(403);
  });

  it("denies when ALLOWLIST is not an array", async () => {
    const { env } = await setup('{"foo":"bar"}');
    const res = await handleMcpDeviceCallback(
      callbackReq({ code: "abc", state: await buildState(rec().device_code) }),
      env,
    );
    expect(res.status).toBe(403);
  });

  it("denies when ALLOWLIST contains non-string entries", async () => {
    const { env } = await setup('["valid", 123]');
    const res = await handleMcpDeviceCallback(
      callbackReq({ code: "abc", state: await buildState(rec().device_code) }),
      env,
    );
    expect(res.status).toBe(403);
  });

  it("denies when login is not in ALLOWLIST", async () => {
    const { env, kv, r, state } = await setup('["someone-else"]');
    const res = await handleMcpDeviceCallback(callbackReq({ code: "abc", state }), env);
    expect(res.status).toBe(403);
    expect(JSON.parse(kv._data[`device_code:${r.device_code}`]!).status).toBe("denied");
  });
});

describe("handleMcpDeviceCallback — success path", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("approves, stores github_token encrypted, and shows success page", async () => {
    const { env, kv } = envWithKv({
      GITHUB_MCP_USER_ALLOWLIST: '["yhonda-ohishi"]',
    });
    const r = rec();
    seedRecord(kv, r);
    const state = await buildState(r.device_code);
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "gho_secret_token_value" }))
        .mockResolvedValueOnce(jsonResp({ login: "yhonda-ohishi" })),
    );

    const res = await handleMcpDeviceCallback(callbackReq({ code: "abc", state }), env);
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("認証完了");

    // device_code record updated
    const stored = JSON.parse(kv._data[`device_code:${r.device_code}`]!);
    expect(stored.status).toBe("approved");
    expect(stored.github_login).toBe("yhonda-ohishi");
    expect(typeof stored.authorized_at).toBe("number");

    // github_token:{sub} stored encrypted, 30d TTL
    const encrypted = kv._data["github_token:github:yhonda-ohishi"];
    expect(encrypted).toBeDefined();
    expect(kv._ttls["github_token:github:yhonda-ohishi"]).toBe(60 * 60 * 24 * 30);
    const recovered = await decryptWithKey(encrypted as string, TEST_SSO_KEY);
    expect(recovered).toBe("gho_secret_token_value");
  });
});
