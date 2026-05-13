import { describe, it, expect } from "vitest";
import { handleMcpDeviceProceed } from "../../src/handlers/mcp-device-proceed";
import {
  createMockEnv,
  createMockKV,
  type MockKV,
} from "../helpers/mock-env";
import type { Env } from "../../src/index";
import type { DeviceCodeRecord } from "../../src/lib/mcp-kv";
import { verifyOAuthState } from "../../src/lib/security";

const ISSUER = "https://auth.test.example";
const TEST_OAUTH_STATE_SECRET = "test-oauth-state-secret-32chars!";

function envWithKv(initial: Record<string, string> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV(initial) as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    GITHUB_MCP_CLIENT_ID: "Iv1.test-github-client",
    OAUTH_STATE_SECRET: TEST_OAUTH_STATE_SECRET,
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
  opts: { origin?: string | null; contentType?: string; body?: BodyInit } = {},
): Request {
  const headers: Record<string, string> = {};
  if (opts.origin !== null) headers.Origin = opts.origin ?? ISSUER;
  if (opts.contentType) headers["Content-Type"] = opts.contentType;
  const body =
    opts.body ??
    (opts.contentType?.includes("json")
      ? JSON.stringify(fields)
      : new URLSearchParams(fields));
  return new Request(`${ISSUER}/device/proceed`, {
    method: "POST",
    headers,
    body,
  });
}

function seedPendingRecord(): { env: Env; kv: MockKV; r: DeviceCodeRecord } {
  const r = rec();
  const { env, kv } = envWithKv({
    [`user_code:${r.user_code}`]: r.device_code,
    [`device_code:${r.device_code}`]: JSON.stringify(r),
  });
  return { env, kv, r };
}

describe("POST /device/proceed — guards", () => {
  it("returns 503 when MCP_OAUTH_KV not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined, AUTH_WORKER_ORIGIN: ISSUER });
    const res = await handleMcpDeviceProceed(postForm({}), env);
    expect(res.status).toBe(503);
  });

  it("falls back to https://auth.ippoan.org issuer when AUTH_WORKER_ORIGIN is empty", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined, AUTH_WORKER_ORIGIN: "" });
    const res = await handleMcpDeviceProceed(postForm({}), env);
    expect(res.status).toBe(503);
    expect(await res.text()).toContain("auth.ippoan.org");
  });

  it("treats absent user_code form field as invalid (covers ?? '' null branch)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpDeviceProceed(postForm({ action: "approve" }), env);
    expect(res.status).toBe(400);
  });

  it("returns 403 when Origin missing or mismatched", async () => {
    const { env } = envWithKv();
    expect(
      (await handleMcpDeviceProceed(postForm({}, { origin: null }), env)).status,
    ).toBe(403);
    expect(
      (
        await handleMcpDeviceProceed(
          postForm({}, { origin: "https://evil.example" }),
          env,
        )
      ).status,
    ).toBe(403);
  });

  it("returns 400 when body is not form-encoded", async () => {
    const { env } = envWithKv();
    const req = new Request(`${ISSUER}/device/proceed`, {
      method: "POST",
      headers: { Origin: ISSUER, "Content-Type": "application/json" },
      body: "not-form-{",
    });
    const res = await handleMcpDeviceProceed(req, env);
    expect(res.status).toBe(400);
  });

  it("returns 400 when user_code format is invalid", async () => {
    const { env } = envWithKv();
    const res = await handleMcpDeviceProceed(
      postForm({ user_code: "12345", action: "approve" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 when action is missing or unknown", async () => {
    const { env, r } = seedPendingRecord();
    const r1 = await handleMcpDeviceProceed(
      postForm({ user_code: r.user_code }),
      env,
    );
    expect(r1.status).toBe(400);
    expect(await r1.text()).toContain("Invalid action");

    const r2 = await handleMcpDeviceProceed(
      postForm({ user_code: r.user_code, action: "maybe" }),
      env,
    );
    expect(r2.status).toBe(400);
  });

  it("returns 404 when user_code is unknown", async () => {
    const { env } = envWithKv();
    const res = await handleMcpDeviceProceed(
      postForm({ user_code: "ZZZZ-ZZZZ", action: "approve" }),
      env,
    );
    expect(res.status).toBe(404);
  });

  it("returns 410 when device_code record is missing (gone)", async () => {
    const kv = createMockKV({
      "user_code:BCDF-GHJK": "missing-device",
    }) as MockKV;
    const env = createMockEnv({
      MCP_OAUTH_KV: kv,
      AUTH_WORKER_ORIGIN: ISSUER,
      GITHUB_MCP_CLIENT_ID: "Iv1.test",
      OAUTH_STATE_SECRET: TEST_OAUTH_STATE_SECRET,
    });
    const res = await handleMcpDeviceProceed(
      postForm({ user_code: "BCDF-GHJK", action: "approve" }),
      env,
    );
    expect(res.status).toBe(410);
  });

  it("returns 409 when status is already non-pending", async () => {
    const r = rec({ status: "denied" });
    const { env } = envWithKv({
      [`user_code:${r.user_code}`]: r.device_code,
      [`device_code:${r.device_code}`]: JSON.stringify(r),
    });
    const res = await handleMcpDeviceProceed(
      postForm({ user_code: r.user_code, action: "approve" }),
      env,
    );
    expect(res.status).toBe(409);
  });
});

describe("POST /device/proceed — deny", () => {
  it("updates KV status to denied and shows result page", async () => {
    const { env, kv, r } = seedPendingRecord();
    const res = await handleMcpDeviceProceed(
      postForm({ user_code: r.user_code, action: "deny" }),
      env,
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Denied");
    const stored = JSON.parse(kv._data[`device_code:${r.device_code}`] as string);
    expect(stored.status).toBe("denied");
  });
});

describe("POST /device/proceed — approve", () => {
  it("returns 503 when GITHUB_MCP_CLIENT_ID not configured", async () => {
    const r = rec();
    const kv = createMockKV({
      [`user_code:${r.user_code}`]: r.device_code,
      [`device_code:${r.device_code}`]: JSON.stringify(r),
    }) as MockKV;
    const env = createMockEnv({
      MCP_OAUTH_KV: kv,
      AUTH_WORKER_ORIGIN: ISSUER,
      OAUTH_STATE_SECRET: TEST_OAUTH_STATE_SECRET,
      GITHUB_MCP_CLIENT_ID: undefined,
    });
    const res = await handleMcpDeviceProceed(
      postForm({ user_code: r.user_code, action: "approve" }),
      env,
    );
    expect(res.status).toBe(503);
    expect(await res.text()).toContain("not configured");
  });

  it("returns 302 to github.com/login/oauth/authorize with signed state containing device_code", async () => {
    const { env, r } = seedPendingRecord();
    const res = await handleMcpDeviceProceed(
      postForm({ user_code: r.user_code, action: "approve" }),
      env,
    );
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location") ?? "";
    expect(loc).toMatch(/^https:\/\/github\.com\/login\/oauth\/authorize\?/);
    const u = new URL(loc);
    expect(u.searchParams.get("client_id")).toBe("Iv1.test-github-client");
    expect(u.searchParams.get("redirect_uri")).toBe(`${ISSUER}/mcp/device_callback`);
    expect(u.searchParams.get("scope")).toBe("read:user");
    expect(u.searchParams.get("allow_signup")).toBe("false");

    // state should decode to include device_code + provider
    const state = u.searchParams.get("state");
    expect(state).toBeTruthy();
    const decoded = await verifyOAuthState(state as string, TEST_OAUTH_STATE_SECRET);
    expect(decoded).not.toBeNull();
    expect((decoded as { device_code?: string }).device_code).toBe(r.device_code);
    expect((decoded as { provider?: string }).provider).toBe("github_mcp");
  });
});
