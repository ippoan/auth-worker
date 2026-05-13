import { describe, it, expect } from "vitest";
import {
  handleMcpDeviceVerify,
  normalizeUserCode,
} from "../../src/handlers/mcp-device-verify";
import {
  createMockEnv,
  createMockKV,
  type MockKV,
} from "../helpers/mock-env";
import type { Env } from "../../src/index";
import type { DeviceCodeRecord } from "../../src/lib/mcp-kv";

const ISSUER = "https://auth.test.example";

function envWithKv(initial: Record<string, string> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV(initial) as MockKV;
  const env = createMockEnv({ MCP_OAUTH_KV: kv, AUTH_WORKER_ORIGIN: ISSUER });
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
  return new Request(`${ISSUER}/device/verify`, {
    method: "POST",
    headers,
    body,
  });
}

describe("normalizeUserCode", () => {
  it("upcases and inserts hyphen for 8-letter input", () => {
    expect(normalizeUserCode("bcdfghjk")).toBe("BCDF-GHJK");
    expect(normalizeUserCode("BCDFGHJK")).toBe("BCDF-GHJK");
  });

  it("strips embedded whitespace and hyphens", () => {
    expect(normalizeUserCode("bcdf-ghjk")).toBe("BCDF-GHJK");
    expect(normalizeUserCode("BCDF GHJK")).toBe("BCDF-GHJK");
    expect(normalizeUserCode("  BC DF-GH JK  ")).toBe("BCDF-GHJK");
  });

  it("returns upcased trimmed input when not 8 letters", () => {
    expect(normalizeUserCode(" foo ")).toBe("FOO");
    expect(normalizeUserCode("toolongxxx")).toBe("TOOLONGXXX");
  });
});

describe("POST /device/verify — guards", () => {
  it("returns 503 when MCP_OAUTH_KV is not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined, AUTH_WORKER_ORIGIN: ISSUER });
    const res = await handleMcpDeviceVerify(postForm({}), env);
    expect(res.status).toBe(503);
    expect(await res.text()).toContain("not configured");
  });

  it("falls back to https://auth.ippoan.org issuer when AUTH_WORKER_ORIGIN is empty", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined, AUTH_WORKER_ORIGIN: "" });
    const res = await handleMcpDeviceVerify(postForm({}), env);
    expect(res.status).toBe(503);
    // security banner host comes from fallback
    expect(await res.text()).toContain("auth.ippoan.org");
  });

  it("treats absent user_code form field as invalid (covers ?? '' null branch)", async () => {
    const { env } = envWithKv();
    // post-form with action only, no user_code — form.get('user_code') returns null
    const res = await handleMcpDeviceVerify(postForm({ other: "x" }), env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Invalid user_code");
  });

  it("returns 403 when Origin header is missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpDeviceVerify(
      postForm({ user_code: "BCDF-GHJK" }, { origin: null }),
      env,
    );
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("Origin mismatch");
  });

  it("returns 403 when Origin header differs", async () => {
    const { env } = envWithKv();
    const res = await handleMcpDeviceVerify(
      postForm({ user_code: "BCDF-GHJK" }, { origin: "https://evil.example" }),
      env,
    );
    expect(res.status).toBe(403);
  });

  it("returns 400 when body is not form-encoded", async () => {
    const { env } = envWithKv();
    const req = new Request(`${ISSUER}/device/verify`, {
      method: "POST",
      headers: { Origin: ISSUER, "Content-Type": "application/json" },
      body: "not-form-encoded-{invalid",
    });
    const res = await handleMcpDeviceVerify(req, env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("form-encoded");
  });
});

describe("POST /device/verify — user_code validation", () => {
  it("returns 400 for invalid user_code format", async () => {
    const { env } = envWithKv();
    const res = await handleMcpDeviceVerify(postForm({ user_code: "1234567" }), env);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Invalid user_code");
  });

  it("returns 404 for unknown user_code (no user_code:* in KV)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpDeviceVerify(postForm({ user_code: "ZZZZ-ZZZZ" }), env);
    expect(res.status).toBe(404);
    expect(await res.text()).toContain("not found or expired");
  });

  it("returns 410 when user_code points to a device_code that is gone", async () => {
    // user_code:* exists but device_code:* expired/missing
    const kv = createMockKV({
      "user_code:BCDF-GHJK": "missing-device-code",
    }) as MockKV;
    const env = createMockEnv({ MCP_OAUTH_KV: kv, AUTH_WORKER_ORIGIN: ISSUER });
    const res = await handleMcpDeviceVerify(postForm({ user_code: "BCDF-GHJK" }), env);
    expect(res.status).toBe(410);
  });

  it("returns 409 when status is already approved", async () => {
    const r = rec({ status: "approved" });
    const { env } = envWithKv({
      [`user_code:${r.user_code}`]: r.device_code,
      [`device_code:${r.device_code}`]: JSON.stringify(r),
    });
    const res = await handleMcpDeviceVerify(
      postForm({ user_code: r.user_code }),
      env,
    );
    expect(res.status).toBe(409);
    expect(await res.text()).toContain("approved");
  });

  it("returns 409 when status is already denied", async () => {
    const r = rec({ status: "denied" });
    const { env } = envWithKv({
      [`user_code:${r.user_code}`]: r.device_code,
      [`device_code:${r.device_code}`]: JSON.stringify(r),
    });
    const res = await handleMcpDeviceVerify(
      postForm({ user_code: r.user_code }),
      env,
    );
    expect(res.status).toBe(409);
    expect(await res.text()).toContain("denied");
  });
});

describe("POST /device/verify — happy path", () => {
  it("returns consent page for a pending user_code", async () => {
    const r = rec();
    const { env } = envWithKv({
      [`user_code:${r.user_code}`]: r.device_code,
      [`device_code:${r.device_code}`]: JSON.stringify(r),
    });
    const res = await handleMcpDeviceVerify(
      postForm({ user_code: r.user_code }),
      env,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    const body = await res.text();
    expect(body).toContain("Approve this device?");
    expect(body).toContain(r.client_id);
    expect(body).toContain(r.scope);
    expect(body).toContain(r.user_code);
  });

  it("accepts non-canonical user_code via normalizeUserCode", async () => {
    const r = rec({ user_code: "BCDF-GHJK" });
    const { env } = envWithKv({
      [`user_code:BCDF-GHJK`]: r.device_code,
      [`device_code:${r.device_code}`]: JSON.stringify(r),
    });
    const res = await handleMcpDeviceVerify(
      postForm({ user_code: "bcdfghjk" }),
      env,
    );
    expect(res.status).toBe(200);
  });
});
