import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMockEnv, createMockKV, type MockKV, TEST_JWT_SECRET } from "../helpers/mock-env";
import type { Env } from "../../src/index";
import type { McpJwtPayload } from "../../src/lib/mcp-jwt";
import { decodeJwtPayload, verifyJwt } from "../../src/lib/jwt";
import {
  DEV_TOKEN_TTL_SEC,
  consumeDevLoginCode,
  issueDevLoginCode,
  mintDevToken,
} from "../../src/lib/dev-login";

const ALLOWED_SUB = "google:dev@example.com";
const ALLOWLIST = JSON.stringify([ALLOWED_SUB]);

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    DEV_LOGIN_ALLOWED_SUBJECTS: ALLOWLIST,
    ...overrides,
  });
  return { env, kv };
}

function payload(overrides: Partial<McpJwtPayload> = {}): McpJwtPayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    sub: ALLOWED_SUB,
    email: "dev@example.com",
    scope: "mcp.read mcp.write",
    aud: "github-mcp-server-rs",
    iat: now,
    exp: now + 3600,
    ...overrides,
  };
}

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

describe("mintDevToken", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("returns 503 when MCP_OAUTH_KV missing", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    const result = await mintDevToken(env, payload());
    expect(result).toEqual({ kind: "error", error: "server_error", status: 503 });
  });

  it("returns 503 when JWT_SECRET missing", async () => {
    const { env } = envWithKv({ JWT_SECRET: undefined });
    const result = await mintDevToken(env, payload());
    expect(result).toEqual({ kind: "error", error: "server_error", status: 503 });
  });

  it("returns 403 when DEV_LOGIN_ALLOWED_SUBJECTS is unset (fail-closed)", async () => {
    const { env } = envWithKv({ DEV_LOGIN_ALLOWED_SUBJECTS: undefined });
    const result = await mintDevToken(env, payload());
    expect(result).toEqual({ kind: "error", error: "dev_login_not_configured", status: 403 });
  });

  it("returns 403 when DEV_LOGIN_ALLOWED_SUBJECTS is malformed JSON (fail-closed)", async () => {
    const { env } = envWithKv({ DEV_LOGIN_ALLOWED_SUBJECTS: "not-json" });
    const result = await mintDevToken(env, payload());
    expect(result).toEqual({ kind: "error", error: "dev_login_not_configured", status: 403 });
  });

  it("returns 403 when DEV_LOGIN_ALLOWED_SUBJECTS is valid JSON but not an array (fail-closed)", async () => {
    const { env } = envWithKv({ DEV_LOGIN_ALLOWED_SUBJECTS: JSON.stringify({ a: 1 }) });
    const result = await mintDevToken(env, payload());
    expect(result).toEqual({ kind: "error", error: "dev_login_not_configured", status: 403 });
  });

  it("returns 403 when DEV_LOGIN_ALLOWED_SUBJECTS is not a JSON array of strings", async () => {
    const { env } = envWithKv({ DEV_LOGIN_ALLOWED_SUBJECTS: JSON.stringify([1, 2]) });
    const result = await mintDevToken(env, payload());
    expect(result).toEqual({ kind: "error", error: "dev_login_not_configured", status: 403 });
  });

  it("returns 403 when payload.sub is not in the allowlist", async () => {
    const { env } = envWithKv();
    const result = await mintDevToken(env, payload({ sub: "google:someone-else@example.com" }));
    expect(result).toEqual({ kind: "error", error: "not_in_allowlist", status: 403 });
  });

  it("returns 403 when payload has no email (non-Google IdP session)", async () => {
    const { env } = envWithKv();
    const result = await mintDevToken(
      env,
      payload({ sub: ALLOWED_SUB, email: undefined, github_login: "someone" }),
    );
    expect(result).toEqual({ kind: "error", error: "google_login_required", status: 403 });
  });

  it("returns 403 when google_sub is not cached for the email", async () => {
    const { env } = envWithKv();
    const result = await mintDevToken(env, payload());
    expect(result).toEqual({ kind: "error", error: "google_sub_not_cached", status: 403 });
  });

  it("returns 403 when upsertGoogleUser finds no tenant for the email", async () => {
    const { env, kv } = envWithKv();
    kv._data["google_sub:dev@example.com"] = "google-sub-xyz";
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: "no_tenant_for_email" }), { status: 403 }),
    );
    const result = await mintDevToken(env, payload());
    expect(result).toEqual({ kind: "error", error: "no_tenant_for_email", status: 403 });
  });

  it("returns 500 when the internal upsertGoogleUser call throws", async () => {
    const { env, kv } = envWithKv();
    kv._data["google_sub:dev@example.com"] = "google-sub-xyz";
    globalThis.fetch = vi.fn().mockResolvedValue(new Response("boom", { status: 500 }));
    const result = await mintDevToken(env, payload());
    expect(result).toEqual({ kind: "error", error: "server_error", status: 500 });
  });

  it("mints a dev JWT with token_kind=dev and the user's AppClaims on success", async () => {
    const { env, kv } = envWithKv();
    kv._data["google_sub:dev@example.com"] = "google-sub-xyz";
    globalThis.fetch = vi.fn().mockResolvedValue(internalUserResponse());

    const result = await mintDevToken(env, payload());
    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") throw new Error("unreachable");
    expect(result.expires_in).toBe(DEV_TOKEN_TTL_SEC);

    const verified = await verifyJwt(result.token, TEST_JWT_SECRET);
    expect(verified).not.toBeNull();
    expect(verified?.sub).toBe("user-uuid-1");
    expect(verified?.email).toBe("dev@example.com");
    expect(verified?.name).toBe("Dev User");
    expect(verified?.tenant_id).toBe("tenant-uuid-1");
    expect(verified?.role).toBe("admin");
    expect(verified?.org_slug).toBe("acme");
    expect(verified?.token_kind).toBe("dev");
    expect((verified?.exp as number) - (verified?.iat as number)).toBe(DEV_TOKEN_TTL_SEC);
  });

  it("omits org_slug when the user has no tenant slug", async () => {
    const { env, kv } = envWithKv();
    kv._data["google_sub:dev@example.com"] = "google-sub-xyz";
    globalThis.fetch = vi.fn().mockResolvedValue(internalUserResponse({ slug: null }));

    const result = await mintDevToken(env, payload());
    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") throw new Error("unreachable");
    const claims = decodeJwtPayload(result.token);
    expect(claims?.org_slug).toBeUndefined();
  });

  it("calls upsertGoogleUser with the cached google_sub and email as name", async () => {
    const { env, kv } = envWithKv();
    kv._data["google_sub:dev@example.com"] = "google-sub-xyz";
    const mockFetch = vi.fn().mockResolvedValue(internalUserResponse());
    globalThis.fetch = mockFetch;

    await mintDevToken(env, payload());

    const call = mockFetch.mock.calls[0]!;
    const url = call[0] as string;
    const init = call[1] as RequestInit;
    expect(url).toBe("https://alc-api.test.example/api/internal/auth/users/upsert-google");
    const sentBody = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(sentBody).toEqual({
      google_sub: "google-sub-xyz",
      email: "dev@example.com",
      name: "dev@example.com",
    });
  });
});

describe("issueDevLoginCode / consumeDevLoginCode", () => {
  it("round-trips a token through a one-time code", async () => {
    const { env, kv } = envWithKv();
    const code = await issueDevLoginCode(env, "the-dev-jwt");
    expect(kv._ttls[`dev_code:${code}`]).toBe(60);

    const consumed = await consumeDevLoginCode(env, code);
    expect(consumed).toBe("the-dev-jwt");
  });

  it("is single-use — a second consume returns null", async () => {
    const { env } = envWithKv();
    const code = await issueDevLoginCode(env, "the-dev-jwt");
    await consumeDevLoginCode(env, code);
    const second = await consumeDevLoginCode(env, code);
    expect(second).toBeNull();
  });

  it("consumeDevLoginCode returns null for an unknown code", async () => {
    const { env } = envWithKv();
    const result = await consumeDevLoginCode(env, "does-not-exist");
    expect(result).toBeNull();
  });

  it("consumeDevLoginCode returns null when MCP_OAUTH_KV is unbound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    const result = await consumeDevLoginCode(env, "whatever");
    expect(result).toBeNull();
  });

  it("issueDevLoginCode throws when MCP_OAUTH_KV is unbound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    await expect(issueDevLoginCode(env, "x")).rejects.toThrow("MCP_OAUTH_KV not bound");
  });

  it("consumeDevLoginCode returns null for a malformed KV record", async () => {
    const { env, kv } = envWithKv();
    kv._data["dev_code:bad"] = "not-json{";
    const result = await consumeDevLoginCode(env, "bad");
    expect(result).toBeNull();
  });

  it("consumeDevLoginCode returns null when the record has no string token field", async () => {
    const { env, kv } = envWithKv();
    kv._data["dev_code:no-token"] = JSON.stringify({ not_token: "x" });
    const result = await consumeDevLoginCode(env, "no-token");
    expect(result).toBeNull();
  });
});
