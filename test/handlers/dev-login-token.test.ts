import { describe, it, expect } from "vitest";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";
import { handleDevLoginToken } from "../../src/handlers/dev-login-token";
import { DEV_TOKEN_TTL_SEC, issueDevLoginCode } from "../../src/lib/dev-login";
import { signJwt } from "../../src/lib/jwt";
import { TEST_JWT_SECRET } from "../helpers/mock-env";

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({ MCP_OAUTH_KV: kv, ...overrides });
  return { env, kv };
}

function req(body: unknown): Request {
  return new Request("https://auth.test.example/dev-login/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("POST /dev-login/token", () => {
  it("returns 503 when MCP_OAUTH_KV is unbound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    const res = await handleDevLoginToken(req({ code: "x" }), env);
    expect(res.status).toBe(503);
  });

  it("returns 400 on invalid JSON body", async () => {
    const { env } = envWithKv();
    const badReq = new Request("https://auth.test.example/dev-login/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not-json{",
    });
    const res = await handleDevLoginToken(badReq, env);
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("invalid_request");
  });

  it("returns 400 when code is missing", async () => {
    const { env } = envWithKv();
    const res = await handleDevLoginToken(req({}), env);
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("invalid_request");
  });

  it("returns 400 invalid_grant for an unknown/expired code", async () => {
    const { env } = envWithKv();
    const res = await handleDevLoginToken(req({ code: "does-not-exist" }), env);
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("invalid_grant");
  });

  it("exchanges a valid code for the stashed dev JWT and reports expires_in from the token exp claim", async () => {
    const { env } = envWithKv();
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(
      { sub: "user-1", token_kind: "dev", iat: now, exp: now + 900 },
      TEST_JWT_SECRET,
    );
    const code = await issueDevLoginCode(env, token);

    const res = await handleDevLoginToken(req({ code }), env);
    expect(res.status).toBe(200);
    const body = await res.json() as { access_token: string; token_type: string; expires_in: number };
    expect(body.access_token).toBe(token);
    expect(body.token_type).toBe("Bearer");
    // allow small scheduling jitter between mint and exchange in this test
    expect(body.expires_in).toBeGreaterThan(890);
    expect(body.expires_in).toBeLessThanOrEqual(900);
  });

  it("falls back to DEV_TOKEN_TTL_SEC for expires_in when the stashed token has no exp claim", async () => {
    const { env } = envWithKv();
    const code = await issueDevLoginCode(env, "not-a-real-jwt");

    const res = await handleDevLoginToken(req({ code }), env);
    expect(res.status).toBe(200);
    const body = await res.json() as { access_token: string; expires_in: number };
    expect(body.access_token).toBe("not-a-real-jwt");
    expect(body.expires_in).toBe(DEV_TOKEN_TTL_SEC);
  });

  it("code is single-use — a second exchange with the same code fails", async () => {
    const { env } = envWithKv();
    const token = await signJwt(
      { sub: "user-1", exp: Math.floor(Date.now() / 1000) + 900 },
      TEST_JWT_SECRET,
    );
    const code = await issueDevLoginCode(env, token);

    const first = await handleDevLoginToken(req({ code }), env);
    expect(first.status).toBe(200);

    const second = await handleDevLoginToken(req({ code }), env);
    expect(second.status).toBe(400);
    const body = await second.json() as { error: string };
    expect(body.error).toBe("invalid_grant");
  });
});
