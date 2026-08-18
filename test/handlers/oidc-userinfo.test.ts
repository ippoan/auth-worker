import { describe, it, expect } from "vitest";
import { handleOidcUserinfo } from "../../src/handlers/oidc-userinfo";
import { createMockEnv, createMockKV } from "../helpers/mock-env";
import { putOidcAccessToken } from "../../src/lib/oidc-authcode";
import type { Env } from "../../src/index";

function call(env: Env, auth?: string): Promise<Response> {
  return handleOidcUserinfo(
    new Request("https://auth.test.example/oidc/userinfo", {
      headers: auth ? { Authorization: auth } : {},
    }),
    env,
  );
}

describe("GET /oidc/userinfo", () => {
  it("returns the identity behind a valid access token", async () => {
    const kv = createMockKV();
    await putOidcAccessToken(kv, "at1", {
      sub: "u1",
      email: "taro@ippoan.org",
      name: "大石 太郎",
      tenant_id: "t1",
      role: "admin",
      org_slug: "ippoan",
    });
    const res = await call(createMockEnv({ MCP_OAUTH_KV: kv }), "Bearer at1");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      sub: "u1",
      email: "taro@ippoan.org",
      email_verified: true,
      name: "大石 太郎",
      tenant_id: "t1",
      role: "admin",
      org_slug: "ippoan",
    });
  });

  it("omits optional claims that the identity does not carry", async () => {
    const kv = createMockKV();
    await putOidcAccessToken(kv, "at1", { sub: "u1", email: "a@x" });
    const res = await call(createMockEnv({ MCP_OAUTH_KV: kv }), "Bearer at1");
    expect(await res.json()).toEqual({ sub: "u1", email: "a@x", email_verified: true });
  });

  it("returns 401 with WWW-Authenticate when the Authorization header is missing", async () => {
    const res = await call(createMockEnv({ MCP_OAUTH_KV: createMockKV() }));
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toContain("Bearer");
  });

  it("returns 401 for a non-Bearer scheme", async () => {
    const res = await call(createMockEnv({ MCP_OAUTH_KV: createMockKV() }), "Basic abc");
    expect(res.status).toBe(401);
  });

  it("returns 401 for an unknown or expired token", async () => {
    const res = await call(createMockEnv({ MCP_OAUTH_KV: createMockKV() }), "Bearer nope");
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toContain("invalid_token");
  });

  it("returns 503 when the KV namespace is not bound", async () => {
    const res = await call(createMockEnv({ MCP_OAUTH_KV: undefined }), "Bearer at1");
    expect(res.status).toBe(503);
  });
});
