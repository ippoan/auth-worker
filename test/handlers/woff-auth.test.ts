import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import { createMockEnv } from "../helpers/mock-env";
import { handleWoffAuth, handleWoffConfig } from "../../src/handlers/woff-auth";

afterAll(() => {
  vi.restoreAllMocks();
});

// ---------- handleWoffAuth ----------

describe("handleWoffAuth", () => {
  const env = createMockEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 400 for invalid JSON body", async () => {
    const req = new Request("https://auth.test.example/auth/woff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not-json",
    });
    const res = await handleWoffAuth(req, env);
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Invalid JSON body");
  });

  it("returns 400 when accessToken is missing", async () => {
    const req = new Request("https://auth.test.example/auth/woff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domainId: "ohishi", redirectUri: "https://app1.test.example/page" }),
    });
    const res = await handleWoffAuth(req, env);
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("accessToken and domainId are required");
  });

  it("returns 400 when domainId is missing", async () => {
    const req = new Request("https://auth.test.example/auth/woff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ accessToken: "tok", redirectUri: "https://app1.test.example/page" }),
    });
    const res = await handleWoffAuth(req, env);
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("accessToken and domainId are required");
  });

  it("returns 400 when redirectUri is missing", async () => {
    const req = new Request("https://auth.test.example/auth/woff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ accessToken: "tok", domainId: "ohishi" }),
    });
    const res = await handleWoffAuth(req, env);
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Invalid or missing redirect_uri");
  });

  it("returns 400 when redirectUri is not in allowed origins", async () => {
    const req = new Request("https://auth.test.example/auth/woff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        accessToken: "tok",
        domainId: "ohishi",
        redirectUri: "https://evil.example/page",
      }),
    });
    const res = await handleWoffAuth(req, env);
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Invalid or missing redirect_uri");
  });

  it("passes through error from backend", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("Unauthorized", { status: 401 })),
    );
    const req = new Request("https://auth.test.example/auth/woff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        accessToken: "tok",
        domainId: "ohishi",
        redirectUri: "https://app1.test.example/page",
      }),
    });
    const res = await handleWoffAuth(req, env);
    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Unauthorized");
  });

  it("returns token, expiresAt, and orgId on success", async () => {
    // JWT payload: {"tenant_id":"test-org"} base64 = eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9
    const fakeToken = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9.sig";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ token: fakeToken, expires_at: "2025-12-31T00:00:00Z" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const req = new Request("https://auth.test.example/auth/woff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        accessToken: "tok",
        domainId: "ohishi",
        redirectUri: "https://app1.test.example/page",
      }),
    });
    const res = await handleWoffAuth(req, env);
    expect(res.status).toBe(200);
    const data = (await res.json()) as { token: string; expiresAt: string; orgId: string };
    expect(data.token).toBe(fakeToken);
    expect(data.expiresAt).toBe("2025-12-31T00:00:00Z");
    expect(data.orgId).toBe("test-org");
  });

  it("sets logi_auth_token cookie on success", async () => {
    const fakeToken = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJ0ZXN0LW9yZyJ9.sig";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ token: fakeToken, expires_at: "2025-12-31T00:00:00Z" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const req = new Request("https://auth.test.example/auth/woff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        accessToken: "tok",
        domainId: "ohishi",
        redirectUri: "https://app1.test.example/page",
      }),
    });
    const res = await handleWoffAuth(req, env);
    expect(res.headers.get("Set-Cookie")).toContain(`logi_auth_token=${fakeToken}`);
  });

  it("extracts orgId from 'org' claim when tenant_id absent", async () => {
    // {"org":"org-from-claim"} base64
    const payload = btoa(JSON.stringify({ org: "org-from-claim" }));
    const fakeToken = `eyJhbGciOiJIUzI1NiJ9.${payload}.sig`;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ token: fakeToken, expires_at: "2025-12-31T00:00:00Z" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const req = new Request("https://auth.test.example/auth/woff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        accessToken: "tok",
        domainId: "ohishi",
        redirectUri: "https://app1.test.example/page",
      }),
    });
    const res = await handleWoffAuth(req, env);
    expect(res.status).toBe(200);
    const data = (await res.json()) as { orgId: string };
    expect(data.orgId).toBe("org-from-claim");
  });

  it("returns empty orgId when JWT payload is not decodable", async () => {
    const fakeToken = "header.!!!invalid-base64!!!.sig";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ token: fakeToken, expires_at: "2025-12-31T00:00:00Z" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const req = new Request("https://auth.test.example/auth/woff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        accessToken: "tok",
        domainId: "ohishi",
        redirectUri: "https://app1.test.example/page",
      }),
    });
    const res = await handleWoffAuth(req, env);
    expect(res.status).toBe(200);
    const data = (await res.json()) as { orgId: string };
    expect(data.orgId).toBe("");
  });

  it("returns empty orgId when token has no second segment", async () => {
    const fakeToken = "no-dots-token";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ token: fakeToken, expires_at: "2025-12-31T00:00:00Z" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const req = new Request("https://auth.test.example/auth/woff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        accessToken: "tok",
        domainId: "ohishi",
        redirectUri: "https://app1.test.example/page",
      }),
    });
    const res = await handleWoffAuth(req, env);
    expect(res.status).toBe(200);
    const data = (await res.json()) as { orgId: string };
    expect(data.orgId).toBe("");
  });

  it("extracts orgId/email from a base64url JWT payload containing `-`/`_` (Refs #529)", async () => {
    // 実運用の JWT (jwt.ts の base64UrlEncodeStr) は base64url で、payload に
    // `-`/`_` が乗ることがある。旧実装 (atob() 直呼び) はこの payload で
    // InvalidCharacterError → orgId/email が空文字になり、ohishi-exp origin
    // 宛て WOFF ログインが常時 ACL 拒否されていた。
    // payload: {"tenant_id":"allowed-tenant","email":"u0@example.com","name":"大石 太郎"}
    const payloadB64Url =
      "eyJ0ZW5hbnRfaWQiOiJhbGxvd2VkLXRlbmFudCIsImVtYWlsIjoidTBAZXhhbXBsZS5jb20iLCJuYW1lIjoi5aSn55-zIOWkqumDjiJ9";
    expect(payloadB64Url).toContain("-");
    expect(() => atob(payloadB64Url)).toThrow();

    const { createMockKV } = await import("../helpers/mock-env");
    const aclEnv = createMockEnv({
      AUTH_CONFIG: createMockKV({
        "origins:prod": "https://dtako-admin.example",
        "app-orgs": JSON.stringify({ "dtako-admin": "ohishi-exp" }),
      }),
      TENANT_ACL: JSON.stringify({ "ohishi-exp": ["allowed-tenant"] }),
    });
    const jwt = `h.${payloadB64Url}.sig`;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ token: jwt, expires_at: "2025-12-31T00:00:00Z" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const req = new Request("https://auth.test.example/auth/woff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        accessToken: "tok",
        domainId: "ohishi",
        redirectUri: "https://dtako-admin.example/page",
      }),
    });
    const res = await handleWoffAuth(req, aclEnv);
    // ACL 上は allowed-tenant なので 403 にならず 200 で orgId が返る。
    expect(res.status).toBe(200);
    const data = (await res.json()) as { orgId: string };
    expect(data.orgId).toBe("allowed-tenant");
  });

  it("returns 403 when tenant is not in TENANT_ACL for an ohishi-exp redirect target", async () => {
    const { createMockKV } = await import("../helpers/mock-env");
    const aclEnv = createMockEnv({
      AUTH_CONFIG: createMockKV({
        "origins:prod": "https://dtako-admin.example",
        "app-orgs": JSON.stringify({ "dtako-admin": "ohishi-exp" }),
      }),
      TENANT_ACL: JSON.stringify({ "ohishi-exp": ["allowed-tenant"] }),
    });
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJub3QtYWxsb3dlZCJ9.sig";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ token: jwt, expires_at: "2025-12-31T00:00:00Z" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const req = new Request("https://auth.test.example/auth/woff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        accessToken: "tok",
        domainId: "ohishi",
        redirectUri: "https://dtako-admin.example/page",
      }),
    });
    const res = await handleWoffAuth(req, aclEnv);
    expect(res.status).toBe(403);
    const data = (await res.json()) as { error: string };
    expect(data.error).toContain("許可されていません");
  });
});

// ---------- handleWoffConfig ----------

describe("handleWoffConfig", () => {
  const env = createMockEnv();
  beforeEach(() => vi.restoreAllMocks());

  it("returns 400 when domain param is missing", async () => {
    const req = new Request("https://auth.test.example/auth/woff-config");
    const res = await handleWoffConfig(req, env);
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("domain parameter required");
  });

  it("passes through error from backend (404)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("Not Found", { status: 404 })),
    );
    const req = new Request("https://auth.test.example/auth/woff-config?domain=unknown");
    const res = await handleWoffConfig(req, env);
    expect(res.status).toBe(404);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Not Found");
  });

  it("returns woffId on success", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify({ woff_id: "woff-sdk-id-123" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const req = new Request("https://auth.test.example/auth/woff-config?domain=ohishi");
    const res = await handleWoffConfig(req, env);
    expect(res.status).toBe(200);
    const data = (await res.json()) as { woffId: string };
    expect(data.woffId).toBe("woff-sdk-id-123");
  });
});
