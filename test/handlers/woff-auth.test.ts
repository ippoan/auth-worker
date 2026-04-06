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
