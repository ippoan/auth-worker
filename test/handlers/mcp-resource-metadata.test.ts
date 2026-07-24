/**
 * `GET /.well-known/oauth-protected-resource` unit test (issue #126 / Phase 4).
 *
 * MCP Authorization spec / RFC 9728 に従い、resource server の metadata と
 * 委譲先 AS の URL を JSON で返すことを検証する。
 */

import { describe, it, expect } from "vitest";
import { handleMcpResourceMetadata } from "../../src/handlers/mcp-resource-metadata";
import { createMockEnv } from "../helpers/mock-env";
import type { Env } from "../../src/index";

function call(env: Env): Response {
  const req = new Request("https://auth.test.example/.well-known/oauth-protected-resource");
  return handleMcpResourceMetadata(req, env);
}

describe("GET /.well-known/oauth-protected-resource", () => {
  it("returns 200 with application/json + CORS + edge cache headers", async () => {
    const res = call(createMockEnv());
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("application/json");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=3600");
  });

  it("resource is the MCP relay origin derived from AUTH_WORKER_ORIGIN", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth-staging.ippoan.org" });
    const body = (await call(env).json()) as { resource: string };
    expect(body.resource).toBe("https://mcp-staging.ippoan.org");
  });

  it("authorization_servers references AUTH_WORKER_ORIGIN", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://issuer.example" });
    const body = (await call(env).json()) as { authorization_servers: string[] };
    expect(body.authorization_servers).toEqual(["https://issuer.example"]);
  });

  it("falls back to ippoan.org defaults when AUTH_WORKER_ORIGIN is empty", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "" });
    const body = (await call(env).json()) as {
      resource: string;
      authorization_servers: string[];
    };
    expect(body.resource).toBe("https://mcp.ippoan.org");
    expect(body.authorization_servers).toEqual(["https://auth.ippoan.org"]);
  });

  it("advertises bearer_methods_supported and scopes_supported", async () => {
    const body = (await call(createMockEnv()).json()) as {
      bearer_methods_supported: string[];
      scopes_supported: string[];
    };
    expect(body.bearer_methods_supported).toEqual(["header"]);
    expect(body.scopes_supported).toEqual([
      "mcp.read",
      "mcp.write",
      "mcp.workflow",
      "mcp.project",
      "offline_access",
    ]);
  });
});

// issue #438: Google IdP surface の PRM。resource は `<auth origin>/mcp/google`、
// authorization_servers は path 付き issuer `<auth origin>/mcp/google` を返す。
describe("GET /.well-known/oauth-protected-resource/mcp/google (issue #438)", () => {
  function callPath(env: Env, path: string): Response {
    const req = new Request(`https://auth.test.example${path}`);
    return handleMcpResourceMetadata(req, env);
  }

  it("returns the google-surface resource + path-scoped authorization server", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth-staging.ippoan.org" });
    const res = callPath(env, "/.well-known/oauth-protected-resource/mcp/google");
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=3600");
    const body = (await res.json()) as {
      resource: string;
      authorization_servers: string[];
      bearer_methods_supported: string[];
      scopes_supported: string[];
    };
    expect(body.resource).toBe("https://auth-staging.ippoan.org/mcp/google");
    expect(body.authorization_servers).toEqual([
      "https://auth-staging.ippoan.org/mcp/google",
    ]);
    expect(body.bearer_methods_supported).toEqual(["header"]);
    expect(body.scopes_supported).toContain("mcp.read");
  });

  it("accepts a trailing slash", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth-staging.ippoan.org" });
    const res = callPath(env, "/.well-known/oauth-protected-resource/mcp/google/");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { resource: string };
    expect(body.resource).toBe("https://auth-staging.ippoan.org/mcp/google");
  });

  it("does not treat other two-segment suffixes as the google surface (404 via slug regex)", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth-staging.ippoan.org" });
    const res = callPath(env, "/.well-known/oauth-protected-resource/mcp/other");
    expect(res.status).toBe(404);
  });
});

describe("GET /.well-known/oauth-protected-resource/<slug>", () => {
  function callPath(env: Env, path: string): Response {
    const req = new Request(`https://auth.test.example${path}`);
    return handleMcpResourceMetadata(req, env);
  }

  it("returns 200 with resource overridden to the slug-matched allowlist origin", async () => {
    const env = createMockEnv({
      AUTH_WORKER_ORIGIN: "https://auth-staging.ippoan.org",
      MCP_RESOURCE_ORIGINS_ALLOWLIST: "https://security-inventory.ippoan.org",
    } as unknown as Partial<Env>);
    const res = callPath(env, "/.well-known/oauth-protected-resource/security-inventory");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { resource: string; authorization_servers: string[] };
    expect(body.resource).toBe("https://security-inventory.ippoan.org");
    expect(body.authorization_servers).toEqual(["https://auth-staging.ippoan.org"]);
  });

  it("returns 404 for unknown slug (not in MCP_RESOURCE_ORIGINS_ALLOWLIST)", async () => {
    const env = createMockEnv({
      MCP_RESOURCE_ORIGINS_ALLOWLIST: "https://security-inventory.ippoan.org",
    } as unknown as Partial<Env>);
    const res = callPath(env, "/.well-known/oauth-protected-resource/attacker");
    expect(res.status).toBe(404);
  });

  it("returns 404 when MCP_RESOURCE_ORIGINS_ALLOWLIST is empty", async () => {
    const res = callPath(createMockEnv(), "/.well-known/oauth-protected-resource/security-inventory");
    expect(res.status).toBe(404);
  });

  it("base path (no slug) still returns mcpRelayOrigin even with allowlist set", async () => {
    const env = createMockEnv({
      AUTH_WORKER_ORIGIN: "https://auth-staging.ippoan.org",
      MCP_RESOURCE_ORIGINS_ALLOWLIST: "https://security-inventory.ippoan.org",
    } as unknown as Partial<Env>);
    const res = callPath(env, "/.well-known/oauth-protected-resource");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { resource: string };
    expect(body.resource).toBe("https://mcp-staging.ippoan.org");
  });

  // defense-in-depth `if (!m)` branch: routing prefix `/.well-known/oauth-
  // protected-resource/` には一致するが slug の char set (= [A-Za-z0-9-]) に
  // 一致しない path (= 不正 char `.` を含む)。
  it("returns 404 when path matches prefix but slug contains invalid chars", async () => {
    const res = callPath(createMockEnv(), "/.well-known/oauth-protected-resource/bad..slug");
    expect(res.status).toBe(404);
  });
});
