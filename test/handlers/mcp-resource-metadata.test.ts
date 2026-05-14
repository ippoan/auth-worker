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
    expect(body.scopes_supported).toEqual(["mcp.read", "mcp.write", "offline_access"]);
  });
});
