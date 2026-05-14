import { describe, it, expect } from "vitest";
import { handleMcpAsMetadata } from "../../src/handlers/mcp-as-metadata";
import { createMockEnv } from "../helpers/mock-env";
import type { Env } from "../../src/index";

function call(env: Env): Response {
  const req = new Request("https://auth.test.example/.well-known/oauth-authorization-server");
  return handleMcpAsMetadata(req, env);
}

describe("GET /.well-known/oauth-authorization-server", () => {
  it("returns 200 with application/json + CORS + edge cache headers", async () => {
    const res = call(createMockEnv());
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("application/json");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=3600");
  });

  it("issuer matches env.AUTH_WORKER_ORIGIN", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth-staging.ippoan.org" });
    const body = (await call(env).json()) as { issuer: string };
    expect(body.issuer).toBe("https://auth-staging.ippoan.org");
  });

  it("falls back to https://auth.ippoan.org when AUTH_WORKER_ORIGIN is empty", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "" });
    const body = (await call(env).json()) as { issuer: string };
    expect(body.issuer).toBe("https://auth.ippoan.org");
  });

  it("device_authorization_endpoint / token_endpoint / introspection_endpoint reference issuer", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://issuer.example" });
    const body = (await call(env).json()) as {
      device_authorization_endpoint: string;
      token_endpoint: string;
      introspection_endpoint: string;
    };
    expect(body.device_authorization_endpoint).toBe("https://issuer.example/mcp/device_authorization");
    expect(body.token_endpoint).toBe("https://issuer.example/mcp/token");
    expect(body.introspection_endpoint).toBe("https://issuer.example/mcp/introspect");
  });

  it("advertises device_code + authorization_code + refresh_token grants and public-client auth", async () => {
    const body = (await call(createMockEnv()).json()) as {
      grant_types_supported: string[];
      token_endpoint_auth_methods_supported: string[];
      scopes_supported: string[];
      response_types_supported: string[];
      code_challenge_methods_supported: string[];
    };
    expect(body.grant_types_supported).toContain("urn:ietf:params:oauth:grant-type:device_code");
    expect(body.grant_types_supported).toContain("authorization_code");
    expect(body.grant_types_supported).toContain("refresh_token");
    expect(body.token_endpoint_auth_methods_supported).toEqual(["none"]);
    expect(body.scopes_supported).toEqual(["mcp.read", "mcp.write", "offline_access"]);
    // Phase 5: Browser client 向け Auth Code grant 追加で response_types に "code"
    expect(body.response_types_supported).toEqual(["code"]);
    expect(body.code_challenge_methods_supported).toEqual(["S256"]);
  });

  // Phase 5 (#128): Browser client (Anthropic Claude.ai) 用 endpoint 追加
  it("includes authorization_endpoint and registration_endpoint (Phase 5 #128)", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://issuer.example" });
    const body = (await call(env).json()) as {
      authorization_endpoint: string;
      registration_endpoint: string;
    };
    expect(body.authorization_endpoint).toBe("https://issuer.example/mcp/authorize");
    expect(body.registration_endpoint).toBe("https://issuer.example/mcp/register");
  });
});
