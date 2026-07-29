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
    expect(body.scopes_supported).toEqual([
      "mcp.read",
      "mcp.write",
      "mcp.workflow",
      "mcp.project",
      "offline_access",
    ]);
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

// issue #438: Google IdP surface variant — issuer は `<origin>/mcp/google`、
// authorize だけ専用 path。他 endpoint は既定 surface と共有。
describe("GET AS metadata — google surface (issue #438)", () => {
  function callGoogle(env: Env): Response {
    const req = new Request(
      "https://auth.test.example/.well-known/oauth-authorization-server/mcp/google",
    );
    return handleMcpAsMetadata(req, env, "google");
  }

  it("issuer is <origin>/mcp/google and authorization_endpoint is /mcp/google/authorize", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://issuer.example" });
    const body = (await callGoogle(env).json()) as {
      issuer: string;
      authorization_endpoint: string;
    };
    expect(body.issuer).toBe("https://issuer.example/mcp/google");
    expect(body.authorization_endpoint).toBe("https://issuer.example/mcp/google/authorize");
  });

  it("token / registration / introspection endpoints stay on the shared paths", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://issuer.example" });
    const body = (await callGoogle(env).json()) as {
      token_endpoint: string;
      registration_endpoint: string;
      introspection_endpoint: string;
      device_authorization_endpoint: string;
    };
    expect(body.token_endpoint).toBe("https://issuer.example/mcp/token");
    expect(body.registration_endpoint).toBe("https://issuer.example/mcp/register");
    expect(body.introspection_endpoint).toBe("https://issuer.example/mcp/introspect");
    expect(body.device_authorization_endpoint).toBe(
      "https://issuer.example/mcp/device_authorization",
    );
  });

  it("falls back to https://auth.ippoan.org when AUTH_WORKER_ORIGIN is empty", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "" });
    const body = (await callGoogle(env).json()) as { issuer: string };
    expect(body.issuer).toBe("https://auth.ippoan.org/mcp/google");
  });
});

// RFC 9207 §2.3 (issue #449): iss を載せる AS は本 flag の advertise が MUST。
describe("handleMcpAsMetadata — RFC 9207 advertisement (issue #449)", () => {
  it("advertises authorization_response_iss_parameter_supported on both surfaces", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth.test.example" });
    const def = await handleMcpAsMetadata(new Request("https://auth.test.example/.well-known/oauth-authorization-server"), env).json() as Record<string, unknown>;
    expect(def["authorization_response_iss_parameter_supported"]).toBe(true);
    const goog = await handleMcpAsMetadata(new Request("https://auth.test.example/mcp/google/.well-known/oauth-authorization-server"), env, "google").json() as Record<string, unknown>;
    expect(goog["authorization_response_iss_parameter_supported"]).toBe(true);
  });
});

// CIMD (SEP-991、issue #449 PR-B) の advertise。
describe("handleMcpAsMetadata — CIMD advertisement (issue #449 PR-B)", () => {
  it("advertises client_id_metadata_document_supported on both surfaces", async () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth.test.example" });
    const def = await handleMcpAsMetadata(new Request("https://auth.test.example/.well-known/oauth-authorization-server"), env).json() as Record<string, unknown>;
    expect(def["client_id_metadata_document_supported"]).toBe(true);
    const goog = await handleMcpAsMetadata(new Request("https://auth.test.example/mcp/google/.well-known/oauth-authorization-server"), env, "google").json() as Record<string, unknown>;
    expect(goog["client_id_metadata_document_supported"]).toBe(true);
  });
});
