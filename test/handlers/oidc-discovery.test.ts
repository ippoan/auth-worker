import { describe, it, expect } from "vitest";
import { handleOidcDiscovery } from "../../src/handlers/oidc-discovery";
import { createMockEnv } from "../helpers/mock-env";
import type { Env } from "../../src/index";

function body(env: Env): Promise<Record<string, unknown>> {
  return handleOidcDiscovery(
    new Request("https://auth.test.example/oidc/.well-known/openid-configuration"),
    env,
  ).json() as Promise<Record<string, unknown>>;
}

describe("GET /oidc/.well-known/openid-configuration", () => {
  it("returns 200 with JSON + CORS + edge cache headers", () => {
    const res = handleOidcDiscovery(
      new Request("https://auth.test.example/oidc/.well-known/openid-configuration"),
      createMockEnv(),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("application/json");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=3600");
  });

  it("issuer is path-scoped so it cannot be confused with the MCP surface", async () => {
    const b = await body(createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth.ippoan.org" }));
    expect(b.issuer).toBe("https://auth.ippoan.org/oidc");
  });

  it("falls back to the prod origin when AUTH_WORKER_ORIGIN is empty", async () => {
    expect((await body(createMockEnv({ AUTH_WORKER_ORIGIN: "" }))).issuer).toBe(
      "https://auth.ippoan.org/oidc",
    );
  });

  it("every endpoint lives under the /oidc surface", async () => {
    const b = await body(createMockEnv({ AUTH_WORKER_ORIGIN: "https://issuer.example" }));
    expect(b.authorization_endpoint).toBe("https://issuer.example/oidc/authorize");
    expect(b.token_endpoint).toBe("https://issuer.example/oidc/token");
    expect(b.userinfo_endpoint).toBe("https://issuer.example/oidc/userinfo");
    expect(b.jwks_uri).toBe("https://issuer.example/oidc/.well-known/jwks.json");
  });

  it("advertises ES256 only — never a symmetric alg for this surface", async () => {
    const b = await body(createMockEnv());
    expect(b.id_token_signing_alg_values_supported).toEqual(["ES256"]);
  });

  it("advertises confidential-client auth (unlike the public-client MCP surface)", async () => {
    const b = await body(createMockEnv());
    expect(b.token_endpoint_auth_methods_supported).toEqual([
      "client_secret_post",
      "client_secret_basic",
    ]);
    expect(b.token_endpoint_auth_methods_supported).not.toContain("none");
  });

  it("advertises only the authorization_code grant with S256 PKCE", async () => {
    const b = await body(createMockEnv());
    expect(b.grant_types_supported).toEqual(["authorization_code"]);
    expect(b.response_types_supported).toEqual(["code"]);
    expect(b.code_challenge_methods_supported).toEqual(["S256"]);
  });

  it("advertises tenant_id / role so Access policies can filter on them", async () => {
    const b = await body(createMockEnv());
    expect(b.claims_supported).toContain("tenant_id");
    expect(b.claims_supported).toContain("role");
    expect(b.claims_supported).toContain("email");
  });

  it("does not leak MCP scopes into this surface", async () => {
    const b = await body(createMockEnv());
    expect(b.scopes_supported).toEqual(["openid", "email", "profile"]);
    expect(JSON.stringify(b)).not.toContain("mcp.");
  });
});
