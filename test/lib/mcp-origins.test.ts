/**
 * `src/lib/mcp-origins.ts` unit test (issue #126 / Phase 4).
 *
 * AS origin → MCP relay (RS) origin 導出と、`WWW-Authenticate.resource_metadata`
 * URL の組み立てを検証する。
 */

import { describe, it, expect } from "vitest";
import {
  mcpRelayOrigin,
  resourceMetadataUrl,
  resourceMetadataUrlFor,
  allowedResourceOrigins,
  isAllowedResourceOrigin,
  resourceOriginBySlug,
  wwwAuthenticateValue,
} from "../../src/lib/mcp-origins";
import { createMockEnv } from "../helpers/mock-env";

describe("mcpRelayOrigin", () => {
  it("maps prod auth host to mcp host", () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth.ippoan.org" });
    expect(mcpRelayOrigin(env)).toBe("https://mcp.ippoan.org");
  });

  it("maps staging auth host to mcp-staging host", () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth-staging.ippoan.org" });
    expect(mcpRelayOrigin(env)).toBe("https://mcp-staging.ippoan.org");
  });

  it("maps generic auth-<env> host to mcp-<env> host (defensive)", () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth-dev.example.com" });
    expect(mcpRelayOrigin(env)).toBe("https://mcp-dev.example.com");
  });

  it("falls back to https://auth.ippoan.org → https://mcp.ippoan.org when AUTH_WORKER_ORIGIN is empty", () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "" });
    expect(mcpRelayOrigin(env)).toBe("https://mcp.ippoan.org");
  });

  it("returns origin unchanged when host does not start with 'auth.'", () => {
    // host が 'auth' で始まらない → 置換せずそのまま返す (caller 側の意味付け責任)
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://issuer.example" });
    expect(mcpRelayOrigin(env)).toBe("https://issuer.example");
  });
});

describe("resourceMetadataUrl", () => {
  it("returns AUTH_WORKER_ORIGIN + /.well-known/oauth-protected-resource", () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth-staging.ippoan.org" });
    expect(resourceMetadataUrl(env)).toBe(
      "https://auth-staging.ippoan.org/.well-known/oauth-protected-resource",
    );
  });

  it("falls back to https://auth.ippoan.org when AUTH_WORKER_ORIGIN is empty", () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "" });
    expect(resourceMetadataUrl(env)).toBe(
      "https://auth.ippoan.org/.well-known/oauth-protected-resource",
    );
  });
});

describe("wwwAuthenticateValue", () => {
  it("formats Bearer challenge with realm + resource_metadata pointing to AS host", () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth-staging.ippoan.org" });
    expect(wwwAuthenticateValue(env)).toBe(
      'Bearer realm="MCP", resource_metadata="https://auth-staging.ippoan.org/.well-known/oauth-protected-resource"',
    );
  });
});

describe("resourceMetadataUrlFor", () => {
  it("appends slug to base resource metadata path", () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth-staging.ippoan.org" });
    expect(resourceMetadataUrlFor("security-inventory", env)).toBe(
      "https://auth-staging.ippoan.org/.well-known/oauth-protected-resource/security-inventory",
    );
  });
});

describe("allowedResourceOrigins / isAllowedResourceOrigin", () => {
  it("includes mcpRelayOrigin even when MCP_RESOURCE_ORIGINS_ALLOWLIST is empty", () => {
    const env = createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth-staging.ippoan.org" });
    expect(allowedResourceOrigins(env).has("https://mcp-staging.ippoan.org")).toBe(true);
  });

  it("merges allowlist env entries with mcpRelayOrigin", () => {
    const env = createMockEnv({
      AUTH_WORKER_ORIGIN: "https://auth-staging.ippoan.org",
      MCP_RESOURCE_ORIGINS_ALLOWLIST:
        "https://security-inventory.ippoan.org,https://security-rotate.ippoan.org",
    } as unknown as Partial<typeof env>);
    const origins = allowedResourceOrigins(env);
    expect(origins.has("https://mcp-staging.ippoan.org")).toBe(true);
    expect(origins.has("https://security-inventory.ippoan.org")).toBe(true);
    expect(origins.has("https://security-rotate.ippoan.org")).toBe(true);
  });

  it("isAllowedResourceOrigin accepts both relay and extra origins", () => {
    const env = createMockEnv({
      AUTH_WORKER_ORIGIN: "https://auth-staging.ippoan.org",
      MCP_RESOURCE_ORIGINS_ALLOWLIST: "https://security-inventory.ippoan.org",
    } as unknown as Partial<typeof env>);
    expect(isAllowedResourceOrigin("https://mcp-staging.ippoan.org", env)).toBe(true);
    expect(isAllowedResourceOrigin("https://security-inventory.ippoan.org", env)).toBe(true);
    expect(isAllowedResourceOrigin("https://attacker.example", env)).toBe(false);
  });
});

describe("resourceOriginBySlug", () => {
  it("maps hostname first label to origin URL", () => {
    const env = createMockEnv({
      MCP_RESOURCE_ORIGINS_ALLOWLIST:
        "https://security-inventory.ippoan.org,https://security-rotate.ippoan.org",
    } as unknown as Partial<typeof env>);
    const map = resourceOriginBySlug(env);
    expect(map.get("security-inventory")).toBe("https://security-inventory.ippoan.org");
    expect(map.get("security-rotate")).toBe("https://security-rotate.ippoan.org");
    expect(map.size).toBe(2);
  });

  it("returns empty map when env is unset", () => {
    const env = createMockEnv();
    expect(resourceOriginBySlug(env).size).toBe(0);
  });

  it("skips malformed entries", () => {
    const env = createMockEnv({
      MCP_RESOURCE_ORIGINS_ALLOWLIST: "not a url,https://security-inventory.ippoan.org",
    } as unknown as Partial<typeof env>);
    const map = resourceOriginBySlug(env);
    expect(map.size).toBe(1);
    expect(map.get("security-inventory")).toBe("https://security-inventory.ippoan.org");
  });
});
