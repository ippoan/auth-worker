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
