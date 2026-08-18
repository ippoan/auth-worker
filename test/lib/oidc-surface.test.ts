import { describe, it, expect } from "vitest";
import { OIDC_SURFACE_PATH, oidcIssuer } from "../../src/lib/oidc-surface";
import { createMockEnv } from "../helpers/mock-env";

describe("oidcIssuer", () => {
  it("is the worker origin plus the surface path", () => {
    expect(oidcIssuer(createMockEnv({ AUTH_WORKER_ORIGIN: "https://auth.ippoan.org" }))).toBe(
      "https://auth.ippoan.org/oidc",
    );
  });

  it("falls back to the prod origin when AUTH_WORKER_ORIGIN is empty", () => {
    expect(oidcIssuer(createMockEnv({ AUTH_WORKER_ORIGIN: "" }))).toBe(
      "https://auth.ippoan.org/oidc",
    );
  });

  it("differs from the MCP surface issuer (the two AS must not be confusable)", () => {
    const origin = "https://auth.test.example";
    expect(oidcIssuer(createMockEnv({ AUTH_WORKER_ORIGIN: origin }))).not.toBe(origin);
    expect(OIDC_SURFACE_PATH).toBe("/oidc");
  });
});
