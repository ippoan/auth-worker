import { describe, it, expect } from "vitest";
import { resolveSecret } from "../../src/lib/secret";

describe("resolveSecret", () => {
  it("returns null for undefined binding (not bound)", async () => {
    expect(await resolveSecret(undefined)).toBeNull();
  });

  it("returns null for empty string binding", async () => {
    expect(await resolveSecret("")).toBeNull();
  });

  it("returns the string as-is for non-empty string binding (vitest / wrangler dev)", async () => {
    expect(await resolveSecret("plain-string-value")).toBe("plain-string-value");
  });

  it("calls .get() on a SecretsStoreSecret binding and returns the value", async () => {
    const binding = {
      get: async () => "value-from-secrets-store",
    } as unknown as SecretsStoreSecret;
    expect(await resolveSecret(binding)).toBe("value-from-secrets-store");
  });

  it("returns null when SecretsStoreSecret.get() throws", async () => {
    const binding = {
      get: async () => {
        throw new Error("simulated Secrets Store outage");
      },
    } as unknown as SecretsStoreSecret;
    expect(await resolveSecret(binding)).toBeNull();
  });

  it("returns null when SecretsStoreSecret.get() resolves to empty string", async () => {
    const binding = {
      get: async () => "",
    } as unknown as SecretsStoreSecret;
    expect(await resolveSecret(binding)).toBeNull();
  });
});
