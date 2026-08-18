import { describe, it, expect } from "vitest";
import {
  findOidcClient,
  isRegisteredRedirectUri,
  parseOidcClients,
  resolveOidcClients,
  verifyClientSecret,
  type OidcClient,
} from "../../src/lib/oidc-clients";

const CLIENT: OidcClient = {
  client_id: "cf-access",
  client_secret: "s3cret",
  redirect_uris: ["https://team.cloudflareaccess.com/cdn-cgi/access/callback"],
  name: "cloudflare-access",
};

describe("parseOidcClients", () => {
  it("parses a JSON array of clients", () => {
    const clients = parseOidcClients(JSON.stringify([CLIENT]));
    expect(clients).toHaveLength(1);
    expect(clients![0]!.client_id).toBe("cf-access");
  });

  it("accepts a bare client object (not wrapped in an array)", () => {
    expect(parseOidcClients(JSON.stringify(CLIENT))).toHaveLength(1);
  });

  it("keeps multiple clients so more services can be added later", () => {
    const other = { ...CLIENT, client_id: "other", redirect_uris: ["https://b.example/cb"] };
    const clients = parseOidcClients(JSON.stringify([CLIENT, other]));
    expect(clients!.map((c) => c.client_id)).toEqual(["cf-access", "other"]);
  });

  it("returns null for malformed JSON", () => {
    expect(parseOidcClients("{oops")).toBeNull();
  });

  it("returns null for an empty array", () => {
    expect(parseOidcClients("[]")).toBeNull();
  });

  it("returns null when any entry is invalid (fail-closed, no silent skip)", () => {
    expect(parseOidcClients(JSON.stringify([CLIENT, { client_id: "x" }]))).toBeNull();
  });

  it.each([
    ["non-object entry", 7],
    ["null entry", null],
    ["missing client_id", { client_secret: "s", redirect_uris: ["https://a/cb"] }],
    ["empty client_id", { client_id: "", client_secret: "s", redirect_uris: ["https://a/cb"] }],
    ["missing client_secret", { client_id: "a", redirect_uris: ["https://a/cb"] }],
    ["empty client_secret", { client_id: "a", client_secret: "", redirect_uris: ["https://a/cb"] }],
    ["missing redirect_uris", { client_id: "a", client_secret: "s" }],
    ["redirect_uris not an array", { client_id: "a", client_secret: "s", redirect_uris: "https://a/cb" }],
    ["empty redirect_uris", { client_id: "a", client_secret: "s", redirect_uris: [] }],
    ["non-string redirect_uri", { client_id: "a", client_secret: "s", redirect_uris: [1] }],
    ["empty-string redirect_uri", { client_id: "a", client_secret: "s", redirect_uris: [""] }],
  ])("rejects %s", (_label, value) => {
    expect(parseOidcClients(JSON.stringify([value]))).toBeNull();
  });
});

describe("resolveOidcClients", () => {
  it("resolves a plain-string binding", async () => {
    expect(await resolveOidcClients(JSON.stringify([CLIENT]))).toHaveLength(1);
  });

  it("resolves a SecretsStoreSecret binding", async () => {
    const binding = { get: async () => JSON.stringify([CLIENT]) } as unknown as SecretsStoreSecret;
    expect(await resolveOidcClients(binding)).toHaveLength(1);
  });

  it("returns null when unbound", async () => {
    expect(await resolveOidcClients(undefined)).toBeNull();
  });

  it("returns null when the value is not client JSON", async () => {
    expect(await resolveOidcClients("nope")).toBeNull();
  });
});

describe("findOidcClient", () => {
  it("finds by exact client_id", () => {
    expect(findOidcClient([CLIENT], "cf-access")?.name).toBe("cloudflare-access");
  });

  it("returns null for an unknown client_id", () => {
    expect(findOidcClient([CLIENT], "nope")).toBeNull();
  });
});

describe("isRegisteredRedirectUri", () => {
  it("accepts an exactly registered URI", () => {
    expect(
      isRegisteredRedirectUri(CLIENT, "https://team.cloudflareaccess.com/cdn-cgi/access/callback"),
    ).toBe(true);
  });

  it.each([
    ["a query-string variant", "https://team.cloudflareaccess.com/cdn-cgi/access/callback?x=1"],
    ["a path suffix", "https://team.cloudflareaccess.com/cdn-cgi/access/callback/evil"],
    ["a different host", "https://evil.example/cdn-cgi/access/callback"],
    ["a scheme downgrade", "http://team.cloudflareaccess.com/cdn-cgi/access/callback"],
    ["an empty string", ""],
  ])("rejects %s", (_label, uri) => {
    expect(isRegisteredRedirectUri(CLIENT, uri)).toBe(false);
  });
});

describe("verifyClientSecret", () => {
  it("accepts the exact secret", () => {
    expect(verifyClientSecret(CLIENT, "s3cret")).toBe(true);
  });

  it.each([
    ["a wrong secret of equal length", "s3creT"],
    ["a prefix of the secret", "s3cre"],
    ["a longer secret sharing the prefix", "s3cretX"],
    ["an empty string", ""],
  ])("rejects %s", (_label, presented) => {
    expect(verifyClientSecret(CLIENT, presented)).toBe(false);
  });
});
