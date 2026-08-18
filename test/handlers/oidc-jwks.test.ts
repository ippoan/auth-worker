import { describe, it, expect } from "vitest";
import { handleOidcJwks } from "../../src/handlers/oidc-jwks";
import { createMockEnv } from "../helpers/mock-env";
import type { Env } from "../../src/index";

async function generatePrivateJwkJson(): Promise<{ jwk: Record<string, string>; d: string }> {
  // generateKey の戻り値は `CryptoKey | CryptoKeyPair`。ECDSA は必ず pair なので
  // 明示する (test/tsconfig.json の型で narrowing が効かないため)。
  const { privateKey } = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  return {
    jwk: { kty: "EC", crv: "P-256", x: jwk.x!, y: jwk.y!, d: jwk.d! },
    d: jwk.d!,
  };
}

function call(env: Env): Promise<Response> {
  return handleOidcJwks(
    new Request("https://auth.test.example/oidc/.well-known/jwks.json"),
    env,
  );
}

describe("GET /oidc/.well-known/jwks.json", () => {
  it("returns 200 with JSON + CORS + edge cache headers", async () => {
    const { jwk } = await generatePrivateJwkJson();
    const res = await call(
      createMockEnv({ ACCESS_OIDC_SIGNING_KEY: JSON.stringify([jwk]) }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("application/json");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=3600");
  });

  it("publishes the public part only — the private component never leaks", async () => {
    const { jwk, d } = await generatePrivateJwkJson();
    const res = await call(
      createMockEnv({ ACCESS_OIDC_SIGNING_KEY: JSON.stringify([jwk]) }),
    );
    const raw = await res.text();
    expect(raw).not.toContain(d);
    expect(raw).not.toContain('"d"');
    const body = JSON.parse(raw) as { keys: Array<Record<string, string>> };
    expect(body.keys).toHaveLength(1);
    expect(body.keys[0]!.kty).toBe("EC");
    expect(body.keys[0]!.crv).toBe("P-256");
    expect(body.keys[0]!.alg).toBe("ES256");
    expect(body.keys[0]!.use).toBe("sig");
    expect(body.keys[0]!.kid).toBeTruthy();
  });

  it("publishes every key during rotation (new key first, old key still verifiable)", async () => {
    const fresh = await generatePrivateJwkJson();
    const old = await generatePrivateJwkJson();
    const res = await call(
      createMockEnv({
        ACCESS_OIDC_SIGNING_KEY: JSON.stringify([fresh.jwk, old.jwk]),
      }),
    );
    const body = (await res.json()) as { keys: Array<Record<string, string>> };
    expect(body.keys).toHaveLength(2);
    expect(body.keys[0]!.x).toBe(fresh.jwk.x);
    expect(body.keys[1]!.x).toBe(old.jwk.x);
  });

  it("returns 503 when the signing key is not bound", async () => {
    const res = await call(createMockEnv({ ACCESS_OIDC_SIGNING_KEY: undefined }));
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("server_error");
  });

  it("returns 503 when the signing key is malformed (never an empty 200 keys list)", async () => {
    const res = await call(createMockEnv({ ACCESS_OIDC_SIGNING_KEY: "{not json" }));
    expect(res.status).toBe(503);
  });
});
