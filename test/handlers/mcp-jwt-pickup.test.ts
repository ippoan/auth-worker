/**
 * `POST /mcp/jwt/pickup` — signature-only JWT verification + one-shot KV pickup.
 */

import { describe, it, expect } from "vitest";
import { handleMcpJwtPickup } from "../../src/handlers/mcp-jwt-pickup";
import { signMcpJwt } from "../../src/lib/mcp-jwt";
import { encryptWithKey } from "../../src/lib/mcp-crypto";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth.test.example";
const TEST_MCP_JWT_SECRET = "test-mcp-jwt-secret-32chars!";
const AUD = "github-mcp-server-rs";
const SSO_KEY = "test-sso-encryption-key";

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    MCP_JWT_SECRET: TEST_MCP_JWT_SECRET,
    SSO_ENCRYPTION_KEY: SSO_KEY,
    ...overrides,
  });
  return { env, kv };
}

function postPickup(jwt: string | null): Request {
  const headers: Record<string, string> = {};
  if (jwt !== null) headers["Authorization"] = `Bearer ${jwt}`;
  return new Request(`${ISSUER}/mcp/jwt/pickup`, {
    method: "POST",
    headers,
  });
}

async function stashPickup(
  kv: MockKV,
  sub: string,
  payload: {
    access_token: string;
    refresh_token: string;
    scope: string;
    expires_in: number;
  },
): Promise<void> {
  const ciphertext = await encryptWithKey(JSON.stringify(payload), SSO_KEY);
  kv._data[`mcp_jwt_pickup:${sub}`] = ciphertext;
}

describe("POST /mcp/jwt/pickup — env guards", () => {
  it("returns 503 when MCP_OAUTH_KV not bound", async () => {
    const env = createMockEnv({
      MCP_OAUTH_KV: undefined,
      MCP_JWT_SECRET: TEST_MCP_JWT_SECRET,
    });
    const res = await handleMcpJwtPickup(postPickup("x"), env);
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("server_error");
  });

  it("returns 503 when MCP_JWT_SECRET missing", async () => {
    const { env } = envWithKv({ MCP_JWT_SECRET: undefined });
    const res = await handleMcpJwtPickup(postPickup("x"), env);
    expect(res.status).toBe(503);
  });

  it("returns 503 when SSO_ENCRYPTION_KEY missing", async () => {
    const { env } = envWithKv({ SSO_ENCRYPTION_KEY: undefined });
    const res = await handleMcpJwtPickup(postPickup("x"), env);
    expect(res.status).toBe(503);
  });
});

describe("POST /mcp/jwt/pickup — auth header", () => {
  it("returns 401 when Authorization header missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpJwtPickup(postPickup(null), env);
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("unauthorized");
  });

  it("returns 401 when Authorization is malformed (no Bearer prefix)", async () => {
    const { env } = envWithKv();
    const req = new Request(`${ISSUER}/mcp/jwt/pickup`, {
      method: "POST",
      headers: { Authorization: "Basic abc" },
    });
    const res = await handleMcpJwtPickup(req, env);
    expect(res.status).toBe(401);
  });

  it("returns 401 when JWT signature is wrong", async () => {
    const jwt = await signMcpJwt(
      { sub: "github:alice", github_login: "alice", scope: "x", aud: AUD },
      "wrong-secret-32chars-padding!",
      3600,
    );
    const { env } = envWithKv();
    const res = await handleMcpJwtPickup(postPickup(jwt), env);
    expect(res.status).toBe(401);
  });

  it("returns 401 when JWT is malformed", async () => {
    const { env } = envWithKv();
    const res = await handleMcpJwtPickup(postPickup("not.a.jwt"), env);
    expect(res.status).toBe(401);
  });
});

describe("POST /mcp/jwt/pickup — pickup lookup", () => {
  it("returns 404 when no pickup exists for the sub", async () => {
    const jwt = await signMcpJwt(
      { sub: "github:alice", github_login: "alice", scope: "x", aud: AUD },
      TEST_MCP_JWT_SECRET,
      3600,
    );
    const { env } = envWithKv();
    const res = await handleMcpJwtPickup(postPickup(jwt), env);
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("no_pickup");
  });

  it("200 with decrypted blob when pickup exists, then deletes the KV entry", async () => {
    const jwt = await signMcpJwt(
      { sub: "github:alice", github_login: "alice", scope: "mcp.read mcp.write", aud: AUD },
      TEST_MCP_JWT_SECRET,
      3600,
    );
    const { env, kv } = envWithKv();
    await stashPickup(kv, "github:alice", {
      access_token: "fresh-access-jwt",
      refresh_token: "fresh-refresh-hex",
      scope: "mcp.read mcp.write",
      expires_in: 3600,
    });

    const res = await handleMcpJwtPickup(postPickup(jwt), env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      access_token: string;
      refresh_token: string;
      scope: string;
      expires_in: number;
    };
    expect(body.access_token).toBe("fresh-access-jwt");
    expect(body.refresh_token).toBe("fresh-refresh-hex");
    expect(body.scope).toBe("mcp.read mcp.write");
    expect(body.expires_in).toBe(3600);
    // one-shot: KV entry must be gone
    expect(kv._data["mcp_jwt_pickup:github:alice"]).toBeUndefined();
  });

  it("200 works even when the presented JWT is expired (signature only)", async () => {
    // exp in the past — verifyMcpJwt would reject this, signatureOnly accepts
    const jwt = await signMcpJwt(
      { sub: "github:bob", github_login: "bob", scope: "x", aud: AUD },
      TEST_MCP_JWT_SECRET,
      -3600,
    );
    const { env, kv } = envWithKv();
    await stashPickup(kv, "github:bob", {
      access_token: "new-jwt",
      refresh_token: "new-refresh",
      scope: "mcp.read mcp.write",
      expires_in: 3600,
    });
    const res = await handleMcpJwtPickup(postPickup(jwt), env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string };
    expect(body.access_token).toBe("new-jwt");
  });

  it("returns 404 when decrypt fails (corrupted ciphertext)", async () => {
    const jwt = await signMcpJwt(
      { sub: "github:eve", github_login: "eve", scope: "x", aud: AUD },
      TEST_MCP_JWT_SECRET,
      3600,
    );
    const { env, kv } = envWithKv();
    // Insert a garbage ciphertext — base64-encoded "not-real-ciphertext"
    kv._data["mcp_jwt_pickup:github:eve"] = btoa("not-real-ciphertext-not-aes-gcm");
    const res = await handleMcpJwtPickup(postPickup(jwt), env);
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("no_pickup");
    // Even on decrypt failure the entry is consumed (delete-first) so a
    // single bad entry doesn't keep returning errors forever.
    expect(kv._data["mcp_jwt_pickup:github:eve"]).toBeUndefined();
  });

  it("returns 404 when decrypted plaintext is not JSON", async () => {
    const jwt = await signMcpJwt(
      { sub: "github:mallory", github_login: "mallory", scope: "x", aud: AUD },
      TEST_MCP_JWT_SECRET,
      3600,
    );
    const { env, kv } = envWithKv();
    const ciphertext = await encryptWithKey("this is plain text not JSON", SSO_KEY);
    kv._data["mcp_jwt_pickup:github:mallory"] = ciphertext;
    const res = await handleMcpJwtPickup(postPickup(jwt), env);
    expect(res.status).toBe(404);
  });

  it("Cache-Control: no-store on success", async () => {
    const jwt = await signMcpJwt(
      { sub: "github:dave", github_login: "dave", scope: "x", aud: AUD },
      TEST_MCP_JWT_SECRET,
      3600,
    );
    const { env, kv } = envWithKv();
    await stashPickup(kv, "github:dave", {
      access_token: "t",
      refresh_token: "r",
      scope: "x",
      expires_in: 60,
    });
    const res = await handleMcpJwtPickup(postPickup(jwt), env);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("Cache-Control: no-store on 401", async () => {
    const { env } = envWithKv();
    const res = await handleMcpJwtPickup(postPickup(null), env);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("Cache-Control: no-store on 404", async () => {
    const jwt = await signMcpJwt(
      { sub: "github:frank", github_login: "frank", scope: "x", aud: AUD },
      TEST_MCP_JWT_SECRET,
      3600,
    );
    const { env } = envWithKv();
    const res = await handleMcpJwtPickup(postPickup(jwt), env);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("Cache-Control: no-store on 503", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    const res = await handleMcpJwtPickup(postPickup("x"), env);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("pickup is bound to the JWT's sub — Alice's JWT can't read Bob's pickup", async () => {
    const aliceJwt = await signMcpJwt(
      { sub: "github:alice", github_login: "alice", scope: "x", aud: AUD },
      TEST_MCP_JWT_SECRET,
      3600,
    );
    const { env, kv } = envWithKv();
    // Bob's pickup stashed
    await stashPickup(kv, "github:bob", {
      access_token: "bobs-token",
      refresh_token: "bobs-refresh",
      scope: "mcp.read",
      expires_in: 3600,
    });
    // Alice asks for pickup → 404 (no entry for her sub)
    const res = await handleMcpJwtPickup(postPickup(aliceJwt), env);
    expect(res.status).toBe(404);
    // Bob's entry still intact (we never touched it)
    expect(kv._data["mcp_jwt_pickup:github:bob"]).toBeDefined();
  });
});
