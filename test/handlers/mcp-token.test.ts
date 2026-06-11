import { describe, it, expect } from "vitest";
import { handleMcpToken } from "../../src/handlers/mcp-token";
import {
  createMockEnv,
  createMockKV,
  type MockKV,
} from "../helpers/mock-env";
import type { Env } from "../../src/index";
import type { DeviceCodeRecord } from "../../src/lib/mcp-kv";
import { verifyMcpJwt } from "../../src/lib/mcp-jwt";
import { issueRefreshToken } from "../../src/lib/mcp-refresh";

const ISSUER = "https://auth.test.example";
const TEST_MCP_JWT_SECRET = "test-mcp-jwt-secret-32chars!";
const AUD = "github-mcp-server-rs";

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    MCP_JWT_SECRET: TEST_MCP_JWT_SECRET,
    ...overrides,
  });
  return { env, kv };
}

function rec(overrides: Partial<DeviceCodeRecord> = {}): DeviceCodeRecord {
  const now = Date.now();
  return {
    device_code: "d".repeat(64),
    user_code: "BCDF-GHJK",
    client_id: "github-mcp-server-rs",
    scope: "read:user",
    status: "pending",
    created_at: now,
    expires_at: now + 900_000,
    ...overrides,
  };
}

function postForm(
  fields: Record<string, string>,
  opts: { contentType?: string; body?: BodyInit } = {},
): Request {
  const headers: Record<string, string> = {};
  if (opts.contentType) headers["Content-Type"] = opts.contentType;
  const body =
    opts.body ??
    (opts.contentType?.includes("json")
      ? JSON.stringify(fields)
      : new URLSearchParams(fields));
  return new Request(`${ISSUER}/mcp/token`, { method: "POST", headers, body });
}

describe("POST /mcp/token — env guards", () => {
  it("returns 503 server_error when MCP_OAUTH_KV not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined, MCP_JWT_SECRET: TEST_MCP_JWT_SECRET });
    const res = await handleMcpToken(postForm({}), env);
    expect(res.status).toBe(503);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("server_error");
  });

  it("returns 503 server_error when MCP_JWT_SECRET missing", async () => {
    const kv = createMockKV() as MockKV;
    const env = createMockEnv({ MCP_OAUTH_KV: kv, MCP_JWT_SECRET: undefined });
    const res = await handleMcpToken(postForm({}), env);
    expect(res.status).toBe(503);
  });
});

describe("POST /mcp/token — form parsing", () => {
  it("returns 400 invalid_request when body is not form-encoded", async () => {
    const { env } = envWithKv();
    const req = new Request(`${ISSUER}/mcp/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not-form-{",
    });
    const res = await handleMcpToken(req, env);
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("invalid_request");
  });

  it("returns 400 unsupported_grant_type for unknown grant_type", async () => {
    const { env } = envWithKv();
    const res = await handleMcpToken(postForm({ grant_type: "password" }), env);
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("unsupported_grant_type");
  });

  it("returns 400 unsupported_grant_type when grant_type missing (empty)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpToken(postForm({}), env);
    expect(res.status).toBe(400);
  });
});

describe("POST /mcp/token — device_code grant", () => {
  const GRANT = "urn:ietf:params:oauth:grant-type:device_code";

  it("400 invalid_request when device_code missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpToken(
      postForm({ grant_type: GRANT, client_id: "x" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("invalid_request");
  });

  it("400 invalid_request when client_id missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpToken(
      postForm({ grant_type: GRANT, device_code: "d" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 expired_token when device_code not found", async () => {
    const { env } = envWithKv();
    const res = await handleMcpToken(
      postForm({ grant_type: GRANT, device_code: "nonexistent", client_id: "x" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("expired_token");
  });

  it("400 expired_token when expires_at < now", async () => {
    const { env, kv } = envWithKv();
    const r = rec({ expires_at: Date.now() - 1000 });
    kv._data[`device_code:${r.device_code}`] = JSON.stringify(r);
    const res = await handleMcpToken(
      postForm({ grant_type: GRANT, device_code: r.device_code, client_id: "x" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("expired_token");
  });

  it("400 authorization_pending when status=pending", async () => {
    const { env, kv } = envWithKv();
    const r = rec({ status: "pending" });
    kv._data[`device_code:${r.device_code}`] = JSON.stringify(r);
    const res = await handleMcpToken(
      postForm({ grant_type: GRANT, device_code: r.device_code, client_id: "x" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("authorization_pending");
  });

  it("400 access_denied when status=denied", async () => {
    const { env, kv } = envWithKv();
    const r = rec({ status: "denied" });
    kv._data[`device_code:${r.device_code}`] = JSON.stringify(r);
    const res = await handleMcpToken(
      postForm({ grant_type: GRANT, device_code: r.device_code, client_id: "x" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("access_denied");
  });

  it("500 server_error when approved but github_login missing (defensive)", async () => {
    const { env, kv } = envWithKv();
    const r = rec({ status: "approved" }); // github_login intentionally not set
    kv._data[`device_code:${r.device_code}`] = JSON.stringify(r);
    const res = await handleMcpToken(
      postForm({ grant_type: GRANT, device_code: r.device_code, client_id: "x" }),
      env,
    );
    expect(res.status).toBe(500);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("server_error");
  });

  it("200 with JWT + refresh_token on approved; device_code is deleted", async () => {
    const { env, kv } = envWithKv();
    const r = rec({ status: "approved", github_login: "alice" });
    kv._data[`device_code:${r.device_code}`] = JSON.stringify(r);
    const res = await handleMcpToken(
      postForm({
        grant_type: GRANT,
        device_code: r.device_code,
        client_id: "github-mcp-server-rs",
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as {
      access_token: string;
      token_type: string;
      expires_in: number;
      refresh_token: string;
      scope: string;
    };
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(3600);
    expect(body.scope).toBe("read:user");
    expect(body.refresh_token).toMatch(/^[0-9a-f]{64}$/);

    // JWT verifiable
    const payload = await verifyMcpJwt(body.access_token, TEST_MCP_JWT_SECRET, AUD);
    expect(payload).not.toBeNull();
    expect(payload!.sub).toBe("github:alice");
    expect(payload!.github_login).toBe("alice");

    // device_code deleted
    expect(kv._data[`device_code:${r.device_code}`]).toBeUndefined();
  });
});

describe("POST /mcp/token — refresh_token grant", () => {
  it("400 invalid_request when refresh_token missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpToken(
      postForm({ grant_type: "refresh_token" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("invalid_request");
  });

  it("400 invalid_grant when refresh_token unknown", async () => {
    const { env } = envWithKv();
    const res = await handleMcpToken(
      postForm({ grant_type: "refresh_token", refresh_token: "unknown" }),
      env,
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("invalid_grant");
  });

  it("200 with new tokens on success; grace re-use returns the SAME pair (Refs #270)", async () => {
    const { env } = envWithKv();
    const refresh = await issueRefreshToken(env, {
      sub: "github:bob",
      scope: "read:user",
      github_login: "bob",
    });

    const res = await handleMcpToken(
      postForm({ grant_type: "refresh_token", refresh_token: refresh }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as {
      access_token: string;
      refresh_token: string;
      scope: string;
    };
    expect(body.scope).toBe("read:user");
    expect(body.refresh_token).not.toBe(refresh);

    // verify access_token
    const payload = await verifyMcpJwt(body.access_token, TEST_MCP_JWT_SECRET, AUD);
    expect(payload!.sub).toBe("github:bob");
    expect(payload!.github_login).toBe("bob");

    // rotation 直後に **旧 refresh を再提示** (並列 fan-out / 応答消失 retry を模す)。
    // delete-first だった旧実装は invalid_grant で session を殺していたが、grace
    // (60s) では **1 回目と同一の新 pair** をそのまま返す (divergence 防止、Refs #270)。
    const res2 = await handleMcpToken(
      postForm({ grant_type: "refresh_token", refresh_token: refresh }),
      env,
    );
    expect(res2.status).toBe(200);
    const body2 = await res2.json() as {
      access_token: string;
      refresh_token: string;
      scope: string;
    };
    expect(body2.refresh_token).toBe(body.refresh_token);
    expect(body2.access_token).toBe(body.access_token);
    expect(body2.scope).toBe("read:user");

    // 新 refresh_token は通常どおり rotate できる (grace は旧 token slot 専用)。
    const res3 = await handleMcpToken(
      postForm({ grant_type: "refresh_token", refresh_token: body.refresh_token }),
      env,
    );
    expect(res3.status).toBe(200);
    expect((await res3.json() as { refresh_token: string }).refresh_token).not.toBe(body.refresh_token);
  });
});

// =============================================================================
// Phase 5 (#128): authorization_code grant + PKCE
// =============================================================================
import { putAuthCode, type AuthCodeRecord } from "../../src/lib/mcp-authcode";

const PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

function authCodeRec(overrides: Partial<AuthCodeRecord> = {}): AuthCodeRecord {
  return {
    code: "ac-1",
    client_id: "c-1",
    redirect_uri: "https://claude.ai/cb",
    code_challenge: PKCE_CHALLENGE,
    code_challenge_method: "S256",
    github_login: "alice",
    scope: "mcp.read mcp.write",
    expires_at: Date.now() + 60_000,
    ...overrides,
  };
}

describe("POST /mcp/token — authorization_code grant (Phase 5 #128)", () => {
  it("400 invalid_request when any of code/code_verifier/redirect_uri/client_id missing", async () => {
    const { env } = envWithKv();
    for (const missing of ["code", "code_verifier", "redirect_uri", "client_id"]) {
      const fields: Record<string, string> = {
        grant_type: "authorization_code",
        code: "ac",
        code_verifier: PKCE_VERIFIER,
        redirect_uri: "https://claude.ai/cb",
        client_id: "c-1",
      };
      delete fields[missing];
      const res = await handleMcpToken(postForm(fields), env);
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("invalid_request");
    }
  });

  it("400 invalid_grant when code unknown", async () => {
    const { env } = envWithKv();
    const res = await handleMcpToken(
      postForm({
        grant_type: "authorization_code",
        code: "missing",
        code_verifier: PKCE_VERIFIER,
        redirect_uri: "https://claude.ai/cb",
        client_id: "c-1",
      }),
      env,
    );
    expect(res.status).toBe(400);
    expect((await res.json() as { error: string }).error).toBe("invalid_grant");
  });

  it("400 invalid_grant when code expired", async () => {
    const { env } = envWithKv();
    await putAuthCode(env, authCodeRec({ expires_at: Date.now() - 1000 }));
    const res = await handleMcpToken(
      postForm({
        grant_type: "authorization_code",
        code: "ac-1",
        code_verifier: PKCE_VERIFIER,
        redirect_uri: "https://claude.ai/cb",
        client_id: "c-1",
      }),
      env,
    );
    expect(res.status).toBe(400);
    expect((await res.json() as { error: string }).error).toBe("invalid_grant");
  });

  it("400 invalid_grant when client_id mismatch", async () => {
    const { env } = envWithKv();
    await putAuthCode(env, authCodeRec());
    const res = await handleMcpToken(
      postForm({
        grant_type: "authorization_code",
        code: "ac-1",
        code_verifier: PKCE_VERIFIER,
        redirect_uri: "https://claude.ai/cb",
        client_id: "other-client",
      }),
      env,
    );
    expect(res.status).toBe(400);
    expect((await res.json() as { error: string }).error).toBe("invalid_grant");
  });

  it("400 invalid_grant when redirect_uri mismatch", async () => {
    const { env } = envWithKv();
    await putAuthCode(env, authCodeRec());
    const res = await handleMcpToken(
      postForm({
        grant_type: "authorization_code",
        code: "ac-1",
        code_verifier: PKCE_VERIFIER,
        redirect_uri: "https://attacker.example/cb",
        client_id: "c-1",
      }),
      env,
    );
    expect(res.status).toBe(400);
    expect((await res.json() as { error: string }).error).toBe("invalid_grant");
  });

  it("400 invalid_grant when PKCE verifier does not match challenge", async () => {
    const { env } = envWithKv();
    await putAuthCode(env, authCodeRec());
    const res = await handleMcpToken(
      postForm({
        grant_type: "authorization_code",
        code: "ac-1",
        code_verifier: "wrong-verifier",
        redirect_uri: "https://claude.ai/cb",
        client_id: "c-1",
      }),
      env,
    );
    expect(res.status).toBe(400);
    expect((await res.json() as { error: string }).error).toBe("invalid_grant");
  });

  it("200 with access_token + refresh_token on success; auth code single-use", async () => {
    const { env, kv } = envWithKv();
    await putAuthCode(env, authCodeRec());
    const res = await handleMcpToken(
      postForm({
        grant_type: "authorization_code",
        code: "ac-1",
        code_verifier: PKCE_VERIFIER,
        redirect_uri: "https://claude.ai/cb",
        client_id: "c-1",
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      access_token: string;
      refresh_token: string;
      scope: string;
      token_type: string;
      expires_in: number;
    };
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(3600);
    expect(body.scope).toBe("mcp.read mcp.write");
    const payload = await verifyMcpJwt(body.access_token, TEST_MCP_JWT_SECRET, AUD);
    expect(payload!.sub).toBe("github:alice");
    expect(payload!.github_login).toBe("alice");

    // KV: auth:code:ac-1 削除済 (single-use)
    expect(kv._data["auth:code:ac-1"]).toBeUndefined();
    // 2 度目は invalid_grant
    const res2 = await handleMcpToken(
      postForm({
        grant_type: "authorization_code",
        code: "ac-1",
        code_verifier: PKCE_VERIFIER,
        redirect_uri: "https://claude.ai/cb",
        client_id: "c-1",
      }),
      env,
    );
    expect(res2.status).toBe(400);
  });
});

// =============================================================================
// RFC 8707 Resource Indicators (MCP Authorization spec 2025-06-18)
// =============================================================================
describe("POST /mcp/token — RFC 8707 resource indicator (authorization_code)", () => {
  const RESOURCE = "https://mcp.test.example";

  it("issues access_token with aud=resource when AuthCodeRecord carries resource", async () => {
    const { env } = envWithKv();
    await putAuthCode(env, authCodeRec({ resource: RESOURCE }));
    const res = await handleMcpToken(
      postForm({
        grant_type: "authorization_code",
        code: "ac-1",
        code_verifier: PKCE_VERIFIER,
        redirect_uri: "https://claude.ai/cb",
        client_id: "c-1",
        resource: RESOURCE,
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string };
    // legacy aud では verify 失敗、resource を expected aud に渡すと通る
    const legacyVerify = await verifyMcpJwt(body.access_token, TEST_MCP_JWT_SECRET, AUD);
    expect(legacyVerify).toBeNull();
    const payload = await verifyMcpJwt(body.access_token, TEST_MCP_JWT_SECRET, RESOURCE);
    expect(payload!.aud).toBe(RESOURCE);
  });

  it("400 invalid_target when token request resource does not match bound resource", async () => {
    const { env } = envWithKv();
    await putAuthCode(env, authCodeRec({ resource: RESOURCE }));
    const res = await handleMcpToken(
      postForm({
        grant_type: "authorization_code",
        code: "ac-1",
        code_verifier: PKCE_VERIFIER,
        redirect_uri: "https://claude.ai/cb",
        client_id: "c-1",
        resource: "https://attacker.example",
      }),
      env,
    );
    expect(res.status).toBe(400);
    expect((await res.json() as { error: string }).error).toBe("invalid_target");
  });

  it("uses bound resource as aud even when token request omits resource (rec.resource side)", async () => {
    const { env } = envWithKv();
    await putAuthCode(env, authCodeRec({ resource: RESOURCE }));
    const res = await handleMcpToken(
      postForm({
        grant_type: "authorization_code",
        code: "ac-1",
        code_verifier: PKCE_VERIFIER,
        redirect_uri: "https://claude.ai/cb",
        client_id: "c-1",
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string };
    const payload = await verifyMcpJwt(body.access_token, TEST_MCP_JWT_SECRET, RESOURCE);
    expect(payload!.aud).toBe(RESOURCE);
  });

  it("ignores form resource (no invalid_target) when AuthCodeRecord has no bound resource — legacy aud", async () => {
    const { env } = envWithKv();
    await putAuthCode(env, authCodeRec()); // no resource
    const res = await handleMcpToken(
      postForm({
        grant_type: "authorization_code",
        code: "ac-1",
        code_verifier: PKCE_VERIFIER,
        redirect_uri: "https://claude.ai/cb",
        client_id: "c-1",
        resource: "https://anything.example",
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string };
    const payload = await verifyMcpJwt(body.access_token, TEST_MCP_JWT_SECRET, AUD);
    expect(payload!.aud).toBe(AUD);
  });

  it("refresh_token grant preserves aud from initial Authorization Code issuance", async () => {
    const { env } = envWithKv();
    // 1. Authorization code grant → refresh が aud=resource を持つ
    await putAuthCode(env, authCodeRec({ resource: RESOURCE }));
    const firstRes = await handleMcpToken(
      postForm({
        grant_type: "authorization_code",
        code: "ac-1",
        code_verifier: PKCE_VERIFIER,
        redirect_uri: "https://claude.ai/cb",
        client_id: "c-1",
        resource: RESOURCE,
      }),
      env,
    );
    expect(firstRes.status).toBe(200);
    const first = (await firstRes.json()) as { refresh_token: string };

    // 2. refresh → 新 access_token も aud=resource のはず
    const res = await handleMcpToken(
      postForm({ grant_type: "refresh_token", refresh_token: first.refresh_token }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string; refresh_token: string };
    const payload = await verifyMcpJwt(body.access_token, TEST_MCP_JWT_SECRET, RESOURCE);
    expect(payload!.aud).toBe(RESOURCE);

    // 3. 二度目の refresh (rotation) でも aud 継承
    const res3 = await handleMcpToken(
      postForm({ grant_type: "refresh_token", refresh_token: body.refresh_token }),
      env,
    );
    expect(res3.status).toBe(200);
    const body3 = (await res3.json()) as { access_token: string };
    const p3 = await verifyMcpJwt(body3.access_token, TEST_MCP_JWT_SECRET, RESOURCE);
    expect(p3!.aud).toBe(RESOURCE);
  });
});
