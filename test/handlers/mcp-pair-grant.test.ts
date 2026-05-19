/**
 * `handleMcpPairGrant` (issue #157 Phase B) — `POST /mcp/pair/grant` テスト。
 *
 * - env guard (503)
 * - Authorization 欠落 / 不正 → 400
 * - body 不正 JSON → 400
 * - refresh_token 未知 / revoked → 401
 * - refresh_token 期限切れ (>30d) → 410
 * - rate limit (10/min) → 429
 * - 正常系: binding_jwt mint + last_used_at bump + mcp_url 返却
 */

import { describe, it, expect } from "vitest";
import { handleMcpPairGrant } from "../../src/handlers/mcp-pair-grant";
import { verifyMcpJwt } from "../../src/lib/mcp-jwt";
import {
  PAIR_REFRESH_TTL_SEC,
  hashRefreshToken,
  putPairRefresh,
  type PairRefreshRecord,
} from "../../src/lib/mcp-pair";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth-staging.test.example";
const RELAY = "https://mcp-staging.test.example";
const MCP_JWT_SECRET = "test-mcp-jwt-secret-32chars!!!!!";
const REFRESH_TOKEN = "RT-test-43chars-base64url-xyzxyzxyzxyzxyzxy";
const REFRESH_TOKEN_2 = "RT-test-43chars-base64url-ABCABCABCABCABCABC";

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    MCP_JWT_SECRET,
    ...overrides,
  });
  return { env, kv };
}

function refreshRec(overrides: Partial<PairRefreshRecord> = {}): PairRefreshRecord {
  const now = Date.now();
  return {
    github_login: "alice",
    requested_scope: "mcp.read mcp.write",
    created_at: now,
    expires_at: now + PAIR_REFRESH_TTL_SEC * 1000,
    last_used_at: null,
    revoked: false,
    ...overrides,
  };
}

function grantReq(
  opts: { auth?: string | null; body?: string | undefined; contentLength?: string } = {},
): Request {
  const headers: Record<string, string> = {};
  if (opts.auth !== null && opts.auth !== undefined) headers.Authorization = opts.auth;
  if (opts.contentLength !== undefined) headers["Content-Length"] = opts.contentLength;
  return new Request(`${ISSUER}/mcp/pair/grant`, {
    method: "POST",
    headers,
    body: opts.body,
  });
}

describe("handleMcpPairGrant — env guards", () => {
  it.each([
    ["MCP_OAUTH_KV", { MCP_OAUTH_KV: undefined }],
    ["MCP_JWT_SECRET", { MCP_JWT_SECRET: "" }],
    ["AUTH_WORKER_ORIGIN", { AUTH_WORKER_ORIGIN: "" }],
  ])("503 when %s missing", async (_label, overrides) => {
    const { env } = envWithKv(overrides as Partial<Env>);
    const res = await handleMcpPairGrant(
      grantReq({ auth: `Bearer ${REFRESH_TOKEN}` }),
      env,
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("server_error");
  });
});

describe("handleMcpPairGrant — Authorization header parsing", () => {
  it("400 when Authorization header missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpPairGrant(grantReq(), env);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_request");
  });

  it("400 when Authorization is not Bearer scheme", async () => {
    const { env } = envWithKv();
    const res = await handleMcpPairGrant(grantReq({ auth: "Basic foo" }), env);
    expect(res.status).toBe(400);
  });

  it("400 when Bearer prefix has no token", async () => {
    const { env } = envWithKv();
    const res = await handleMcpPairGrant(grantReq({ auth: "Bearer " }), env);
    expect(res.status).toBe(400);
  });
});

describe("handleMcpPairGrant — body parsing", () => {
  it("400 when body is malformed JSON (and Content-Length > 0)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpPairGrant(
      grantReq({ auth: `Bearer ${REFRESH_TOKEN}`, body: "{not json", contentLength: "9" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("accepts empty body (Content-Length: 0)", async () => {
    const { env } = envWithKv();
    await putPairRefresh(env, await hashRefreshToken(REFRESH_TOKEN), refreshRec());
    const res = await handleMcpPairGrant(
      grantReq({ auth: `Bearer ${REFRESH_TOKEN}`, contentLength: "0" }),
      env,
    );
    expect(res.status).toBe(200);
  });

  it("accepts well-formed body with binary_version + fingerprint", async () => {
    const { env } = envWithKv();
    await putPairRefresh(env, await hashRefreshToken(REFRESH_TOKEN), refreshRec());
    const res = await handleMcpPairGrant(
      grantReq({
        auth: `Bearer ${REFRESH_TOKEN}`,
        body: JSON.stringify({ binary_version: "v0.0.14", binary_fingerprint: "abc" }),
        contentLength: "55",
      }),
      env,
    );
    expect(res.status).toBe(200);
  });
});

describe("handleMcpPairGrant — refresh_token lookup", () => {
  it("401 when refresh_token unknown", async () => {
    const { env } = envWithKv();
    const res = await handleMcpPairGrant(
      grantReq({ auth: `Bearer ${REFRESH_TOKEN}`, contentLength: "0" }),
      env,
    );
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_grant");
  });

  it("401 when refresh_token is revoked", async () => {
    const { env } = envWithKv();
    await putPairRefresh(
      env,
      await hashRefreshToken(REFRESH_TOKEN),
      refreshRec({ revoked: true }),
    );
    const res = await handleMcpPairGrant(
      grantReq({ auth: `Bearer ${REFRESH_TOKEN}`, contentLength: "0" }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("410 when refresh_token expired (expires_at < now)", async () => {
    const { env, kv } = envWithKv();
    // putPairRefresh は TTL を clamp するので、KV 直接書きで expired record を作る
    const hash = await hashRefreshToken(REFRESH_TOKEN);
    const expiredRec = refreshRec({ expires_at: Date.now() - 1_000 });
    kv._data[`mcp/pair_refresh/${hash}`] = JSON.stringify(expiredRec);
    const res = await handleMcpPairGrant(
      grantReq({ auth: `Bearer ${REFRESH_TOKEN}`, contentLength: "0" }),
      env,
    );
    expect(res.status).toBe(410);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("expired_token");
  });
});

describe("handleMcpPairGrant — rate limit", () => {
  it("429 when more than 10 grants per minute per refresh_token", async () => {
    const { env } = envWithKv();
    await putPairRefresh(env, await hashRefreshToken(REFRESH_TOKEN), refreshRec());
    // 10 are allowed
    for (let i = 0; i < 10; i++) {
      const res = await handleMcpPairGrant(
        grantReq({ auth: `Bearer ${REFRESH_TOKEN}`, contentLength: "0" }),
        env,
      );
      expect(res.status).toBe(200);
    }
    // 11th rejected
    const res = await handleMcpPairGrant(
      grantReq({ auth: `Bearer ${REFRESH_TOKEN}`, contentLength: "0" }),
      env,
    );
    expect(res.status).toBe(429);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("rate_limited");
  });

  it("rate limit is per-token (different tokens do not interfere)", async () => {
    const { env } = envWithKv();
    await putPairRefresh(env, await hashRefreshToken(REFRESH_TOKEN), refreshRec());
    await putPairRefresh(
      env,
      await hashRefreshToken(REFRESH_TOKEN_2),
      refreshRec({ github_login: "bob" }),
    );
    for (let i = 0; i < 10; i++) {
      await handleMcpPairGrant(
        grantReq({ auth: `Bearer ${REFRESH_TOKEN}`, contentLength: "0" }),
        env,
      );
    }
    // token1 exhausted, token2 still works
    expect(
      (
        await handleMcpPairGrant(
          grantReq({ auth: `Bearer ${REFRESH_TOKEN}`, contentLength: "0" }),
          env,
        )
      ).status,
    ).toBe(429);
    expect(
      (
        await handleMcpPairGrant(
          grantReq({ auth: `Bearer ${REFRESH_TOKEN_2}`, contentLength: "0" }),
          env,
        )
      ).status,
    ).toBe(200);
  });
});

describe("handleMcpPairGrant — success", () => {
  it("returns binding_jwt + same refresh_token + mcp_url + bumps last_used_at", async () => {
    const { env, kv } = envWithKv();
    const hash = await hashRefreshToken(REFRESH_TOKEN);
    const original = refreshRec({ requested_scope: "mcp.admin" });
    await putPairRefresh(env, hash, original);

    const res = await handleMcpPairGrant(
      grantReq({ auth: `Bearer ${REFRESH_TOKEN}`, contentLength: "0" }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      binding_jwt: string;
      refresh_token: string;
      mcp_url: string;
      github_login: string;
      expires_in: number;
    };
    // refresh_token は rotation 無し: 同じ値を返す
    expect(body.refresh_token).toBe(REFRESH_TOKEN);
    expect(body.github_login).toBe("alice");
    expect(body.expires_in).toBe(60 * 60 * 24);
    // mcp_url は auth host → mcp host へ書き換えた origin で /u/<login>/mcp
    expect(body.mcp_url).toBe(`${RELAY}/u/alice/mcp`);
    // binding_jwt 検証: scope = refresh record の requested_scope と一致
    const payload = await verifyMcpJwt(
      body.binding_jwt,
      MCP_JWT_SECRET,
      "github-mcp-server-rs",
    );
    expect(payload).not.toBeNull();
    expect(payload!.github_login).toBe("alice");
    expect(payload!.scope).toBe("mcp.admin");
    expect(payload!.sub).toBe("github:alice");

    // KV: last_used_at が更新されている
    const stored = JSON.parse(kv._data[`mcp/pair_refresh/${hash}`]!) as PairRefreshRecord;
    expect(stored.last_used_at).not.toBeNull();
    expect(stored.last_used_at).toBeLessThanOrEqual(Date.now());
    expect(stored.last_used_at).toBeGreaterThan(Date.now() - 1_000);
    // expires_at は伸びていない (30 日 hard expiry)
    expect(stored.expires_at).toBe(original.expires_at);
  });

  it("default scope is preserved when refresh record stores 'mcp.read mcp.write'", async () => {
    const { env } = envWithKv();
    await putPairRefresh(env, await hashRefreshToken(REFRESH_TOKEN), refreshRec());
    const res = await handleMcpPairGrant(
      grantReq({ auth: `Bearer ${REFRESH_TOKEN}`, contentLength: "0" }),
      env,
    );
    const body = (await res.json()) as { binding_jwt: string };
    const payload = await verifyMcpJwt(
      body.binding_jwt,
      MCP_JWT_SECRET,
      "github-mcp-server-rs",
    );
    expect(payload?.scope).toBe("mcp.read mcp.write");
  });
});
