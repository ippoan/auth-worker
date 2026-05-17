/**
 * `handleMcpPairClaim` (issue #144) — `GET /mcp/pair/<code>` テスト。
 *
 * - env guard
 * - cookie 不在 → GitHub OAuth redirect
 * - cookie 有り + record 不在 → 404
 * - cookie 有り + claim_login mismatch → 403
 * - cookie 有り + match → approve + 200 HTML
 * - 既に approved → 200 HTML (idempotent)
 * - approve race (approvePair が null) → 404
 */

import { describe, it, expect } from "vitest";
import { handleMcpPairClaim } from "../../src/handlers/mcp-pair-claim";
import { verifyMcpJwt } from "../../src/lib/mcp-jwt";
import {
  PAIR_CODE_TTL_SEC,
  putPair,
  type PairRecord,
} from "../../src/lib/mcp-pair";
import {
  PAIR_SESSION_COOKIE_NAME,
  signPairSession,
} from "../../src/lib/mcp-session";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth.test.example";
const MCP_JWT_SECRET = "test-mcp-jwt-secret-32chars!!!!!";
const SESSION_SECRET = "test-session-cookie-secret-32!!!!";
const STATE_SECRET = "test-oauth-state-secret-32chars!";

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    MCP_JWT_SECRET,
    SESSION_COOKIE_SECRET: SESSION_SECRET,
    OAUTH_STATE_SECRET: STATE_SECRET,
    GITHUB_MCP_CLIENT_ID: "Iv1.test",
    ...overrides,
  });
  return { env, kv };
}

function pairRec(overrides: Partial<PairRecord> = {}): PairRecord {
  const now = Date.now();
  return {
    pair_code: "PC1",
    claim_login: "alice",
    binary_version: "v0.0.13",
    created_at: now,
    expires_at: now + PAIR_CODE_TTL_SEC * 1000,
    status: "pending",
    binding_jwt: null,
    ...overrides,
  };
}

async function reqWith(opts: { cookie?: string; code?: string } = {}): Promise<Request> {
  const headers: Record<string, string> = {};
  if (opts.cookie) headers.Cookie = opts.cookie;
  return new Request(`${ISSUER}/mcp/pair/${opts.code ?? "PC1"}`, { headers });
}

describe("handleMcpPairClaim — env guard", () => {
  it.each([
    ["MCP_OAUTH_KV", { MCP_OAUTH_KV: undefined as unknown as undefined }],
    ["MCP_JWT_SECRET", { MCP_JWT_SECRET: "" }],
    ["SESSION_COOKIE_SECRET", { SESSION_COOKIE_SECRET: "" }],
    ["OAUTH_STATE_SECRET", { OAUTH_STATE_SECRET: "" }],
    ["GITHUB_MCP_CLIENT_ID", { GITHUB_MCP_CLIENT_ID: undefined }],
    ["AUTH_WORKER_ORIGIN", { AUTH_WORKER_ORIGIN: "" }],
  ])("503 when %s missing", async (_label, overrides) => {
    const { env } = envWithKv(overrides as Partial<Env>);
    const res = await handleMcpPairClaim(await reqWith(), env, "PC1");
    expect(res.status).toBe(503);
  });
});

describe("handleMcpPairClaim — cookie missing → GitHub OAuth redirect", () => {
  it("redirects to github.com/login/oauth/authorize with provider=github_mcp_pair state", async () => {
    const { env } = envWithKv();
    const res = await handleMcpPairClaim(await reqWith(), env, "PC1");
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.origin).toBe("https://github.com");
    expect(loc.pathname).toBe("/login/oauth/authorize");
    expect(loc.searchParams.get("client_id")).toBe("Iv1.test");
    expect(loc.searchParams.get("redirect_uri")).toBe(`${ISSUER}/mcp/pair_callback`);
    // state は HMAC + payload なので「.」を含む
    expect(loc.searchParams.get("state")).toContain(".");
  });

  it("redirects even when cookie is malformed (no verify)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpPairClaim(
      await reqWith({ cookie: `${PAIR_SESSION_COOKIE_NAME}=garbage` }),
      env,
      "PC1",
    );
    expect(res.status).toBe(302);
  });
});

describe("handleMcpPairClaim — record / mismatch errors", () => {
  it("404 when record not found", async () => {
    const { env } = envWithKv();
    const sess = await signPairSession("alice", SESSION_SECRET);
    const res = await handleMcpPairClaim(
      await reqWith({ cookie: `${PAIR_SESSION_COOKIE_NAME}=${sess}`, code: "missing" }),
      env,
      "missing",
    );
    expect(res.status).toBe(404);
    const text = await res.text();
    expect(text).toContain("expired");
  });

  it("403 when claim_login != session.github_login", async () => {
    const { env } = envWithKv();
    await putPair(env, pairRec({ claim_login: "alice" }));
    const sess = await signPairSession("intruder", SESSION_SECRET);
    const res = await handleMcpPairClaim(
      await reqWith({ cookie: `${PAIR_SESSION_COOKIE_NAME}=${sess}` }),
      env,
      "PC1",
    );
    expect(res.status).toBe(403);
    const text = await res.text();
    expect(text).toContain("intruder");
    expect(text).toContain("alice");
  });
});

describe("handleMcpPairClaim — success", () => {
  it("approves the record + mints binding_jwt + returns 200 HTML", async () => {
    const { env, kv } = envWithKv();
    await putPair(env, pairRec({ claim_login: "alice" }));
    const sess = await signPairSession("alice", SESSION_SECRET);
    const res = await handleMcpPairClaim(
      await reqWith({ cookie: `${PAIR_SESSION_COOKIE_NAME}=${sess}` }),
      env,
      "PC1",
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Paired");
    expect(html).toContain("alice");
    // KV 確認
    const updated = JSON.parse(kv._data["mcp/pair/PC1"]!) as PairRecord;
    expect(updated.status).toBe("approved");
    expect(updated.binding_jwt).toBeTruthy();
    // binding_jwt が valid (aud=github-mcp-server-rs)
    const payload = await verifyMcpJwt(
      updated.binding_jwt!,
      MCP_JWT_SECRET,
      "github-mcp-server-rs",
    );
    expect(payload).not.toBeNull();
    expect(payload?.github_login).toBe("alice");
    expect(payload?.scope).toBe("mcp.read mcp.write");
  });

  it("returns 200 idempotent message when already approved (no re-mint)", async () => {
    const { env, kv } = envWithKv();
    await putPair(env, pairRec({ claim_login: "alice", status: "approved", binding_jwt: "OLD-JWT" }));
    const sess = await signPairSession("alice", SESSION_SECRET);
    const res = await handleMcpPairClaim(
      await reqWith({ cookie: `${PAIR_SESSION_COOKIE_NAME}=${sess}` }),
      env,
      "PC1",
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Paired");
    // binding_jwt は変化していない
    const updated = JSON.parse(kv._data["mcp/pair/PC1"]!) as PairRecord;
    expect(updated.binding_jwt).toBe("OLD-JWT");
  });

  it("404 when record vanishes between getPair and approvePair (race path)", async () => {
    const { env, kv } = envWithKv();
    await putPair(env, pairRec({ claim_login: "alice" }));
    // approvePair の get 時点で消すよう KV を細工 (race を模擬)。
    // → 簡易には kv.get を override する代わりに、approvePair 内の getPair の
    //   2 回目読込を不在にする。実装上、approvePair が record を 2 度 get
    //   するので、ここでは getPair → 直後に手動で delete することで擬似的に再現する。
    // この test は実装の race window 取扱 (= updated null → 404 path) のみ確認。
    // approve 直前で消すために、kv.get を一時的に書き換える。
    const realGet = kv.get.bind(kv);
    let getCount = 0;
    kv.get = async (key: string) => {
      getCount++;
      // 1 回目 (handler 側 getPair) は record を返し、2 回目 (approvePair 側) は null
      if (key === "mcp/pair/PC1" && getCount === 2) return null;
      return realGet(key);
    };
    const sess = await signPairSession("alice", SESSION_SECRET);
    const res = await handleMcpPairClaim(
      await reqWith({ cookie: `${PAIR_SESSION_COOKIE_NAME}=${sess}` }),
      env,
      "PC1",
    );
    expect(res.status).toBe(404);
  });
});
