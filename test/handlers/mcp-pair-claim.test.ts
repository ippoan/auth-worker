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
 * - requested_scope が record にあれば binding_jwt.scope に焼かれる
 * - requested_scope が record に無い (legacy) → "mcp.read mcp.write" に decay
 */

import { describe, it, expect } from "vitest";
import { handleMcpPairClaim } from "../../src/handlers/mcp-pair-claim";
import { verifyMcpJwt } from "../../src/lib/mcp-jwt";
import {
  PAIR_CODE_TTL_SEC,
  PAIR_REFRESH_TTL_SEC,
  getPairRefresh,
  hashRefreshToken,
  putPair,
  type PairRecord,
  type PairRefreshRecord,
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
    // legacy record (requested_scope なし) → default
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
    // KVNamespace.get は overload なので Promise<string|null> 単一型に再代入できない。
    // cast して race を模擬する。
    const realGet = (kv.get as (k: string) => Promise<string | null>).bind(kv);
    let getCount = 0;
    const stubGet = async (key: string): Promise<string | null> => {
      getCount++;
      // 1 回目 (handler 側 getPair) は record を返し、2 回目 (approvePair 側) は null
      if (key === "mcp/pair/PC1" && getCount === 2) return null;
      return realGet(key);
    };
    (kv as unknown as { get: (k: string) => Promise<string | null> }).get = stubGet;
    const sess = await signPairSession("alice", SESSION_SECRET);
    const res = await handleMcpPairClaim(
      await reqWith({ cookie: `${PAIR_SESSION_COOKIE_NAME}=${sess}` }),
      env,
      "PC1",
    );
    expect(res.status).toBe(404);
  });
});

describe("handleMcpPairClaim — requested_scope plumbing", () => {
  it("honors record.requested_scope=mcp.admin in binding_jwt.scope", async () => {
    const { env, kv } = envWithKv();
    await putPair(
      env,
      pairRec({ claim_login: "alice", requested_scope: "mcp.admin" }),
    );
    const sess = await signPairSession("alice", SESSION_SECRET);
    const res = await handleMcpPairClaim(
      await reqWith({ cookie: `${PAIR_SESSION_COOKIE_NAME}=${sess}` }),
      env,
      "PC1",
    );
    expect(res.status).toBe(200);
    const updated = JSON.parse(kv._data["mcp/pair/PC1"]!) as PairRecord;
    const payload = await verifyMcpJwt(
      updated.binding_jwt!,
      MCP_JWT_SECRET,
      "github-mcp-server-rs",
    );
    expect(payload?.scope).toBe("mcp.admin");
    // success HTML にも scope が表示される (運用デバッグ用)
    const html = await res.text();
    expect(html).toContain("mcp.admin");
  });

  it("honors record.requested_scope=mcp.read in binding_jwt.scope (read-only)", async () => {
    const { env, kv } = envWithKv();
    await putPair(
      env,
      pairRec({ claim_login: "alice", requested_scope: "mcp.read" }),
    );
    const sess = await signPairSession("alice", SESSION_SECRET);
    const res = await handleMcpPairClaim(
      await reqWith({ cookie: `${PAIR_SESSION_COOKIE_NAME}=${sess}` }),
      env,
      "PC1",
    );
    expect(res.status).toBe(200);
    const updated = JSON.parse(kv._data["mcp/pair/PC1"]!) as PairRecord;
    const payload = await verifyMcpJwt(
      updated.binding_jwt!,
      MCP_JWT_SECRET,
      "github-mcp-server-rs",
    );
    expect(payload?.scope).toBe("mcp.read");
  });

  it("legacy record without requested_scope → defaults to 'mcp.read mcp.write'", async () => {
    const { env, kv } = envWithKv();
    // pairRec helper は requested_scope を set しない → legacy record 相当
    await putPair(env, pairRec({ claim_login: "alice" }));
    const sess = await signPairSession("alice", SESSION_SECRET);
    const res = await handleMcpPairClaim(
      await reqWith({ cookie: `${PAIR_SESSION_COOKIE_NAME}=${sess}` }),
      env,
      "PC1",
    );
    expect(res.status).toBe(200);
    const updated = JSON.parse(kv._data["mcp/pair/PC1"]!) as PairRecord;
    const payload = await verifyMcpJwt(
      updated.binding_jwt!,
      MCP_JWT_SECRET,
      "github-mcp-server-rs",
    );
    expect(payload?.scope).toBe("mcp.read mcp.write");
  });
});

// ────────────────────────────────────────────────────────────────────────
// issue #157 Phase A: refresh_token mint on approve
// ────────────────────────────────────────────────────────────────────────

describe("handleMcpPairClaim — refresh_token (issue #157)", () => {
  it("mints refresh_token + writes mcp/pair_refresh/<hash> with 30d TTL", async () => {
    const { env, kv } = envWithKv();
    await putPair(env, pairRec({ claim_login: "alice", requested_scope: "mcp.read" }));
    const sess = await signPairSession("alice", SESSION_SECRET);
    const res = await handleMcpPairClaim(
      await reqWith({ cookie: `${PAIR_SESSION_COOKIE_NAME}=${sess}` }),
      env,
      "PC1",
    );
    expect(res.status).toBe(200);

    const updated = JSON.parse(kv._data["mcp/pair/PC1"]!) as PairRecord;
    expect(updated.refresh_token).toBeTruthy();
    expect(updated.refresh_token!.length).toBe(43); // base64url(32 byte) = 43
    expect(updated.refresh_token_expires_at).toBeGreaterThan(Date.now());

    // hash lookup で本体を引ける
    const hash = await hashRefreshToken(updated.refresh_token!);
    const refRec = await getPairRefresh(env, hash);
    expect(refRec).not.toBeNull();
    expect(refRec!.github_login).toBe("alice");
    expect(refRec!.requested_scope).toBe("mcp.read");
    expect(refRec!.revoked).toBe(false);
    expect(refRec!.last_used_at).toBeNull();
    // 30 日 ± 数秒
    expect(refRec!.expires_at - refRec!.created_at).toBe(
      PAIR_REFRESH_TTL_SEC * 1000,
    );

    // KV TTL も 30d 近辺
    const refKey = `mcp/pair_refresh/${hash}`;
    expect(kv._ttls[refKey]).toBeGreaterThan(PAIR_REFRESH_TTL_SEC - 60);
    expect(kv._ttls[refKey]).toBeLessThanOrEqual(PAIR_REFRESH_TTL_SEC);
  });

  it("legacy record (no requested_scope) → refresh record stores default scope", async () => {
    const { env, kv } = envWithKv();
    await putPair(env, pairRec({ claim_login: "alice" }));
    const sess = await signPairSession("alice", SESSION_SECRET);
    await handleMcpPairClaim(
      await reqWith({ cookie: `${PAIR_SESSION_COOKIE_NAME}=${sess}` }),
      env,
      "PC1",
    );
    const updated = JSON.parse(kv._data["mcp/pair/PC1"]!) as PairRecord;
    const refRec = (await getPairRefresh(
      env,
      await hashRefreshToken(updated.refresh_token!),
    )) as PairRefreshRecord;
    expect(refRec.requested_scope).toBe("mcp.read mcp.write");
  });

  it("idempotent re-approve (status=approved) does not mint a new refresh_token", async () => {
    const { env, kv } = envWithKv();
    await putPair(
      env,
      pairRec({
        claim_login: "alice",
        status: "approved",
        binding_jwt: "OLD-JWT",
        refresh_token: "OLD-RT",
        refresh_token_expires_at: Date.now() + 1_000_000,
      }),
    );
    const sess = await signPairSession("alice", SESSION_SECRET);
    const res = await handleMcpPairClaim(
      await reqWith({ cookie: `${PAIR_SESSION_COOKIE_NAME}=${sess}` }),
      env,
      "PC1",
    );
    expect(res.status).toBe(200);
    // refresh_token は変化していない (= 二度押しでも 30 日 token は安定)
    const updated = JSON.parse(kv._data["mcp/pair/PC1"]!) as PairRecord;
    expect(updated.refresh_token).toBe("OLD-RT");
    // 新規 mcp/pair_refresh/<hash> entry も作られていない
    const hashKeys = Object.keys(kv._data).filter((k) =>
      k.startsWith("mcp/pair_refresh/"),
    );
    expect(hashKeys).toHaveLength(0);
  });
});
