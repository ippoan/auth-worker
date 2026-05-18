/**
 * `handleMcpPairNew` (issue #144) — `POST /mcp/pair/new` テスト。
 *
 * env guard / body parse / rate-limit / KV put + response shape を網羅。
 */

import { describe, it, expect } from "vitest";
import { handleMcpPairNew } from "../../src/handlers/mcp-pair-new";
import {
  PAIR_CODE_TTL_SEC,
  checkAndBumpRateLimit,
  type PairRecord,
} from "../../src/lib/mcp-pair";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth.test.example";

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    ...overrides,
  });
  return { env, kv };
}

function req(opts: { body?: unknown; ip?: string | null; bodyText?: string } = {}): Request {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.ip !== null && opts.ip !== undefined) headers["cf-connecting-ip"] = opts.ip;
  const body =
    opts.bodyText !== undefined
      ? opts.bodyText
      : opts.body === undefined
        ? undefined
        : JSON.stringify(opts.body);
  return new Request("https://mcp.test.example/mcp/pair/new", {
    method: "POST",
    headers,
    body,
  });
}

describe("handleMcpPairNew — env guards", () => {
  it("503 when MCP_OAUTH_KV not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined, AUTH_WORKER_ORIGIN: ISSUER });
    const res = await handleMcpPairNew(req({ body: { claim_login: "a" } }), env);
    expect(res.status).toBe(503);
  });

  it("503 when AUTH_WORKER_ORIGIN missing", async () => {
    const { env } = envWithKv({ AUTH_WORKER_ORIGIN: "" });
    const res = await handleMcpPairNew(req({ body: { claim_login: "a" } }), env);
    expect(res.status).toBe(503);
  });
});

describe("handleMcpPairNew — body parsing", () => {
  it("400 on malformed JSON body", async () => {
    const { env } = envWithKv();
    const res = await handleMcpPairNew(req({ bodyText: "{not json" }), env);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe("invalid_request");
  });

  it("400 when claim_login is missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpPairNew(req({ body: {} }), env);
    expect(res.status).toBe(400);
  });

  it("400 when claim_login is empty string", async () => {
    const { env } = envWithKv();
    const res = await handleMcpPairNew(req({ body: { claim_login: "" } }), env);
    expect(res.status).toBe(400);
  });

  it("400 when claim_login is not a string", async () => {
    const { env } = envWithKv();
    const res = await handleMcpPairNew(req({ body: { claim_login: 42 } }), env);
    expect(res.status).toBe(400);
  });
});

describe("handleMcpPairNew — success path", () => {
  it("200 with pair_code/pair_url/expires_in + KV record persisted", async () => {
    const { env, kv } = envWithKv();
    const res = await handleMcpPairNew(
      req({ body: { claim_login: "alice", binary_version: "v0.0.13" }, ip: "1.2.3.4" }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      pair_code: string;
      pair_url: string;
      expires_in: number;
    };
    expect(body.pair_code).toMatch(/^[A-Za-z0-9_-]{40}$/);
    expect(body.pair_url).toBe(`${ISSUER}/mcp/pair/${body.pair_code}`);
    expect(body.expires_in).toBe(PAIR_CODE_TTL_SEC);

    // KV check
    const key = `mcp/pair/${body.pair_code}`;
    expect(kv._data[key]).toBeDefined();
    const rec = JSON.parse(kv._data[key]!) as PairRecord;
    expect(rec.claim_login).toBe("alice");
    expect(rec.binary_version).toBe("v0.0.13");
    expect(rec.status).toBe("pending");
    expect(rec.binding_jwt).toBeNull();
    expect(kv._ttls[key]).toBe(PAIR_CODE_TTL_SEC);
  });

  it("defaults binary_version to 'unknown' when not provided", async () => {
    const { env, kv } = envWithKv();
    const res = await handleMcpPairNew(req({ body: { claim_login: "alice" } }), env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { pair_code: string };
    const rec = JSON.parse(kv._data[`mcp/pair/${body.pair_code}`]!) as PairRecord;
    expect(rec.binary_version).toBe("unknown");
  });

  it("defaults binary_version to 'unknown' when given non-string", async () => {
    const { env, kv } = envWithKv();
    const res = await handleMcpPairNew(
      req({ body: { claim_login: "alice", binary_version: 123 } }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { pair_code: string };
    const rec = JSON.parse(kv._data[`mcp/pair/${body.pair_code}`]!) as PairRecord;
    expect(rec.binary_version).toBe("unknown");
  });

  it("uses 'anon' as IP key when cf-connecting-ip is missing", async () => {
    const { env, kv } = envWithKv();
    const res = await handleMcpPairNew(
      req({ body: { claim_login: "alice" }, ip: null }),
      env,
    );
    expect(res.status).toBe(200);
    // anon bucket key が存在することを確認
    const anonKeys = Object.keys(kv._data).filter((k) => k.startsWith("mcp/pair_rate/anon/"));
    expect(anonKeys.length).toBe(1);
  });
});

describe("handleMcpPairNew — requested_scope plumbing", () => {
  it("defaults requested_scope to 'mcp.read mcp.write' when omitted", async () => {
    const { env, kv } = envWithKv();
    const res = await handleMcpPairNew(req({ body: { claim_login: "alice" } }), env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { pair_code: string };
    const rec = JSON.parse(kv._data[`mcp/pair/${body.pair_code}`]!) as PairRecord;
    expect(rec.requested_scope).toBe("mcp.read mcp.write");
  });

  it("persists requested_scope=mcp.admin verbatim (admin-only token)", async () => {
    const { env, kv } = envWithKv();
    const res = await handleMcpPairNew(
      req({ body: { claim_login: "alice", requested_scope: "mcp.admin" } }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { pair_code: string };
    const rec = JSON.parse(kv._data[`mcp/pair/${body.pair_code}`]!) as PairRecord;
    expect(rec.requested_scope).toBe("mcp.admin");
  });

  it("normalizes requested_scope to canonical MCP_SCOPES_SUPPORTED order", async () => {
    const { env, kv } = envWithKv();
    const res = await handleMcpPairNew(
      req({ body: { claim_login: "alice", requested_scope: "mcp.admin mcp.write mcp.read" } }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { pair_code: string };
    const rec = JSON.parse(kv._data[`mcp/pair/${body.pair_code}`]!) as PairRecord;
    expect(rec.requested_scope).toBe("mcp.read mcp.write mcp.admin");
  });

  it("unknown-only requested_scope decays to 'mcp.read' (RFC 6749 §3.3 ignore)", async () => {
    const { env, kv } = envWithKv();
    const res = await handleMcpPairNew(
      req({ body: { claim_login: "alice", requested_scope: "garbage another" } }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { pair_code: string };
    const rec = JSON.parse(kv._data[`mcp/pair/${body.pair_code}`]!) as PairRecord;
    expect(rec.requested_scope).toBe("mcp.read");
  });

  it("non-string requested_scope ignored, default applies", async () => {
    const { env, kv } = envWithKv();
    const res = await handleMcpPairNew(
      req({ body: { claim_login: "alice", requested_scope: 42 } }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { pair_code: string };
    const rec = JSON.parse(kv._data[`mcp/pair/${body.pair_code}`]!) as PairRecord;
    expect(rec.requested_scope).toBe("mcp.read mcp.write");
  });
});

describe("handleMcpPairNew — rate limit", () => {
  it("429 after 10 requests in 1 minute from same IP", async () => {
    const { env } = envWithKv();
    // 11 連発 — 10 までは 200、11 回目は 429
    for (let i = 0; i < 10; i++) {
      const res = await handleMcpPairNew(
        req({ body: { claim_login: "alice" }, ip: "9.9.9.9" }),
        env,
      );
      expect(res.status).toBe(200);
    }
    const eleventh = await handleMcpPairNew(
      req({ body: { claim_login: "alice" }, ip: "9.9.9.9" }),
      env,
    );
    expect(eleventh.status).toBe(429);
    const body = (await eleventh.json()) as { error: string };
    expect(body.error).toBe("rate_limited");
  });

  it("does not call putPair when rate limited (preserve KV slot for legitimate requests)", async () => {
    const { env, kv } = envWithKv();
    // pre-fill bucket to 10
    const now = Date.now();
    for (let i = 0; i < 10; i++) {
      await checkAndBumpRateLimit(env, "8.8.8.8", now);
    }
    const before = Object.keys(kv._data).filter((k) => k.startsWith("mcp/pair/")).length;
    const res = await handleMcpPairNew(
      req({ body: { claim_login: "alice" }, ip: "8.8.8.8" }),
      env,
    );
    expect(res.status).toBe(429);
    const after = Object.keys(kv._data).filter((k) => k.startsWith("mcp/pair/")).length;
    expect(after).toBe(before);
  });
});
