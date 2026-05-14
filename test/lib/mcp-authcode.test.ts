/**
 * `src/lib/mcp-authcode.ts` unit test (Phase 5 / #128).
 */

import { describe, it, expect } from "vitest";
import {
  type AuthCodeRecord,
  type AuthRequestRecord,
  AUTH_CODE_TTL_SEC,
  AUTH_REQUEST_TTL_SEC,
  consumeAuthCode,
  deleteAuthRequest,
  getAuthRequest,
  putAuthCode,
  putAuthRequest,
} from "../../src/lib/mcp-authcode";
import { createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

function envWithKv(): { env: Env; kv: MockKV } {
  const kv = createMockKV() as unknown as MockKV;
  const env = { MCP_OAUTH_KV: kv } as unknown as Env;
  return { env, kv };
}

function sampleRequest(id: string): AuthRequestRecord {
  return {
    id,
    client_id: "c-1",
    redirect_uri: "https://claude.ai/cb",
    code_challenge: "abc",
    code_challenge_method: "S256",
    client_state: "csrf-1",
    scope: "mcp.read",
    expires_at: Date.now() + 60_000,
  };
}

function sampleCode(code: string): AuthCodeRecord {
  return {
    code,
    client_id: "c-1",
    redirect_uri: "https://claude.ai/cb",
    code_challenge: "abc",
    code_challenge_method: "S256",
    github_login: "alice",
    scope: "mcp.read",
    expires_at: Date.now() + 60_000,
  };
}

describe("auth:request:* CRUD", () => {
  it("put/get round-trips with TTL", async () => {
    const { env, kv } = envWithKv();
    await putAuthRequest(env, sampleRequest("r-1"));
    expect(kv._ttls["auth:request:r-1"]).toBe(AUTH_REQUEST_TTL_SEC);
    const got = await getAuthRequest(env, "r-1");
    expect(got?.client_state).toBe("csrf-1");
  });

  it("getAuthRequest returns null for unknown id", async () => {
    const { env } = envWithKv();
    expect(await getAuthRequest(env, "x")).toBeNull();
  });

  it("getAuthRequest returns null on malformed JSON", async () => {
    const { env, kv } = envWithKv();
    kv._data["auth:request:bad"] = "{";
    expect(await getAuthRequest(env, "bad")).toBeNull();
  });

  it("deleteAuthRequest removes the entry", async () => {
    const { env, kv } = envWithKv();
    await putAuthRequest(env, sampleRequest("r-2"));
    await deleteAuthRequest(env, "r-2");
    expect(kv._data["auth:request:r-2"]).toBeUndefined();
  });

  it("KV-not-bound: getAuthRequest → null, putAuthRequest → throws, deleteAuthRequest → no-op", async () => {
    const env = {} as Env;
    expect(await getAuthRequest(env, "x")).toBeNull();
    await expect(putAuthRequest(env, sampleRequest("x"))).rejects.toThrow(
      /MCP_OAUTH_KV not bound/,
    );
    // delete は静かに通過 (no throw, no effect)
    await deleteAuthRequest(env, "x");
  });
});

describe("auth:code:* lifecycle (single-use)", () => {
  it("put then consume returns record once and deletes the entry", async () => {
    const { env, kv } = envWithKv();
    await putAuthCode(env, sampleCode("ac-1"));
    expect(kv._ttls["auth:code:ac-1"]).toBe(AUTH_CODE_TTL_SEC);
    const first = await consumeAuthCode(env, "ac-1");
    expect(first?.github_login).toBe("alice");
    expect(kv._data["auth:code:ac-1"]).toBeUndefined();
    // 2 回目は null
    const second = await consumeAuthCode(env, "ac-1");
    expect(second).toBeNull();
  });

  it("consumeAuthCode returns null for unknown code", async () => {
    const { env } = envWithKv();
    expect(await consumeAuthCode(env, "missing")).toBeNull();
  });

  it("consumeAuthCode returns null on malformed JSON (entry still deleted)", async () => {
    const { env, kv } = envWithKv();
    kv._data["auth:code:bad"] = "{";
    expect(await consumeAuthCode(env, "bad")).toBeNull();
    expect(kv._data["auth:code:bad"]).toBeUndefined();
  });

  it("KV-not-bound: putAuthCode throws, consumeAuthCode → null", async () => {
    const env = {} as Env;
    await expect(putAuthCode(env, sampleCode("x"))).rejects.toThrow(
      /MCP_OAUTH_KV not bound/,
    );
    expect(await consumeAuthCode(env, "x")).toBeNull();
  });
});
