/**
 * `src/lib/mcp-dcr.ts` unit test (Phase 5 / #128).
 */

import { describe, it, expect } from "vitest";
import {
  type DcrClientRecord,
  DCR_CLIENT_TTL_SEC,
  getDcrClient,
  putDcrClient,
} from "../../src/lib/mcp-dcr";
import { createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

function envWithKv(): { env: Env; kv: MockKV } {
  const kv = createMockKV() as unknown as MockKV;
  const env = { MCP_OAUTH_KV: kv } as unknown as Env;
  return { env, kv };
}

function sampleRec(client_id: string): DcrClientRecord {
  return {
    client_id,
    client_id_issued_at: 1_000_000,
    token_endpoint_auth_method: "none",
    response_types: ["code"],
    grant_types: ["authorization_code", "refresh_token"],
    redirect_uris: ["https://claude.ai/cb"],
    client_name: "Test",
    scope: "mcp.read mcp.write",
  };
}

describe("putDcrClient / getDcrClient", () => {
  it("round-trips a record under dcr:client:<id> with 90d TTL", async () => {
    const { env, kv } = envWithKv();
    await putDcrClient(env, sampleRec("c-1"));
    expect(kv._data["dcr:client:c-1"]).toBeDefined();
    expect(kv._ttls["dcr:client:c-1"]).toBe(DCR_CLIENT_TTL_SEC);
    const got = await getDcrClient(env, "c-1");
    expect(got?.client_id).toBe("c-1");
    expect(got?.redirect_uris).toEqual(["https://claude.ai/cb"]);
  });

  it("getDcrClient returns null for unknown client_id", async () => {
    const { env } = envWithKv();
    expect(await getDcrClient(env, "missing")).toBeNull();
  });

  it("getDcrClient returns null when KV value is malformed JSON", async () => {
    const { env, kv } = envWithKv();
    kv._data["dcr:client:bad"] = "{not json";
    expect(await getDcrClient(env, "bad")).toBeNull();
  });

  it("getDcrClient returns null when KV is not bound", async () => {
    const env = {} as Env;
    expect(await getDcrClient(env, "any")).toBeNull();
  });

  it("putDcrClient throws when KV is not bound", async () => {
    const env = {} as Env;
    await expect(putDcrClient(env, sampleRec("x"))).rejects.toThrow(
      /MCP_OAUTH_KV not bound/,
    );
  });
});
