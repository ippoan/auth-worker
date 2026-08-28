import { describe, it, expect } from "vitest";
import { handleMcpShot } from "../../src/handlers/mcp-shot";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import { base64Encode } from "../../src/lib/lineworks-crypto";
import { VERIFY_SHOT_KV_PREFIX } from "../../src/lib/verify-shot";

const ID = "a".repeat(64);
const REQ = new Request(`https://auth.test.example/mcp/shot/${ID}`);

describe("GET /mcp/shot/:id", () => {
  it("returns the stored PNG bytes with no-store", async () => {
    const kv = createMockKV() as MockKV;
    const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]);
    kv._data[`${VERIFY_SHOT_KV_PREFIX}${ID}`] = base64Encode(png);
    const env = createMockEnv({ MCP_OAUTH_KV: kv });
    const res = await handleMcpShot(REQ, env, ID);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/png");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(png);
  });

  it("404s for an unknown id", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: createMockKV() });
    const res = await handleMcpShot(REQ, env, ID);
    expect(res.status).toBe(404);
  });

  it("404s for a malformed id without touching KV", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: createMockKV() });
    for (const bad of ["short", "A".repeat(64), `${"a".repeat(63)}/`, `${"a".repeat(64)}x`]) {
      const res = await handleMcpShot(REQ, env, bad);
      expect(res.status).toBe(404);
    }
  });

  it("503s when MCP_OAUTH_KV is not bound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined });
    const res = await handleMcpShot(REQ, env, ID);
    expect(res.status).toBe(503);
  });
});
