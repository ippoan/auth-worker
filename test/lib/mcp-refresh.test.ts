import { describe, it, expect } from "vitest";
import {
  issueRefreshToken,
  consumeRefreshToken,
  REFRESH_TTL_SEC,
} from "../../src/lib/mcp-refresh";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

function envWithKv(): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({ MCP_OAUTH_KV: kv });
  return { env, kv };
}

describe("mcp-refresh", () => {
  describe("issueRefreshToken", () => {
    it("returns 64-char hex token + writes refresh:{hash} to KV with TTL 30d", async () => {
      const { env, kv } = envWithKv();
      const tok = await issueRefreshToken(env, {
        sub: "github:alice",
        scope: "read:user",
        github_login: "alice",
      });
      expect(tok).toMatch(/^[0-9a-f]{64}$/);
      const keys = Object.keys(kv._data).filter((k) => k.startsWith("refresh:"));
      expect(keys).toHaveLength(1);
      const stored = JSON.parse(kv._data[keys[0]!]!) as Record<string, unknown>;
      expect(stored.sub).toBe("github:alice");
      expect(stored.scope).toBe("read:user");
      expect(stored.github_login).toBe("alice");
      expect(typeof stored.expires_at).toBe("number");
      expect(stored.rotated_from).toBeUndefined();
      expect(kv._ttls[keys[0]!]).toBe(REFRESH_TTL_SEC);
    });

    it("records rotated_from when provided", async () => {
      const { env, kv } = envWithKv();
      await issueRefreshToken(env, {
        sub: "github:bob",
        scope: "",
        github_login: "bob",
        rotated_from: "deadbeef",
      });
      const key = Object.keys(kv._data).find((k) => k.startsWith("refresh:"))!;
      const stored = JSON.parse(kv._data[key]!) as Record<string, unknown>;
      expect(stored.rotated_from).toBe("deadbeef");
    });

    it("throws when KV not bound", async () => {
      const env = createMockEnv({ MCP_OAUTH_KV: undefined });
      await expect(
        issueRefreshToken(env, { sub: "x", scope: "", github_login: "x" }),
      ).rejects.toThrow(/not bound/);
    });
  });

  describe("consumeRefreshToken", () => {
    it("returns the record and deletes KV entry on success (rotation)", async () => {
      const { env, kv } = envWithKv();
      const tok = await issueRefreshToken(env, {
        sub: "github:carol",
        scope: "read:user",
        github_login: "carol",
      });
      const consumed = await consumeRefreshToken(env, tok);
      expect(consumed).not.toBeNull();
      expect(consumed!.sub).toBe("github:carol");
      expect(consumed!.github_login).toBe("carol");
      expect(consumed!.hash).toMatch(/^[0-9a-f]{64}$/);
      // KV entry is gone (rotation)
      const remaining = Object.keys(kv._data).filter((k) => k.startsWith("refresh:"));
      expect(remaining).toHaveLength(0);
    });

    it("returns null on second consumption (rotation enforced)", async () => {
      const { env } = envWithKv();
      const tok = await issueRefreshToken(env, {
        sub: "github:dave",
        scope: "",
        github_login: "dave",
      });
      expect(await consumeRefreshToken(env, tok)).not.toBeNull();
      expect(await consumeRefreshToken(env, tok)).toBeNull();
    });

    it("returns null for unknown token", async () => {
      const { env } = envWithKv();
      expect(await consumeRefreshToken(env, "not-a-real-token")).toBeNull();
    });

    it("returns null and deletes KV when token is expired", async () => {
      const { env, kv } = envWithKv();
      // manually write an expired record bypassing issueRefreshToken
      const fakeHash = "a".repeat(64);
      // We need the token whose sha256 hex == fakeHash — impossible, so write a real
      // token's hash but with expired expires_at.
      const tok = await issueRefreshToken(env, {
        sub: "github:eve",
        scope: "",
        github_login: "eve",
      });
      // find its key
      const key = Object.keys(kv._data).find((k) => k.startsWith("refresh:"))!;
      const rec = JSON.parse(kv._data[key]!) as { expires_at: number };
      rec.expires_at = Date.now() - 1000;
      kv._data[key] = JSON.stringify(rec);
      expect(await consumeRefreshToken(env, tok)).toBeNull();
      // delete-first means even expired entries are removed
      expect(kv._data[key]).toBeUndefined();
      // ensure fakeHash silenced lint (no use)
      expect(fakeHash.length).toBe(64);
    });

    it("returns null when KV value is malformed JSON", async () => {
      const { env, kv } = envWithKv();
      const tok = await issueRefreshToken(env, {
        sub: "github:frank",
        scope: "",
        github_login: "frank",
      });
      const key = Object.keys(kv._data).find((k) => k.startsWith("refresh:"))!;
      kv._data[key] = "not-json{";
      expect(await consumeRefreshToken(env, tok)).toBeNull();
    });

    it("throws when KV not bound", async () => {
      const env = createMockEnv({ MCP_OAUTH_KV: undefined });
      await expect(consumeRefreshToken(env, "tok")).rejects.toThrow(/not bound/);
    });
  });
});
