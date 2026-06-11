import { describe, it, expect } from "vitest";
import {
  issueRefreshToken,
  consumeRefreshToken,
  markRefreshRotated,
  REFRESH_TTL_SEC,
  GRACE_TTL_SEC,
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
    it("resolves a normal token to {kind:record} WITHOUT deleting (grace rotation, Refs #270)", async () => {
      const { env, kv } = envWithKv();
      const tok = await issueRefreshToken(env, {
        sub: "github:carol",
        scope: "read:user",
        github_login: "carol",
      });
      const consumed = await consumeRefreshToken(env, tok);
      expect(consumed).not.toBeNull();
      expect(consumed!.kind).toBe("record");
      if (consumed!.kind !== "record") throw new Error("unreachable");
      expect(consumed!.record.sub).toBe("github:carol");
      expect(consumed!.record.github_login).toBe("carol");
      expect(consumed!.record.hash).toMatch(/^[0-9a-f]{64}$/);
      // delete-first を廃したので consume だけでは KV entry は消えない
      // (one-shot は markRefreshRotated の grace 置換で担保する)。
      const remaining = Object.keys(kv._data).filter((k) => k.startsWith("refresh:"));
      expect(remaining).toHaveLength(1);
    });

    it("does not enforce one-shot by itself (rotation is via markRefreshRotated)", async () => {
      const { env } = envWithKv();
      const tok = await issueRefreshToken(env, {
        sub: "github:dave", scope: "", github_login: "dave",
      });
      // 通常 record は (rotation されるまで) 何度読んでも kind:record。
      const a = await consumeRefreshToken(env, tok);
      const b = await consumeRefreshToken(env, tok);
      expect(a?.kind).toBe("record");
      expect(b?.kind).toBe("record");
    });

    it("after markRefreshRotated, the OLD token resolves to {kind:grace} with the SAME pair", async () => {
      const { env, kv } = envWithKv();
      const tok = await issueRefreshToken(env, {
        sub: "github:grace", scope: "mcp.read", github_login: "grace",
      });
      const consumed = await consumeRefreshToken(env, tok);
      if (consumed?.kind !== "record") throw new Error("expected record");
      // rotation: 新 pair を発行したことにして旧 hash を grace 置換。
      await markRefreshRotated(env, consumed.record.hash, {
        access_token: "AT_NEW", refresh_token: "RT_NEW", scope: "mcp.read",
      });
      const key = `refresh:${consumed.record.hash}`;
      expect(kv._ttls[key]).toBe(GRACE_TTL_SEC);

      const reused = await consumeRefreshToken(env, tok);
      expect(reused?.kind).toBe("grace");
      if (reused?.kind !== "grace") throw new Error("unreachable");
      expect(reused.grace.access_token).toBe("AT_NEW");
      expect(reused.grace.refresh_token).toBe("RT_NEW");
      expect(reused.grace.scope).toBe("mcp.read");
    });

    it("returns null and clears the slot once the grace window has passed", async () => {
      const { env, kv } = envWithKv();
      const tok = await issueRefreshToken(env, {
        sub: "github:heidi", scope: "", github_login: "heidi",
      });
      const consumed = await consumeRefreshToken(env, tok);
      if (consumed?.kind !== "record") throw new Error("expected record");
      await markRefreshRotated(env, consumed.record.hash, {
        access_token: "AT", refresh_token: "RT", scope: "",
      });
      // grace_until を過去に倒す。
      const key = `refresh:${consumed.record.hash}`;
      const g = JSON.parse(kv._data[key]!) as { grace_until: number };
      g.grace_until = Date.now() - 1000;
      kv._data[key] = JSON.stringify(g);

      expect(await consumeRefreshToken(env, tok)).toBeNull();
      expect(kv._data[key]).toBeUndefined(); // 超過 grace slot は掃除される
    });

    it("returns null for unknown token", async () => {
      const { env } = envWithKv();
      expect(await consumeRefreshToken(env, "not-a-real-token")).toBeNull();
    });

    it("returns null when the normal record is expired", async () => {
      const { env, kv } = envWithKv();
      const tok = await issueRefreshToken(env, {
        sub: "github:eve", scope: "", github_login: "eve",
      });
      const key = Object.keys(kv._data).find((k) => k.startsWith("refresh:"))!;
      const rec = JSON.parse(kv._data[key]!) as { expires_at: number };
      rec.expires_at = Date.now() - 1000;
      kv._data[key] = JSON.stringify(rec);
      expect(await consumeRefreshToken(env, tok)).toBeNull();
    });

    it("returns null when KV value is malformed JSON", async () => {
      const { env, kv } = envWithKv();
      const tok = await issueRefreshToken(env, {
        sub: "github:frank", scope: "", github_login: "frank",
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

  describe("markRefreshRotated", () => {
    it("throws when KV not bound", async () => {
      const env = createMockEnv({ MCP_OAUTH_KV: undefined });
      await expect(
        markRefreshRotated(env, "deadbeef", { access_token: "a", refresh_token: "r", scope: "" }),
      ).rejects.toThrow(/not bound/);
    });
  });
});
