/**
 * `branch-protection-github` helpers — unit tests (issue #159 Phase 1).
 *
 * GitHub REST は `vi.stubGlobal("fetch", ...)` で stub する。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { encryptWithKey } from "../../src/lib/mcp-crypto";
import {
  deleteBranchProtection,
  fetchProtectionRows,
  getBranchProtection,
  listOwnedRepos,
  loadGithubToken,
  setBranchProtection,
} from "../../src/lib/branch-protection-github";
import { PRESETS } from "../../src/lib/branch-protection-presets";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";

const SSO_KEY = "test-sso-encryption-key";
const TOKEN = "gho_user_abc";

describe("loadGithubToken", () => {
  it("returns null when MCP_OAUTH_KV is unbound", async () => {
    const env = createMockEnv({ MCP_OAUTH_KV: undefined, SSO_ENCRYPTION_KEY: SSO_KEY });
    const t = await loadGithubToken(env, "github:alice");
    expect(t).toBeNull();
  });

  it("returns null when SSO_ENCRYPTION_KEY missing", async () => {
    const kv = createMockKV() as MockKV;
    const env = createMockEnv({ MCP_OAUTH_KV: kv });
    (env as { SSO_ENCRYPTION_KEY?: string }).SSO_ENCRYPTION_KEY = undefined;
    const t = await loadGithubToken(env, "github:alice");
    expect(t).toBeNull();
  });

  it("returns null when key missing in KV", async () => {
    const kv = createMockKV() as MockKV;
    const env = createMockEnv({ MCP_OAUTH_KV: kv, SSO_ENCRYPTION_KEY: SSO_KEY });
    const t = await loadGithubToken(env, "github:alice");
    expect(t).toBeNull();
  });

  it("returns null when ciphertext fails to decrypt", async () => {
    const kv = createMockKV() as MockKV;
    await kv.put("github_token:github:alice", "garbage-not-base64");
    const env = createMockEnv({ MCP_OAUTH_KV: kv, SSO_ENCRYPTION_KEY: SSO_KEY });
    const t = await loadGithubToken(env, "github:alice");
    expect(t).toBeNull();
  });

  it("returns decrypted token on the happy path", async () => {
    const kv = createMockKV() as MockKV;
    const cipher = await encryptWithKey(TOKEN, SSO_KEY);
    await kv.put("github_token:github:alice", cipher);
    const env = createMockEnv({ MCP_OAUTH_KV: kv, SSO_ENCRYPTION_KEY: SSO_KEY });
    const t = await loadGithubToken(env, "github:alice");
    expect(t).toBe(TOKEN);
  });
});

describe("setBranchProtection / getBranchProtection / deleteBranchProtection", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("set sends PUT with the preset payload and parses JSON body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        expect(url).toBe("https://api.github.com/repos/ippoan/r/branches/main/protection");
        expect(init?.method).toBe("PUT");
        const sent = JSON.parse(init!.body as string);
        expect(sent).toEqual(PRESETS["ippoan-rust-default"].payload);
        const headers = init?.headers as Record<string, string>;
        expect(headers["Authorization"]).toBe(`Bearer ${TOKEN}`);
        return new Response(JSON.stringify({ url: "x" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );
    const res = await setBranchProtection(
      TOKEN,
      "ippoan",
      "r",
      "main",
      PRESETS["ippoan-rust-default"].payload,
    );
    expect(res.ok).toBe(true);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ url: "x" });
  });

  it("get returns 404 body as null", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("", { status: 404 })),
    );
    const res = await getBranchProtection(TOKEN, "ippoan", "r", "main");
    expect(res.ok).toBe(false);
    expect(res.status).toBe(404);
    expect(res.body).toBeNull();
  });

  it("get returns raw string when body is non-JSON", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("plain", { status: 200 })),
    );
    const res = await getBranchProtection(TOKEN, "ippoan", "r", "main");
    expect(res.body).toBe("plain");
  });

  it("delete sends DELETE", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (_u: string, init?: RequestInit) => {
        expect(init?.method).toBe("DELETE");
        return new Response(null, { status: 200 });
      }),
    );
    const res = await deleteBranchProtection(TOKEN, "ippoan", "r", "main");
    expect(res.status).toBe(200);
  });

  it("encodes owner/repo/branch path components", async () => {
    const seen: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string) => {
        seen.push(url);
        return new Response("{}", { status: 200 });
      }),
    );
    await getBranchProtection(TOKEN, "ipp oan", "r/x", "ma in");
    expect(seen[0]).toBe(
      "https://api.github.com/repos/ipp%20oan/r%2Fx/branches/ma%20in/protection",
    );
  });
});

describe("listOwnedRepos", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  function mockReposResponse(items: unknown): void {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify(items), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
  }

  it("filters by allowlist, excludes archived/fork, and sorts by owner/name", async () => {
    mockReposResponse([
      { owner: { login: "ippoan" }, name: "b-repo", default_branch: "main" },
      { owner: { login: "stranger" }, name: "a-repo", default_branch: "main" },
      { owner: { login: "ippoan" }, name: "a-repo", default_branch: "main" },
      { owner: { login: "ippoan" }, name: "archived", default_branch: "main", archived: true },
      { owner: { login: "ippoan" }, name: "forked", default_branch: "main", fork: true },
    ]);
    const out = await listOwnedRepos(TOKEN, ["ippoan"]);
    expect(out).toEqual([
      { owner: "ippoan", name: "a-repo", default_branch: "main" },
      { owner: "ippoan", name: "b-repo", default_branch: "main" },
    ]);
  });

  it("skips entries missing owner/name/default_branch", async () => {
    mockReposResponse([
      { owner: { login: "ippoan" }, name: "ok", default_branch: "main" },
      { owner: { login: "ippoan" }, name: "no-branch" },
      { owner: {}, name: "no-owner", default_branch: "main" },
    ]);
    const out = await listOwnedRepos(TOKEN, ["ippoan"]);
    expect(out).toEqual([{ owner: "ippoan", name: "ok", default_branch: "main" }]);
  });

  it("throws when GitHub returns non-2xx", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("nope", { status: 502 })),
    );
    await expect(listOwnedRepos(TOKEN, ["ippoan"])).rejects.toThrow(/502/);
  });
});

describe("fetchProtectionRows", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("marks 404 as unprotected, parses contexts on 200", async () => {
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string) => {
        calls.push(url);
        if (url.includes("/a/")) return new Response("", { status: 404 });
        return new Response(
          JSON.stringify({
            required_status_checks: { contexts: ["ci / x", "ci / y"], strict: true },
            allow_force_pushes: { enabled: false },
            allow_deletions: { enabled: true },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }),
    );
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "a", default_branch: "main" },
      { owner: "ippoan", name: "b", default_branch: "main" },
    ]);
    expect(rows[0]).toMatchObject({
      owner: "ippoan",
      name: "a",
      protected: false,
      protection_status: 404,
    });
    expect(rows[1]).toMatchObject({
      owner: "ippoan",
      name: "b",
      protected: true,
      required_checks: ["ci / x", "ci / y"],
      allow_force_pushes: false,
      allow_deletions: true,
    });
  });

  it("falls back gracefully when the response body is non-object", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("\"weird\"", { status: 200 })),
    );
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "a", default_branch: "main" },
    ]);
    expect(rows[0]?.protected).toBe(false);
  });
});
