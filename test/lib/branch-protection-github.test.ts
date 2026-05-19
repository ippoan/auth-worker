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

describe("getBranchRulesetRules", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("returns empty struct when GitHub responds non-2xx", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("nope", { status: 403 })),
    );
    const { getBranchRulesetRules } = await import("../../src/lib/branch-protection-github");
    const out = await getBranchRulesetRules(TOKEN, "ippoan", "r", "main");
    expect(out).toEqual({
      active: false,
      required_checks: [],
      blocks_force_push: false,
      blocks_deletion: false,
      rule_types: [],
    });
  });

  it("returns empty struct on empty array (no ruleset rules apply)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response("[]", { status: 200, headers: { "Content-Type": "application/json" } }),
      ),
    );
    const { getBranchRulesetRules } = await import("../../src/lib/branch-protection-github");
    const out = await getBranchRulesetRules(TOKEN, "ippoan", "r", "main");
    expect(out.active).toBe(false);
  });

  it("aggregates rule types, required_status_checks contexts, and block flags", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(
          JSON.stringify([
            { type: "non_fast_forward" },
            { type: "deletion" },
            {
              type: "required_status_checks",
              parameters: {
                required_status_checks: [
                  { context: "ci / b" },
                  { context: "ci / a" },
                ],
              },
            },
            // Duplicate ruleset entries (different ruleset_id) — should de-dup
            { type: "required_status_checks", parameters: { required_status_checks: [{ context: "ci / a" }] } },
            // Malformed entries should be skipped, not crash
            { /* no type */ },
            { type: "required_status_checks", parameters: { required_status_checks: "not-array" } },
          ]),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const { getBranchRulesetRules } = await import("../../src/lib/branch-protection-github");
    const out = await getBranchRulesetRules(TOKEN, "ippoan", "r", "main");
    expect(out.active).toBe(true);
    expect(out.required_checks).toEqual(["ci / a", "ci / b"]);
    expect(out.blocks_force_push).toBe(true);
    expect(out.blocks_deletion).toBe(true);
    expect(out.rule_types.sort()).toEqual([
      "deletion",
      "non_fast_forward",
      "required_status_checks",
    ]);
  });
});

describe("fetchProtectionRows", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  /**
   * Route the classic `/protection` + ruleset `/rules/branches/` endpoints
   * to per-repo response handlers. Each handler returns
   * `{ classic?: Response, ruleset?: Response }`; missing entries default
   * to 404 (= no classic protection) and `[]` (= no ruleset rules).
   */
  function stubFetch(perRepo: Record<string, { classic?: Response; ruleset?: Response }>): void {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string) => {
        for (const [key, plan] of Object.entries(perRepo)) {
          if (url.includes(`/repos/ippoan/${key}/branches/`)) {
            return plan.classic ?? new Response("", { status: 404 });
          }
          if (url.includes(`/repos/ippoan/${key}/rules/branches/`)) {
            return plan.ruleset ?? new Response("[]", {
              status: 200,
              headers: { "Content-Type": "application/json" },
            });
          }
        }
        throw new Error("unexpected url: " + url);
      }),
    );
  }

  it("marks classic 404 + no rulesets as unprotected (source=none)", async () => {
    stubFetch({ a: {} });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "a", default_branch: "main" },
    ]);
    expect(rows[0]).toMatchObject({
      protected: false,
      protection_source: "none",
      protection_status: 404,
      required_checks: [],
      ruleset_rule_types: [],
    });
  });

  it("merges classic + ruleset on the same repo (source=both, union of checks)", async () => {
    stubFetch({
      b: {
        classic: new Response(
          JSON.stringify({
            required_status_checks: { contexts: ["ci / classic-only", "ci / both"], strict: true },
            allow_force_pushes: { enabled: false },
            allow_deletions: { enabled: true },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
        ruleset: new Response(
          JSON.stringify([
            { type: "non_fast_forward" },
            {
              type: "required_status_checks",
              parameters: {
                required_status_checks: [
                  { context: "ci / ruleset-only" },
                  { context: "ci / both" },
                ],
              },
            },
          ]),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      },
    });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "b", default_branch: "main" },
    ]);
    expect(rows[0]).toMatchObject({
      protected: true,
      protection_source: "both",
      required_checks: ["ci / both", "ci / classic-only", "ci / ruleset-only"],
      // classic says force_push allowed=false, ruleset adds non_fast_forward
      // → effectively blocked.
      allow_force_pushes: false,
      // classic says deletion allowed=true, ruleset does NOT block deletion
      // → still allowed.
      allow_deletions: true,
      ruleset_rule_types: ["non_fast_forward", "required_status_checks"],
    });
  });

  it("ruleset-only protection (classic 404) — source=ruleset, .protected stays true", async () => {
    stubFetch({
      c: {
        ruleset: new Response(
          JSON.stringify([
            { type: "non_fast_forward" },
            { type: "deletion" },
          ]),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      },
    });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "c", default_branch: "main" },
    ]);
    expect(rows[0]).toMatchObject({
      protected: true,
      protection_source: "ruleset",
      allow_force_pushes: false,
      allow_deletions: false,
      required_checks: [],
      ruleset_rule_types: ["deletion", "non_fast_forward"],
    });
  });

  it("classic-only protection (no ruleset rules) — source=classic", async () => {
    stubFetch({
      d: {
        classic: new Response(
          JSON.stringify({
            required_status_checks: { contexts: ["ci / x"], strict: true },
            allow_force_pushes: { enabled: false },
            allow_deletions: { enabled: false },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      },
    });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "d", default_branch: "main" },
    ]);
    expect(rows[0]).toMatchObject({
      protected: true,
      protection_source: "classic",
      required_checks: ["ci / x"],
      allow_force_pushes: false,
      allow_deletions: false,
    });
  });

  it("falls back gracefully when classic body is non-object and no rulesets", async () => {
    stubFetch({
      a: {
        classic: new Response("\"weird\"", { status: 200 }),
      },
    });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "a", default_branch: "main" },
    ]);
    expect(rows[0]?.protected).toBe(false);
    expect(rows[0]?.protection_source).toBe("none");
  });
});
