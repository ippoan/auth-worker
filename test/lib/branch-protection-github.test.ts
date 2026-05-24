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

describe("getRepoSettings", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("returns null when /repos/:o/:r is non-2xx", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("nope", { status: 404 })),
    );
    const { getRepoSettings } = await import("../../src/lib/branch-protection-github");
    const out = await getRepoSettings(TOKEN, "ippoan", "r");
    expect(out).toBeNull();
  });

  it("coerces missing/falsy flags to false (not undefined)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify({}), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
    const { getRepoSettings } = await import("../../src/lib/branch-protection-github");
    const out = await getRepoSettings(TOKEN, "ippoan", "r");
    expect(out).toEqual({ allow_auto_merge: false, delete_branch_on_merge: false });
  });

  it("returns both flags true on the happy path", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify({ allow_auto_merge: true, delete_branch_on_merge: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
    const { getRepoSettings } = await import("../../src/lib/branch-protection-github");
    const out = await getRepoSettings(TOKEN, "ippoan", "r");
    expect(out).toEqual({ allow_auto_merge: true, delete_branch_on_merge: true });
  });
});

describe("patchRepoSettings", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("sends PATCH with the supplied settings and parses the body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        expect(url).toBe("https://api.github.com/repos/ippoan/r");
        expect(init?.method).toBe("PATCH");
        expect(JSON.parse(init!.body as string)).toEqual({
          allow_auto_merge: true,
          delete_branch_on_merge: true,
        });
        return new Response(
          JSON.stringify({ allow_auto_merge: true, delete_branch_on_merge: true }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }),
    );
    const { patchRepoSettings } = await import("../../src/lib/branch-protection-github");
    const res = await patchRepoSettings(TOKEN, "ippoan", "r", {
      allow_auto_merge: true,
      delete_branch_on_merge: true,
    });
    expect(res.ok).toBe(true);
    expect(res.status).toBe(200);
  });

  it("returns ok:false with status when GitHub rejects (e.g. 403)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("forbidden", { status: 403 })),
    );
    const { patchRepoSettings } = await import("../../src/lib/branch-protection-github");
    const res = await patchRepoSettings(TOKEN, "ippoan", "r", { allow_auto_merge: true });
    expect(res.ok).toBe(false);
    expect(res.status).toBe(403);
  });
});

describe("getBranchRulesetRules", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  /**
   * Stub the two endpoints that getBranchRulesetRules now hits in series.
   * Per-call response defaults: rules endpoint → 200 [], list endpoint → 200 [].
   */
  function stubProbe(opts: {
    rules?: Response;
    rulesets?: Response;
  } = {}): void {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string) => {
        if (url.includes("/rules/branches/")) {
          return opts.rules ?? new Response("[]", {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (url.endsWith("/rulesets")) {
          return opts.rulesets ?? new Response("[]", {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        throw new Error("unexpected url: " + url);
      }),
    );
  }

  it("returns empty struct when both endpoints respond non-2xx", async () => {
    stubProbe({
      rules: new Response("nope", { status: 403 }),
      rulesets: new Response("nope", { status: 403 }),
    });
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
    stubProbe();
    const { getBranchRulesetRules } = await import("../../src/lib/branch-protection-github");
    const out = await getBranchRulesetRules(TOKEN, "ippoan", "r", "main");
    expect(out.active).toBe(false);
  });

  it("surfaces evaluate-mode rulesets via synthetic rule_types[] marker", async () => {
    stubProbe({
      rulesets: new Response(
        JSON.stringify([
          {
            id: 1,
            enforcement: "evaluate",
            conditions: { ref_name: { include: ["~DEFAULT_BRANCH"], exclude: [] } },
          },
        ]),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    });
    const { getBranchRulesetRules } = await import("../../src/lib/branch-protection-github");
    const out = await getBranchRulesetRules(TOKEN, "ippoan", "r", "main");
    expect(out.active).toBe(false);
    expect(out.rule_types).toEqual(["evaluate-mode"]);
  });

  it("does not surface evaluate-mode when conditions target a different branch", async () => {
    stubProbe({
      rulesets: new Response(
        JSON.stringify([
          {
            id: 1,
            enforcement: "evaluate",
            conditions: { ref_name: { include: ["refs/heads/release"], exclude: [] } },
          },
        ]),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    });
    const { getBranchRulesetRules } = await import("../../src/lib/branch-protection-github");
    const out = await getBranchRulesetRules(TOKEN, "ippoan", "r", "main");
    expect(out.active).toBe(false);
    expect(out.rule_types).toEqual([]);
  });

  it("does not surface evaluate-mode when an exclude rule excludes the branch", async () => {
    stubProbe({
      rulesets: new Response(
        JSON.stringify([
          {
            id: 1,
            enforcement: "evaluate",
            conditions: { ref_name: { include: ["~ALL"], exclude: ["refs/heads/main"] } },
          },
        ]),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    });
    const { getBranchRulesetRules } = await import("../../src/lib/branch-protection-github");
    const out = await getBranchRulesetRules(TOKEN, "ippoan", "r", "main");
    expect(out.rule_types).toEqual([]);
  });

  it("active rules win over evaluate-mode fallback (real enforcement detected)", async () => {
    stubProbe({
      rules: new Response(
        JSON.stringify([{ type: "non_fast_forward" }]),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
      rulesets: new Response(
        JSON.stringify([{ id: 9, enforcement: "evaluate", conditions: {} }]),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    });
    const { getBranchRulesetRules } = await import("../../src/lib/branch-protection-github");
    const out = await getBranchRulesetRules(TOKEN, "ippoan", "r", "main");
    expect(out.active).toBe(true);
    expect(out.blocks_force_push).toBe(true);
    expect(out.rule_types).toEqual(["non_fast_forward"]);
  });

  it("aggregates rule types, required_status_checks contexts, and block flags", async () => {
    stubProbe({
      rules: new Response(
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
    });
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
  function stubFetch(perRepo: Record<string, {
    classic?: Response;
    ruleset?: Response;
    rulesetsList?: Response;
    settings?: Response;
    /** Body of `.github/workflows/ci.yml` (base64-encoded automatically). */
    ciYml?: string | null;
    /** Body of `Cargo.toml` (base64-encoded automatically). */
    cargoToml?: string | null;
    /** Body of `go.mod` (base64-encoded automatically). */
    goMod?: string | null;
    /** Body of `app/src/main/AndroidManifest.xml` (base64-encoded automatically). */
    androidManifest?: string | null;
  }>): void {
    const b64 = (s: string) => Buffer.from(s, "utf-8").toString("base64");
    const contentsRespFor = (body: string | null | undefined): Response => {
      if (body == null) return new Response("", { status: 404 });
      return new Response(
        JSON.stringify({ encoding: "base64", content: b64(body) }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    };
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
          if (url.endsWith(`/repos/ippoan/${key}/rulesets`)) {
            return plan.rulesetsList ?? new Response("[]", {
              status: 200,
              headers: { "Content-Type": "application/json" },
            });
          }
          if (url.includes(`/repos/ippoan/${key}/contents/.github/workflows/ci.yml`)) {
            return contentsRespFor(plan.ciYml ?? null);
          }
          if (url.includes(`/repos/ippoan/${key}/contents/Cargo.toml`)) {
            return contentsRespFor(plan.cargoToml ?? null);
          }
          if (url.includes(`/repos/ippoan/${key}/contents/go.mod`)) {
            return contentsRespFor(plan.goMod ?? null);
          }
          if (url.includes(`/repos/ippoan/${key}/contents/app/src/main/AndroidManifest.xml`)) {
            return contentsRespFor(plan.androidManifest ?? null);
          }
          if (url.endsWith(`/repos/ippoan/${key}`)) {
            return plan.settings ?? new Response(
              JSON.stringify({ allow_auto_merge: true, delete_branch_on_merge: true }),
              { status: 200, headers: { "Content-Type": "application/json" } },
            );
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
      repo_settings: { allow_auto_merge: true, delete_branch_on_merge: true },
    });
  });

  it("surfaces repo_settings flags off when GitHub returns them as false", async () => {
    stubFetch({
      a: {
        settings: new Response(
          JSON.stringify({ allow_auto_merge: false, delete_branch_on_merge: false }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      },
    });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "a", default_branch: "main" },
    ]);
    expect(rows[0]?.repo_settings).toEqual({
      allow_auto_merge: false,
      delete_branch_on_merge: false,
    });
  });

  it("sets repo_settings to null when the repo metadata probe fails", async () => {
    stubFetch({
      a: {
        settings: new Response("nope", { status: 404 }),
      },
    });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "a", default_branch: "main" },
    ]);
    expect(rows[0]?.repo_settings).toBeNull();
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

  it("populates project_type=worker when ci.yml references frontend-ci.yml", async () => {
    stubFetch({
      a: {
        ciYml:
          "jobs:\n  ci:\n    uses: ippoan/ci-workflows/.github/workflows/frontend-ci.yml@main\n",
      },
    });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "a", default_branch: "main" },
    ]);
    expect(rows[0]?.project_type).toBe("worker");
  });

  it("populates project_type=rust when ci.yml references rust-ci.yml", async () => {
    stubFetch({
      b: {
        ciYml:
          "jobs:\n  ci:\n    uses: ippoan/ci-workflows/.github/workflows/rust-ci.yml@main\n",
      },
    });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "b", default_branch: "main" },
    ]);
    expect(rows[0]?.project_type).toBe("rust");
  });

  it("falls back to Cargo.toml when ci.yml is missing", async () => {
    stubFetch({
      c: {
        // ciYml unset → 404
        cargoToml: "[package]\nname = \"foo\"\n",
      },
    });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "c", default_branch: "main" },
    ]);
    expect(rows[0]?.project_type).toBe("rust");
  });

  it("populates project_type=go when ci.yml references go-ci.yml", async () => {
    stubFetch({
      f: {
        ciYml:
          "jobs:\n  ci:\n    uses: ippoan/ci-workflows/.github/workflows/go-ci.yml@main\n",
      },
    });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "f", default_branch: "main" },
    ]);
    expect(rows[0]?.project_type).toBe("go");
  });

  it("falls back to go.mod when ci.yml is missing and Cargo.toml is absent", async () => {
    stubFetch({
      g: {
        // ciYml + cargoToml unset → 404
        goMod: "module github.com/ippoan/secrets-inventory-gcp\n\ngo 1.24\n",
      },
    });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "g", default_branch: "main" },
    ]);
    expect(rows[0]?.project_type).toBe("go");
  });

  it("populates project_type=lib when ci.yml references lib-ci.yml", async () => {
    // lib-ci.yml is the new Node.js library reusable. Detection lives in
    // detectProjectType after worker/rust/go so hybrid repos keep their
    // existing classification.
    stubFetch({
      h: {
        ciYml:
          "jobs:\n  ci:\n    uses: ippoan/ci-workflows/.github/workflows/lib-ci.yml@main\n",
      },
    });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "h", default_branch: "main" },
    ]);
    expect(rows[0]?.project_type).toBe("lib");
  });

  it("populates project_type=android when ci.yml references android-ci.yml", async () => {
    // android-ci.yml does not yet exist in ci-workflows but the detector
    // pins the substring so the dashboard can pick the android preset as
    // soon as a consumer migrates. Same pattern as the lib-ci.yml branch.
    stubFetch({
      i: {
        ciYml:
          "jobs:\n  ci:\n    uses: ippoan/ci-workflows/.github/workflows/android-ci.yml@main\n",
      },
    });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "i", default_branch: "main" },
    ]);
    expect(rows[0]?.project_type).toBe("android");
  });

  it("falls back to AndroidManifest.xml when ci.yml/Cargo.toml/go.mod all missing", async () => {
    // HealthConnectReader's bootstrap state: no PR-trigger ci.yml exists
    // yet (only release.yml on push to main), so detection has to lean on
    // the AGP-standard manifest path. The dashboard then offers the
    // android preset with the standard caveat (override required_checks
    // until android-ci.yml ships).
    stubFetch({
      j: {
        androidManifest:
          "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n</manifest>\n",
      },
    });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "j", default_branch: "main" },
    ]);
    expect(rows[0]?.project_type).toBe("android");
  });

  it("returns project_type=unknown when no marker file exists", async () => {
    stubFetch({ d: {} });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "d", default_branch: "main" },
    ]);
    expect(rows[0]?.project_type).toBe("unknown");
  });

  it("returns project_type=unknown when ci.yml uses an unrelated workflow", async () => {
    stubFetch({
      e: {
        ciYml: "jobs:\n  test:\n    runs-on: ubuntu-latest\n",
        // no Cargo.toml / go.mod either
      },
    });
    const rows = await fetchProtectionRows(TOKEN, [
      { owner: "ippoan", name: "e", default_branch: "main" },
    ]);
    expect(rows[0]?.project_type).toBe("unknown");
  });
});
