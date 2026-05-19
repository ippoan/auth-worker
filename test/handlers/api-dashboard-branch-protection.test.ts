/**
 * `/api/dashboard/repos*` handlers — tests (issue #159 Phase 1).
 *
 * Two-factor auth (`mcp_pair_session` cookie + `elevate:<login>` KV flag) is
 * shared with the page handler. CSRF header is required on POST/DELETE.
 * GitHub REST is `vi.stubGlobal("fetch", ...)`.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  _clearReposCache,
  handleApiDashboardApplyProtection,
  handleApiDashboardListRepos,
  handleApiDashboardRemoveProtection,
  handleApiDashboardFixRepoSettings,
} from "../../src/handlers/api-dashboard-branch-protection";
import { encryptWithKey } from "../../src/lib/mcp-crypto";
import { signPairSession } from "../../src/lib/mcp-session";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth.test.example";
const SESSION_SECRET = "test-session-cookie-secret-32!!!";
const SSO_KEY = "test-sso-encryption-key";
const TOKEN = "gho_user_abc";

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    SESSION_COOKIE_SECRET: SESSION_SECRET,
    SSO_ENCRYPTION_KEY: SSO_KEY,
    ...overrides,
  });
  return { env, kv };
}

async function seedElevate(kv: MockKV, login: string): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await kv.put(
    `elevate:${login}`,
    JSON.stringify({ elevated_at: now, expires_at: now + 900 }),
    { expirationTtl: 900 },
  );
}

async function seedToken(kv: MockKV, login: string, token = TOKEN): Promise<void> {
  const cipher = await encryptWithKey(token, SSO_KEY);
  await kv.put(`github_token:github:${login}`, cipher);
}

async function csrfFor(login: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`csrf|${login}`));
  const bytes = new Uint8Array(sig);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] as number);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function authedRequest(opts: {
  login: string;
  path: string;
  method?: string;
  body?: unknown;
  csrf?: boolean;
}): Promise<Request> {
  const cookie = await signPairSession(opts.login, SESSION_SECRET);
  const headers: Record<string, string> = { Cookie: `mcp_pair_session=${cookie}` };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (opts.csrf) headers["X-CSRF"] = await csrfFor(opts.login);
  return new Request(`${ISSUER}${opts.path}`, {
    method: opts.method ?? "GET",
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
}

describe("GET /api/dashboard/repos — auth gates", () => {
  beforeEach(() => { _clearReposCache(); });

  it("401 missing_session when no cookie", async () => {
    const { env } = envWithKv();
    const req = new Request(`${ISSUER}/api/dashboard/repos`);
    const res = await handleApiDashboardListRepos(req, env);
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false, error: "missing_session" });
  });

  it("403 not_elevated when cookie valid but elevate flag missing", async () => {
    const { env } = envWithKv();
    const req = await authedRequest({ login: "alice", path: "/api/dashboard/repos" });
    const res = await handleApiDashboardListRepos(req, env);
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ ok: false, error: "not_elevated" });
  });

  it("502 github_token_unavailable when KV has no encrypted token", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    const req = await authedRequest({ login: "alice", path: "/api/dashboard/repos" });
    const res = await handleApiDashboardListRepos(req, env);
    expect(res.status).toBe(502);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("github_token_unavailable");
  });
});

describe("GET /api/dashboard/repos — happy path + cache", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => {
    _clearReposCache();
    originalFetch = globalThis.fetch;
  });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("200 with rendered rows, calls GitHub /user/repos + per-repo /protection", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    await seedToken(kv, "alice");

    const fetchSpy = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes("/user/repos")) {
        return new Response(
          JSON.stringify([
            { owner: { login: "ippoan" }, name: "r1", default_branch: "main" },
            { owner: { login: "stranger" }, name: "r2", default_branch: "main" },
          ]),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (url.includes("/repos/ippoan/r1/branches/main/protection")) {
        return new Response("", { status: 404 });
      }
      if (url.includes("/repos/ippoan/r1/rules/branches/main")) {
        // No ruleset rules in this fixture → unprotected (source=none).
        return new Response("[]", {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (url.endsWith("/repos/ippoan/r1/rulesets")) {
        // No repo-level rulesets either → no evaluate-mode fallback.
        return new Response("[]", {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (url.endsWith("/repos/ippoan/r1")) {
        return new Response(
          JSON.stringify({ allow_auto_merge: true, delete_branch_on_merge: true }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      throw new Error("unexpected url: " + url);
    });
    vi.stubGlobal("fetch", fetchSpy);

    const req = await authedRequest({ login: "alice", path: "/api/dashboard/repos" });
    const res = await handleApiDashboardListRepos(req, env);
    expect(res.status).toBe(200);
    const body = await res.json() as { repos: Array<{ owner: string; name: string; protected: boolean }> };
    expect(body.repos).toHaveLength(1);
    expect(body.repos[0]).toMatchObject({
      owner: "ippoan",
      name: "r1",
      protected: false,
      protection_status: 404,
    });
  });

  it("Phase 2: ruleset-only repo shows protected via ruleset (issue #159 follow-up)", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    await seedToken(kv, "alice");

    const fetchSpy = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes("/user/repos")) {
        return new Response(
          JSON.stringify([
            { owner: { login: "ippoan" }, name: "rs", default_branch: "main" },
          ]),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (url.includes("/repos/ippoan/rs/branches/main/protection")) {
        // No classic protection — would have shown ❌ in Phase 1.
        return new Response("", { status: 404 });
      }
      if (url.includes("/repos/ippoan/rs/rules/branches/main")) {
        return new Response(
          JSON.stringify([
            { type: "non_fast_forward" },
            { type: "deletion" },
          ]),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (url.endsWith("/repos/ippoan/rs/rulesets")) {
        return new Response("[]", {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (url.endsWith("/repos/ippoan/rs")) {
        return new Response(
          JSON.stringify({ allow_auto_merge: true, delete_branch_on_merge: true }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      throw new Error("unexpected url: " + url);
    });
    vi.stubGlobal("fetch", fetchSpy);

    const req = await authedRequest({ login: "alice", path: "/api/dashboard/repos" });
    const res = await handleApiDashboardListRepos(req, env);
    expect(res.status).toBe(200);
    const body = await res.json() as {
      repos: Array<{
        protected: boolean;
        protection_source: string;
        allow_force_pushes: boolean;
        allow_deletions: boolean;
      }>;
    };
    expect(body.repos[0]).toMatchObject({
      protected: true,
      protection_source: "ruleset",
      allow_force_pushes: false,
      allow_deletions: false,
    });
  });

  it("re-uses the cache within 30s (only one /user/repos call)", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    await seedToken(kv, "alice");

    const fetchSpy = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes("/user/repos")) {
        return new Response("[]", { status: 200, headers: { "Content-Type": "application/json" } });
      }
      throw new Error("unexpected url: " + url);
    });
    vi.stubGlobal("fetch", fetchSpy);

    await handleApiDashboardListRepos(
      await authedRequest({ login: "alice", path: "/api/dashboard/repos" }),
      env,
    );
    await handleApiDashboardListRepos(
      await authedRequest({ login: "alice", path: "/api/dashboard/repos" }),
      env,
    );
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("502 github_user_repos_failed when GitHub returns non-2xx", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    await seedToken(kv, "alice");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(new Response("forbidden", { status: 403 })),
    );
    const req = await authedRequest({ login: "alice", path: "/api/dashboard/repos" });
    const res = await handleApiDashboardListRepos(req, env);
    expect(res.status).toBe(502);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("github_user_repos_failed");
  });
});

describe("POST /api/dashboard/repos/:o/:r/protection", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => {
    _clearReposCache();
    originalFetch = globalThis.fetch;
  });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("400 forbidden_owner when owner not in allowlist (auth not even checked)", async () => {
    const { env } = envWithKv();
    const req = new Request(
      `${ISSUER}/api/dashboard/repos/stranger/x/protection`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" },
    );
    const res = await handleApiDashboardApplyProtection(req, env, "stranger", "x");
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ ok: false, error: "forbidden_owner" });
  });

  it("403 csrf_mismatch when X-CSRF missing", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    await seedToken(kv, "alice");
    const req = await authedRequest({
      login: "alice",
      path: "/api/dashboard/repos/ippoan/r1/protection",
      method: "POST",
      body: { preset: "ippoan-rust-default" },
    });
    const res = await handleApiDashboardApplyProtection(req, env, "ippoan", "r1");
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ ok: false, error: "csrf_mismatch" });
  });

  it("400 invalid_request when body is malformed JSON", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    await seedToken(kv, "alice");
    const cookie = await signPairSession("alice", SESSION_SECRET);
    const req = new Request(
      `${ISSUER}/api/dashboard/repos/ippoan/r1/protection`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: `mcp_pair_session=${cookie}`,
          "X-CSRF": await csrfFor("alice"),
        },
        body: "{not-json",
      },
    );
    const res = await handleApiDashboardApplyProtection(req, env, "ippoan", "r1");
    expect(res.status).toBe(400);
  });

  it("400 invalid_request when preset is unknown", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    await seedToken(kv, "alice");
    const req = await authedRequest({
      login: "alice",
      path: "/api/dashboard/repos/ippoan/r1/protection",
      method: "POST",
      csrf: true,
      body: { preset: "evil-preset" },
    });
    const res = await handleApiDashboardApplyProtection(req, env, "ippoan", "r1");
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      ok: false,
      error: "invalid_request",
      details: "missing_or_unknown_preset",
    });
  });

  it("200 ok: looks up default branch then PUTs the preset payload", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    await seedToken(kv, "alice");

    const calls: Array<{ url: string; method: string; body?: unknown }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        calls.push({
          url,
          method: init?.method ?? "GET",
          body: init?.body ? JSON.parse(init.body as string) : undefined,
        });
        if (url === "https://api.github.com/repos/ippoan/r1") {
          return new Response(JSON.stringify({ default_branch: "main" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (url.includes("/protection")) {
          return new Response(JSON.stringify({ url: "applied" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        throw new Error("unexpected: " + url);
      }),
    );

    const req = await authedRequest({
      login: "alice",
      path: "/api/dashboard/repos/ippoan/r1/protection",
      method: "POST",
      csrf: true,
      body: { preset: "ippoan-rust-default" },
    });
    const res = await handleApiDashboardApplyProtection(req, env, "ippoan", "r1");
    expect(res.status).toBe(200);
    const body = await res.json() as { ok: boolean; branch: string };
    expect(body.ok).toBe(true);
    expect(body.branch).toBe("main");

    expect(calls[0]?.url).toBe("https://api.github.com/repos/ippoan/r1");
    expect(calls[1]?.method).toBe("PUT");
    expect(calls[1]?.body).toMatchObject({
      required_status_checks: {
        contexts: ["ci / rustfmt", "ci / clippy", "ci / cargo test", "ci / cargo build --release"],
      },
      enforce_admins: true,
      allow_force_pushes: false,
      allow_deletions: false,
    });
  });

  it("502 github_api_error when PUT fails", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    await seedToken(kv, "alice");

    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string) => {
        if (url === "https://api.github.com/repos/ippoan/r1") {
          return new Response(JSON.stringify({ default_branch: "main" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response(JSON.stringify({ message: "validation failed" }), {
          status: 422,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );

    const req = await authedRequest({
      login: "alice",
      path: "/api/dashboard/repos/ippoan/r1/protection",
      method: "POST",
      csrf: true,
      body: { preset: "ippoan-rust-default" },
    });
    const res = await handleApiDashboardApplyProtection(req, env, "ippoan", "r1");
    expect(res.status).toBe(502);
    const body = await res.json() as { error: string; status: number };
    expect(body.error).toBe("github_api_error");
    expect(body.status).toBe(422);
  });
});

describe("DELETE /api/dashboard/repos/:o/:r/protection", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => {
    _clearReposCache();
    originalFetch = globalThis.fetch;
  });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("400 forbidden_owner for non-allowlisted owner", async () => {
    const { env } = envWithKv();
    const req = new Request(
      `${ISSUER}/api/dashboard/repos/stranger/x/protection`,
      { method: "DELETE" },
    );
    const res = await handleApiDashboardRemoveProtection(req, env, "stranger", "x");
    expect(res.status).toBe(400);
  });

  it("403 csrf_mismatch when X-CSRF missing", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    await seedToken(kv, "alice");
    const req = await authedRequest({
      login: "alice",
      path: "/api/dashboard/repos/ippoan/r1/protection",
      method: "DELETE",
    });
    const res = await handleApiDashboardRemoveProtection(req, env, "ippoan", "r1");
    expect(res.status).toBe(403);
  });

  it("200 ok: looks up default branch then sends DELETE", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    await seedToken(kv, "alice");

    const calls: Array<{ url: string; method: string }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        calls.push({ url, method: init?.method ?? "GET" });
        if (url === "https://api.github.com/repos/ippoan/r1") {
          return new Response(JSON.stringify({ default_branch: "main" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response(null, { status: 200 });
      }),
    );

    const req = await authedRequest({
      login: "alice",
      path: "/api/dashboard/repos/ippoan/r1/protection",
      method: "DELETE",
      csrf: true,
    });
    const res = await handleApiDashboardRemoveProtection(req, env, "ippoan", "r1");
    expect(res.status).toBe(200);
    expect((await res.json() as { ok: boolean }).ok).toBe(true);
    expect(calls[1]?.method).toBe("DELETE");
    expect(calls[1]?.url).toContain("/repos/ippoan/r1/branches/main/protection");
  });

  it("502 github_api_error when DELETE fails", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    await seedToken(kv, "alice");

    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string) => {
        if (url === "https://api.github.com/repos/ippoan/r1") {
          return new Response(JSON.stringify({ default_branch: "main" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response(JSON.stringify({ message: "nope" }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );

    const req = await authedRequest({
      login: "alice",
      path: "/api/dashboard/repos/ippoan/r1/protection",
      method: "DELETE",
      csrf: true,
    });
    const res = await handleApiDashboardRemoveProtection(req, env, "ippoan", "r1");
    expect(res.status).toBe(502);
  });
});

describe("POST /api/dashboard/repos/:o/:r/fix-settings", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => {
    _clearReposCache();
    originalFetch = globalThis.fetch;
  });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("400 forbidden_owner for non-allowlisted owner", async () => {
    const { env } = envWithKv();
    const req = new Request(
      `${ISSUER}/api/dashboard/repos/stranger/x/fix-settings`,
      { method: "POST" },
    );
    const res = await handleApiDashboardFixRepoSettings(req, env, "stranger", "x");
    expect(res.status).toBe(400);
  });

  it("403 csrf_mismatch when X-CSRF missing", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    await seedToken(kv, "alice");
    const req = await authedRequest({
      login: "alice",
      path: "/api/dashboard/repos/ippoan/r1/fix-settings",
      method: "POST",
    });
    const res = await handleApiDashboardFixRepoSettings(req, env, "ippoan", "r1");
    expect(res.status).toBe(403);
  });

  it("200 ok: sends PATCH /repos/:o/:r with both flags true", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    await seedToken(kv, "alice");

    const seen: Array<{ url: string; method: string; body?: unknown }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
        seen.push({
          url,
          method: init?.method ?? "GET",
          body: init?.body ? JSON.parse(init.body as string) : undefined,
        });
        return new Response(
          JSON.stringify({ allow_auto_merge: true, delete_branch_on_merge: true }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }),
    );

    const req = await authedRequest({
      login: "alice",
      path: "/api/dashboard/repos/ippoan/r1/fix-settings",
      method: "POST",
      csrf: true,
    });
    const res = await handleApiDashboardFixRepoSettings(req, env, "ippoan", "r1");
    expect(res.status).toBe(200);
    const body = await res.json() as { ok: boolean };
    expect(body.ok).toBe(true);
    expect(seen[0]?.method).toBe("PATCH");
    expect(seen[0]?.url).toBe("https://api.github.com/repos/ippoan/r1");
    expect(seen[0]?.body).toEqual({
      allow_auto_merge: true,
      delete_branch_on_merge: true,
    });
  });

  it("502 github_api_error when PATCH fails", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    await seedToken(kv, "alice");

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(
        new Response(JSON.stringify({ message: "Resource not accessible" }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    const req = await authedRequest({
      login: "alice",
      path: "/api/dashboard/repos/ippoan/r1/fix-settings",
      method: "POST",
      csrf: true,
    });
    const res = await handleApiDashboardFixRepoSettings(req, env, "ippoan", "r1");
    expect(res.status).toBe(502);
    const body = await res.json() as { error: string; status: number };
    expect(body.error).toBe("github_api_error");
    expect(body.status).toBe(403);
  });
});
