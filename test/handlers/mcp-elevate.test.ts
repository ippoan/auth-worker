/**
 * `handleMcpElevateStart` / `handleMcpElevateCallback` (Phase 1 admin auth)。
 * GitHub OAuth round-trip は `globalThis.fetch` stub で模擬。KV は MockKV。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  handleMcpElevateStart,
  handleMcpElevateCallback,
} from "../../src/handlers/mcp-elevate";
import { decryptWithKey } from "../../src/lib/mcp-crypto";
import { verifyMcpJwtSignatureOnly } from "../../src/lib/mcp-jwt";
import {
  createMockEnv,
  createMockKV,
  createSpyDONamespace,
  type MockKV,
} from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth.test.example";
const TEST_MCP_JWT_SECRET = "test-mcp-jwt-secret-32chars!";

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    GITHUB_MCP_CLIENT_ID: "Iv1.test",
    GITHUB_MCP_CLIENT_SECRET: "ghs_test",
    GITHUB_MCP_USER_ALLOWLIST: '["alice"]',
    ...overrides,
  });
  return { env, kv };
}

function jsonResp(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("handleMcpElevateStart", () => {
  it("503 when MCP_OAUTH_KV unbound", async () => {
    const env = createMockEnv({
      MCP_OAUTH_KV: undefined,
      AUTH_WORKER_ORIGIN: ISSUER,
      GITHUB_MCP_CLIENT_ID: "Iv1.test",
    });
    const res = await handleMcpElevateStart(
      new Request(`${ISSUER}/mcp/elevate`),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("503 when GITHUB_MCP_CLIENT_ID missing", async () => {
    const { env } = envWithKv({ GITHUB_MCP_CLIENT_ID: undefined });
    const res = await handleMcpElevateStart(
      new Request(`${ISSUER}/mcp/elevate`),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("503 when AUTH_WORKER_ORIGIN missing", async () => {
    const { env } = envWithKv({ AUTH_WORKER_ORIGIN: "" });
    const res = await handleMcpElevateStart(
      new Request(`${ISSUER}/mcp/elevate`),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("400 when return_to is invalid (http://)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpElevateStart(
      new Request(`${ISSUER}/mcp/elevate?return_to=http://insecure.example`),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when return_to is not a URL", async () => {
    const { env } = envWithKv();
    const res = await handleMcpElevateStart(
      new Request(`${ISSUER}/mcp/elevate?return_to=not-a-url`),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("302 to GitHub authorize + KV entry created when return_to absent", async () => {
    const { env, kv } = envWithKv();
    const res = await handleMcpElevateStart(
      new Request(`${ISSUER}/mcp/elevate`),
      env,
    );
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location")!;
    expect(loc).toMatch(/^https:\/\/github\.com\/login\/oauth\/authorize\?/);
    const u = new URL(loc);
    expect(u.searchParams.get("client_id")).toBe("Iv1.test");
    expect(u.searchParams.get("redirect_uri")).toBe(`${ISSUER}/mcp/elevate_callback`);
    expect(u.searchParams.get("scope")).toBe("read:user");
    expect(u.searchParams.get("prompt")).toBe("consent");
    expect(u.searchParams.get("allow_signup")).toBe("false");
    const state = u.searchParams.get("state")!;
    expect(state.length).toBeGreaterThan(20);
    const entry = JSON.parse(kv._data[`elevate_state:${state}`]!);
    expect(entry.return_to).toBe("");
    expect(typeof entry.created_at).toBe("number");
    expect(kv._ttls[`elevate_state:${state}`]).toBe(600);
  });

  it("302 + preserves return_to when valid https URL", async () => {
    const { env, kv } = envWithKv();
    const target = "https://app.example/dashboard";
    const res = await handleMcpElevateStart(
      new Request(`${ISSUER}/mcp/elevate?return_to=${encodeURIComponent(target)}`),
      env,
    );
    expect(res.status).toBe(302);
    const u = new URL(res.headers.get("Location")!);
    const state = u.searchParams.get("state")!;
    const entry = JSON.parse(kv._data[`elevate_state:${state}`]!);
    expect(entry.return_to).toBe(target);
  });
});

describe("handleMcpElevateCallback", () => {
  let originalFetch: typeof globalThis.fetch;
  beforeEach(() => { originalFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = originalFetch; });

  async function seedState(
    env: Env,
    kv: MockKV,
    overrides: Partial<{ return_to: string; created_at: number }> = {},
  ): Promise<string> {
    const state = "STATE-ABC";
    const entry = { return_to: "", created_at: Date.now(), ...overrides };
    await kv.put(`elevate_state:${state}`, JSON.stringify(entry), {
      expirationTtl: 600,
    });
    void env;
    return state;
  }

  it("503 when env unset", async () => {
    const env = createMockEnv({
      MCP_OAUTH_KV: undefined,
      AUTH_WORKER_ORIGIN: ISSUER,
      GITHUB_MCP_CLIENT_ID: "Iv1.test",
      GITHUB_MCP_CLIENT_SECRET: "ghs_test",
    });
    const res = await handleMcpElevateCallback(
      new Request(`${ISSUER}/mcp/elevate_callback?state=x&code=y`),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("503 when GITHUB_MCP_CLIENT_SECRET missing", async () => {
    const { env } = envWithKv({ GITHUB_MCP_CLIENT_SECRET: undefined });
    const res = await handleMcpElevateCallback(
      new Request(`${ISSUER}/mcp/elevate_callback?state=x&code=y`),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("400 when state missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpElevateCallback(
      new Request(`${ISSUER}/mcp/elevate_callback`),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when state not found in KV", async () => {
    const { env } = envWithKv();
    const res = await handleMcpElevateCallback(
      new Request(`${ISSUER}/mcp/elevate_callback?state=missing&code=ghc`),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when stored state JSON is malformed (read-then-delete safety)", async () => {
    const { env, kv } = envWithKv();
    const state = "BAD-STATE";
    await kv.put(`elevate_state:${state}`, "{not-json", { expirationTtl: 600 });
    const res = await handleMcpElevateCallback(
      new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
      env,
    );
    expect(res.status).toBe(400);
    expect(kv._data[`elevate_state:${state}`]).toBeUndefined();
  });

  it("400 with GitHub error param (access_denied)", async () => {
    const { env, kv } = envWithKv();
    const state = await seedState(env, kv);
    const res = await handleMcpElevateCallback(
      new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&error=access_denied`),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when code missing (no error)", async () => {
    const { env, kv } = envWithKv();
    const state = await seedState(env, kv);
    const res = await handleMcpElevateCallback(
      new Request(`${ISSUER}/mcp/elevate_callback?state=${state}`),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when GitHub token exchange returns non-OK", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response("err", { status: 500 })));
    const { env, kv } = envWithKv();
    const state = await seedState(env, kv);
    const res = await handleMcpElevateCallback(
      new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when token response missing access_token", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResp({ error: "bad" })));
    const { env, kv } = envWithKv();
    const state = await seedState(env, kv);
    const res = await handleMcpElevateCallback(
      new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when token exchange throws", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValueOnce(new Error("net")));
    const { env, kv } = envWithKv();
    const state = await seedState(env, kv);
    const res = await handleMcpElevateCallback(
      new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when /user fetch fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockResolvedValueOnce(new Response("err", { status: 500 })),
    );
    const { env, kv } = envWithKv();
    const state = await seedState(env, kv);
    const res = await handleMcpElevateCallback(
      new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when /user response missing login", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockResolvedValueOnce(jsonResp({})),
    );
    const { env, kv } = envWithKv();
    const state = await seedState(env, kv);
    const res = await handleMcpElevateCallback(
      new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when /user fetch throws", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
        .mockRejectedValueOnce(new Error("net")),
    );
    const { env, kv } = envWithKv();
    const state = await seedState(env, kv);
    const res = await handleMcpElevateCallback(
      new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
      env,
    );
    expect(res.status).toBe(400);
  });

  describe("ACL", () => {
    async function expectDeny(allowlist: string | undefined, login: string): Promise<Response> {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
          .mockResolvedValueOnce(jsonResp({ login })),
      );
      const { env, kv } = envWithKv({ GITHUB_MCP_USER_ALLOWLIST: allowlist });
      const state = "S-" + Math.random().toString(36).slice(2);
      await kv.put(`elevate_state:${state}`, JSON.stringify({ return_to: "", created_at: 0 }), { expirationTtl: 600 });
      return await handleMcpElevateCallback(
        new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
        env,
      );
    }

    it("403 admin_allowlist_unset when GITHUB_MCP_USER_ALLOWLIST missing", async () => {
      const res = await expectDeny(undefined, "alice");
      expect(res.status).toBe(403);
      expect(await res.text()).toContain("admin_allowlist_unset");
    });

    it("403 admin_allowlist_unset when allowlist is malformed JSON", async () => {
      const res = await expectDeny("{not-json", "alice");
      expect(res.status).toBe(403);
      expect(await res.text()).toContain("admin_allowlist_unset");
    });

    it("403 admin_allowlist_unset when allowlist is not an array", async () => {
      const res = await expectDeny('{"alice":true}', "alice");
      expect(res.status).toBe(403);
    });

    it("403 admin_allowlist_unset when allowlist array contains non-string", async () => {
      const res = await expectDeny('["alice", 42]', "alice");
      expect(res.status).toBe(403);
    });

    it("403 not_in_allowlist when login is not in array", async () => {
      const res = await expectDeny('["alice"]', "intruder");
      expect(res.status).toBe(403);
      expect(await res.text()).toContain("not_in_allowlist");
    });
  });

  describe("success", () => {
    it("sets KV elevate flag and redirects to return_to when present", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
          .mockResolvedValueOnce(jsonResp({ login: "alice" })),
      );
      const { env, kv } = envWithKv();
      const state = await seedState(env, kv, { return_to: "https://app.example/back" });
      const res = await handleMcpElevateCallback(
        new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
        env,
      );
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("https://app.example/back");
      const flag = JSON.parse(kv._data["elevate:alice"]!);
      expect(flag.elevated_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
      expect(flag.expires_at - flag.elevated_at).toBe(900);
      expect(kv._ttls["elevate:alice"]).toBe(900);
      // state must be consumed (one-shot)
      expect(kv._data[`elevate_state:${state}`]).toBeUndefined();
    });

    it("returns success HTML when return_to absent", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
          .mockResolvedValueOnce(jsonResp({ login: "alice" })),
      );
      const { env, kv } = envWithKv();
      const state = await seedState(env, kv);
      const res = await handleMcpElevateCallback(
        new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
        env,
      );
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toContain("text/html");
      const body = await res.text();
      expect(body).toContain("Admin elevation granted");
    });

    it("stashes a fresh JWT pickup in KV when MCP_JWT_SECRET configured", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
          .mockResolvedValueOnce(jsonResp({ login: "alice" })),
      );
      const { env, kv } = envWithKv({
        MCP_JWT_SECRET: TEST_MCP_JWT_SECRET,
      });
      const state = await seedState(env, kv);
      const res = await handleMcpElevateCallback(
        new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
        env,
      );
      expect(res.status).toBe(200);
      // Pickup KV entry is present and encrypted (not raw JSON)
      const ciphertext = kv._data["mcp_jwt_pickup:github:alice"];
      expect(ciphertext).toBeDefined();
      expect(ciphertext).not.toContain("access_token"); // encrypted, not plaintext
      // Decrypt and verify shape
      const plaintext = await decryptWithKey(ciphertext!, "test-sso-encryption-key");
      const blob = JSON.parse(plaintext) as {
        access_token: string;
        refresh_token: string;
        scope: string;
        expires_in: number;
      };
      expect(blob.scope).toBe("mcp.read mcp.write");
      expect(blob.expires_in).toBe(3600);
      expect(blob.access_token).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/); // JWT shape
      expect(blob.refresh_token.length).toBeGreaterThan(40);
      // The minted access_token has the correct sub / aud
      const payload = await verifyMcpJwtSignatureOnly(
        blob.access_token,
        TEST_MCP_JWT_SECRET,
      );
      expect(payload).not.toBeNull();
      expect(payload!.sub).toBe("github:alice");
      expect(payload!.aud).toBe("github-mcp-server-rs");
      expect(payload!.github_login).toBe("alice");
      // TTL set
      expect(kv._ttls["mcp_jwt_pickup:github:alice"]).toBe(3600);
    });

    it("sets the mcp_pair_session cookie when SESSION_COOKIE_SECRET is configured (issue #159)", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
          .mockResolvedValueOnce(jsonResp({ login: "alice" })),
      );
      const { env, kv } = envWithKv({
        SESSION_COOKIE_SECRET: "test-session-cookie-secret-32!!!",
      });
      const state = await seedState(env, kv, { return_to: "https://app.example/back" });
      const res = await handleMcpElevateCallback(
        new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
        env,
      );
      expect(res.status).toBe(302);
      const setCookie = res.headers.get("Set-Cookie");
      expect(setCookie).not.toBeNull();
      expect(setCookie!).toMatch(/^mcp_pair_session=/);
      expect(setCookie!).toContain("HttpOnly");
      expect(setCookie!).toContain("Secure");
    });

    it("omits Set-Cookie when SESSION_COOKIE_SECRET is unset (issue #159, best-effort)", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
          .mockResolvedValueOnce(jsonResp({ login: "alice" })),
      );
      // envWithKv default leaves SESSION_COOKIE_SECRET unset.
      const { env, kv } = envWithKv();
      const state = await seedState(env, kv);
      const res = await handleMcpElevateCallback(
        new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
        env,
      );
      expect(res.status).toBe(200);
      expect(res.headers.get("Set-Cookie")).toBeNull();
    });

    it("does not block the elevate flow when MCP_JWT_SECRET missing (best-effort)", async () => {
      // The existing success tests already exercise this path (no MCP_JWT_SECRET
      // in default envWithKv). Pickup mint silently skips and elevation still
      // returns 200/302 with the elevate flag set.
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
          .mockResolvedValueOnce(jsonResp({ login: "alice" })),
      );
      const { env, kv } = envWithKv({ MCP_JWT_SECRET: undefined });
      const state = await seedState(env, kv);
      const res = await handleMcpElevateCallback(
        new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
        env,
      );
      // Elevate succeeded
      expect(res.status).toBe(200);
      // Elevate flag is set
      expect(kv._data["elevate:alice"]).toBeDefined();
      // No pickup entry (mint silently skipped)
      expect(kv._data["mcp_jwt_pickup:github:alice"]).toBeUndefined();
    });
  });

  // ────────────────────────────────────────────────────────────────────────
  // issue #155 (follow-up comment): tools/list_changed broadcast on elevate
  // ────────────────────────────────────────────────────────────────────────
  describe("tools/list_changed broadcast (issue #155)", () => {
    it("forwards /__notify_tools_list_changed to the DO when MCP_SESSION_DO is bound", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
          .mockResolvedValueOnce(jsonResp({ login: "alice" })),
      );
      const { ns, calls } = createSpyDONamespace(
        async () => new Response(JSON.stringify({ sse_total: 0 }), { status: 200 }),
      );
      const { env, kv } = envWithKv({ MCP_SESSION_DO: ns });
      const state = await seedState(env, kv);
      const res = await handleMcpElevateCallback(
        new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
        env,
      );
      expect(res.status).toBe(200);
      expect(calls).toHaveLength(1);
      expect(calls[0]!.method).toBe("POST");
      expect(new URL(calls[0]!.url).pathname).toBe(
        "/__notify_tools_list_changed",
      );
    });

    it("does not block the elevate flow when DO fetch rejects (best-effort)", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce(jsonResp({ access_token: "ghpat" }))
          .mockResolvedValueOnce(jsonResp({ login: "alice" })),
      );
      const { ns } = createSpyDONamespace(async () => {
        throw new Error("simulated DO unreachable");
      });
      const { env, kv } = envWithKv({ MCP_SESSION_DO: ns });
      const state = await seedState(env, kv);
      const res = await handleMcpElevateCallback(
        new Request(`${ISSUER}/mcp/elevate_callback?state=${state}&code=ghc`),
        env,
      );
      // Elevate succeeded (flag set) despite broadcast failure
      expect(res.status).toBe(200);
      expect(kv._data["elevate:alice"]).toBeDefined();
    });
  });
});
