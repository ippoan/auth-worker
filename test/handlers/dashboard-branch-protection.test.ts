/**
 * `handleDashboardBranchProtection` — GET /dashboard/branch-protection
 * (issue #159 Phase 1). Auth gates:
 *   1. `mcp_pair_session` cookie
 *   2. `elevate:<login>` KV flag (15min admin window)
 */

import { describe, it, expect } from "vitest";
import {
  authenticateDashboard,
  handleDashboardBranchProtection,
  verifyCsrfHeader,
} from "../../src/handlers/dashboard-branch-protection";
import { signPairSession } from "../../src/lib/mcp-session";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ISSUER = "https://auth.test.example";
const SESSION_SECRET = "test-session-cookie-secret-32!!!";

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    SESSION_COOKIE_SECRET: SESSION_SECRET,
    ...overrides,
  });
  return { env, kv };
}

async function seedElevate(kv: MockKV, login: string, opts: { expired?: boolean } = {}): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const expires = opts.expired ? now - 10 : now + 900;
  await kv.put(
    `elevate:${login}`,
    JSON.stringify({ elevated_at: now, expires_at: expires }),
    { expirationTtl: 900 },
  );
}

async function makeAuthedRequest(login: string, path = "/dashboard/branch-protection"): Promise<Request> {
  const cookie = await signPairSession(login, SESSION_SECRET);
  return new Request(`${ISSUER}${path}`, {
    headers: { Cookie: `mcp_pair_session=${cookie}` },
  });
}

describe("handleDashboardBranchProtection — auth gates", () => {
  it("503 when SESSION_COOKIE_SECRET is missing", async () => {
    const { env } = envWithKv({ SESSION_COOKIE_SECRET: undefined });
    const res = await handleDashboardBranchProtection(
      new Request(`${ISSUER}/dashboard/branch-protection`),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("302 to /mcp/elevate when no session cookie", async () => {
    const { env } = envWithKv();
    const res = await handleDashboardBranchProtection(
      new Request(`${ISSUER}/dashboard/branch-protection`),
      env,
    );
    expect(res.status).toBe(302);
    const loc = res.headers.get("Location")!;
    expect(loc).toContain(`${ISSUER}/mcp/elevate?return_to=`);
    expect(loc).toContain(encodeURIComponent(`${ISSUER}/dashboard/branch-protection`));
  });

  it("302 when session cookie is malformed", async () => {
    const { env } = envWithKv();
    const res = await handleDashboardBranchProtection(
      new Request(`${ISSUER}/dashboard/branch-protection`, {
        headers: { Cookie: "mcp_pair_session=garbage" },
      }),
      env,
    );
    expect(res.status).toBe(302);
  });

  it("302 when cookie valid but elevate flag missing", async () => {
    const { env } = envWithKv();
    const req = await makeAuthedRequest("alice");
    const res = await handleDashboardBranchProtection(req, env);
    expect(res.status).toBe(302);
  });

  it("302 when elevate flag is expired", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice", { expired: true });
    const req = await makeAuthedRequest("alice");
    const res = await handleDashboardBranchProtection(req, env);
    expect(res.status).toBe(302);
  });

  it("302 when elevate flag JSON is malformed", async () => {
    const { env, kv } = envWithKv();
    await kv.put("elevate:alice", "{not-json", { expirationTtl: 900 });
    const req = await makeAuthedRequest("alice");
    const res = await handleDashboardBranchProtection(req, env);
    expect(res.status).toBe(302);
  });

  it("200 HTML when cookie + elevate flag both valid", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    const req = await makeAuthedRequest("alice");
    const res = await handleDashboardBranchProtection(req, env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("text/html");
    const body = await res.text();
    expect(body).toContain("Branch protection dashboard");
    expect(body).toContain("alice");
    // preset metadata is embedded as JSON for the inline script to read
    expect(body).toContain("ippoan-rust-default");
  });
});

describe("authenticateDashboard — direct helper", () => {
  it("returns missing_session when no cookie", async () => {
    const { env } = envWithKv();
    const out = await authenticateDashboard(new Request(`${ISSUER}/x`), env);
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.reason).toBe("missing_session");
  });

  it("returns expired_session when cookie cannot be verified", async () => {
    const { env } = envWithKv();
    const out = await authenticateDashboard(
      new Request(`${ISSUER}/x`, { headers: { Cookie: "mcp_pair_session=bogus" } }),
      env,
    );
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.reason).toBe("expired_session");
  });

  it("returns not_elevated when cookie valid but elevate flag absent", async () => {
    const { env } = envWithKv();
    const out = await authenticateDashboard(await makeAuthedRequest("alice"), env);
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.reason).toBe("not_elevated");
  });

  it("returns ok with login on the happy path", async () => {
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    const out = await authenticateDashboard(await makeAuthedRequest("alice"), env);
    expect(out.ok).toBe(true);
    if (out.ok) expect(out.login).toBe("alice");
  });
});

describe("verifyCsrfHeader", () => {
  it("returns false when header missing", async () => {
    const req = new Request(`${ISSUER}/x`);
    expect(await verifyCsrfHeader(req, "alice", SESSION_SECRET)).toBe(false);
  });

  it("returns false when header value does not match HMAC", async () => {
    const req = new Request(`${ISSUER}/x`, { headers: { "X-CSRF": "wrong-token" } });
    expect(await verifyCsrfHeader(req, "alice", SESSION_SECRET)).toBe(false);
  });

  it("returns true when header matches the HMAC for the login", async () => {
    // Mint the same token the page renders by hitting the page once and
    // pulling it out of the inline script.
    const { env, kv } = envWithKv();
    await seedElevate(kv, "alice");
    const pageRes = await handleDashboardBranchProtection(
      await makeAuthedRequest("alice"),
      env,
    );
    const html = await pageRes.text();
    // The token is JSON-encoded inside the inline script as `var CSRF = "..."`.
    const match = html.match(/var CSRF = "([^"]+)"/);
    expect(match).not.toBeNull();
    const token = match![1] as string;
    const req = new Request(`${ISSUER}/x`, { headers: { "X-CSRF": token } });
    expect(await verifyCsrfHeader(req, "alice", SESSION_SECRET)).toBe(true);
  });
});
