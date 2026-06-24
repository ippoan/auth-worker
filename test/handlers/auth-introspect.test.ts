import { describe, it, expect } from "vitest";
import { handleAuthIntrospect } from "../../src/handlers/auth-introspect";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";
import type { Env } from "../../src/index";

const ORIGIN = "https://auth.test.example";
const TEST_INTERNAL_SECRET = "test-internal-shared-secret-32chr";
const APP_ORIGIN = "https://ichibanboshi.ippoan.org";
const PROD_TENANT = "11111111-1111-1111-1111-111111111111";
const OTHER_TENANT = "22222222-2222-2222-2222-222222222222";

function makeEnv(overrides: Partial<Env> = {}): Env {
  return createMockEnv({
    INTERNAL_SHARED_SECRET: TEST_INTERNAL_SECRET,
    ...overrides,
  });
}

function req(opts: { auth?: string | null; body?: BodyInit | null; contentType?: string }): Request {
  const headers: Record<string, string> = {};
  if (opts.auth !== null && opts.auth !== undefined) headers.Authorization = opts.auth;
  if (opts.contentType !== undefined) headers["Content-Type"] = opts.contentType;
  else headers["Content-Type"] = "application/json";
  return new Request(`${ORIGIN}/auth/introspect`, {
    method: "POST",
    headers,
    body: opts.body ?? null,
  });
}

/** HS256 JWT signed with the same JWT_SECRET createMockEnv uses. */
async function jwt(payload: Record<string, unknown>): Promise<string> {
  return signTestJwt({ env: "prod", ...payload }, TEST_JWT_SECRET);
}

describe("POST /auth/introspect — env guards", () => {
  it("returns 503 active:false when JWT_SECRET missing", async () => {
    const env = makeEnv({ JWT_SECRET: undefined });
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: "x", origin: APP_ORIGIN }) }),
      env,
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as { active: boolean; error?: string };
    expect(body.active).toBe(false);
    expect(body.error).toBe("server_error");
  });

  it("returns 503 when no INTERNAL_SHARED_SECRET* binding present", async () => {
    const env = makeEnv({ INTERNAL_SHARED_SECRET: undefined });
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: "x", origin: APP_ORIGIN }) }),
      env,
    );
    expect(res.status).toBe(503);
  });
});

describe("POST /auth/introspect — authentication", () => {
  it("401 when Authorization header missing", async () => {
    const res = await handleAuthIntrospect(
      req({ auth: null, body: JSON.stringify({ token: "x", origin: APP_ORIGIN }) }),
      makeEnv(),
    );
    expect(res.status).toBe(401);
  });

  it("401 when shared secret does not match", async () => {
    const res = await handleAuthIntrospect(
      req({ auth: "wrong-secret", body: JSON.stringify({ token: "x", origin: APP_ORIGIN }) }),
      makeEnv(),
    );
    expect(res.status).toBe(401);
  });

  it("accepts a per-consumer INTERNAL_SHARED_SECRET_* binding (#189)", async () => {
    const env = makeEnv({
      INTERNAL_SHARED_SECRET: undefined,
      INTERNAL_SHARED_SECRET_SEIKYU: "per-consumer-secret-value-32chrs!",
    } as Partial<Env>);
    const token = await jwt({ tenant_id: PROD_TENANT, email: "a@b.com", role: "admin" });
    const res = await handleAuthIntrospect(
      req({
        auth: "per-consumer-secret-value-32chrs!",
        body: JSON.stringify({ token, origin: APP_ORIGIN }),
      }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { active: boolean };
    expect(body.active).toBe(true);
  });
});

describe("POST /auth/introspect — token validation", () => {
  it("active:true for a valid JWT on an unrestricted origin", async () => {
    const token = await jwt({ tenant_id: PROD_TENANT, email: "a@b.com", role: "viewer", exp: Math.floor(Date.now() / 1000) + 3600 });
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token, origin: APP_ORIGIN }) }),
      makeEnv(),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { active: boolean; tenant_id: string; role: string; email: string };
    expect(body.active).toBe(true);
    expect(body.tenant_id).toBe(PROD_TENANT);
    expect(body.role).toBe("viewer");
    expect(body.email).toBe("a@b.com");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("reads tenant_id from the `org` claim as fallback", async () => {
    const token = await jwt({ org: PROD_TENANT });
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token, origin: APP_ORIGIN }) }),
      makeEnv(),
    );
    const body = (await res.json()) as { active: boolean; tenant_id: string };
    expect(body.active).toBe(true);
    expect(body.tenant_id).toBe(PROD_TENANT);
  });

  it("active:false for a JWT signed with the wrong secret", async () => {
    const token = await signTestJwt({ env: "prod", tenant_id: PROD_TENANT }, "wrong-jwt-secret-padding-32chr!!");
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token, origin: APP_ORIGIN }) }),
      makeEnv(),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { active: boolean };
    expect(body.active).toBe(false);
  });

  it("active:false for an expired JWT", async () => {
    const token = await jwt({ tenant_id: PROD_TENANT, exp: Math.floor(Date.now() / 1000) - 10 });
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token, origin: APP_ORIGIN }) }),
      makeEnv(),
    );
    const body = (await res.json()) as { active: boolean };
    expect(body.active).toBe(false);
  });

  it("active:false when env claim mismatches WORKER_ENV (#218)", async () => {
    const token = await signTestJwt({ env: "staging", tenant_id: PROD_TENANT }, TEST_JWT_SECRET);
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token, origin: APP_ORIGIN }) }),
      makeEnv(), // WORKER_ENV = "prod"
    );
    const body = (await res.json()) as { active: boolean };
    expect(body.active).toBe(false);
  });

  it("active:false when token field absent", async () => {
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ origin: APP_ORIGIN }) }),
      makeEnv(),
    );
    const body = (await res.json()) as { active: boolean };
    expect(body.active).toBe(false);
  });

  it("active:false on malformed JSON body", async () => {
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: "{not json" }),
      makeEnv(),
    );
    const body = (await res.json()) as { active: boolean };
    expect(body.active).toBe(false);
  });
});

describe("POST /auth/introspect — origin / ACL", () => {
  it("active:false when origin is missing (fail-closed, ACL cannot be enforced)", async () => {
    const token = await jwt({ tenant_id: PROD_TENANT });
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token }) }),
      makeEnv(),
    );
    const body = (await res.json()) as { active: boolean };
    expect(body.active).toBe(false);
  });

  it("active:false when origin is not a valid URL", async () => {
    const token = await jwt({ tenant_id: PROD_TENANT });
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token, origin: "not-a-url" }) }),
      makeEnv(),
    );
    const body = (await res.json()) as { active: boolean };
    expect(body.active).toBe(false);
  });

  it("active:false when tenant is not allowlisted for the app (APP_TENANT_ACL, #290 hole #3)", async () => {
    const env = makeEnv({
      APP_TENANT_ACL: JSON.stringify({ apps: { [APP_ORIGIN]: [PROD_TENANT] } }),
    });
    const token = await jwt({ tenant_id: OTHER_TENANT, email: "x@y.com" });
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token, origin: APP_ORIGIN }) }),
      env,
    );
    const body = (await res.json()) as { active: boolean };
    expect(body.active).toBe(false);
  });

  it("active:true when tenant is allowlisted for the app", async () => {
    const env = makeEnv({
      APP_TENANT_ACL: JSON.stringify({ apps: { [APP_ORIGIN]: [PROD_TENANT] } }),
    });
    const token = await jwt({ tenant_id: PROD_TENANT, email: "x@y.com" });
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token, origin: APP_ORIGIN }) }),
      env,
    );
    const body = (await res.json()) as { active: boolean; tenant_id: string };
    expect(body.active).toBe(true);
    expect(body.tenant_id).toBe(PROD_TENANT);
  });

  it("active:true via bypass_emails even when tenant is not in the app allowlist", async () => {
    const env = makeEnv({
      APP_TENANT_ACL: JSON.stringify({
        bypass_emails: ["dev@example.com"],
        apps: { [APP_ORIGIN]: [PROD_TENANT] },
      }),
    });
    const token = await jwt({ tenant_id: OTHER_TENANT, email: "dev@example.com" });
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token, origin: APP_ORIGIN }) }),
      env,
    );
    const body = (await res.json()) as { active: boolean };
    expect(body.active).toBe(true);
  });
});
