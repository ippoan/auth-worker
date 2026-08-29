import { describe, it, expect } from "vitest";
import { handleAuthIntrospect } from "../../src/handlers/auth-introspect";
import { createMockEnv, createMockKV, TEST_JWT_SECRET } from "../helpers/mock-env";
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
    const token = await jwt({ tenant_id: PROD_TENANT, email: "a@b.com", role: "viewer", sub: "github:alice", exp: Math.floor(Date.now() / 1000) + 3600 });
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token, origin: APP_ORIGIN }) }),
      makeEnv(),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { active: boolean; tenant_id: string; role: string; email: string; sub: string };
    expect(body.active).toBe(true);
    expect(body.tenant_id).toBe(PROD_TENANT);
    expect(body.role).toBe("viewer");
    expect(body.email).toBe("a@b.com");
    expect(body.sub).toBe("github:alice");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("active:true for a device-hub device JWT (cf-alc-recorder の WS ハンドシェイク経路、#363)", async () => {
    const { mintDeviceJwt, DEVICE_ROLE_HUB } = await import("../../src/lib/device");
    const token = await mintDeviceJwt(
      { JWT_SECRET: TEST_JWT_SECRET, WORKER_ENV: "prod" },
      {
        device_id: "hub-dev-1",
        tenant_id: PROD_TENANT,
        secret_hash: "x",
        label: "cores3",
        created_at: Math.floor(Date.now() / 1000),
        revoked: false,
        role: DEVICE_ROLE_HUB,
      },
      Math.floor(Date.now() / 1000),
    );
    const res = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token, origin: APP_ORIGIN }) }),
      makeEnv(),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { active: boolean; tenant_id: string; role: string; sub: string };
    expect(body.active).toBe(true);
    expect(body.tenant_id).toBe(PROD_TENANT);
    expect(body.role).toBe(DEVICE_ROLE_HUB);
    expect(body.sub).toBe("hub-dev-1"); // recorder は sub を device_id として注入する
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


// ── org_wide (Refs ohishi-exp/nuxt-dtako-admin#1049) ────────────────────────
// USER_ACL 由来の「テナント境界を越えて org 全体を見てよい人」フラグ。
// DEVELOPER_EMAILS (UI 専用) とも role とも無関係であることに注意。
const OHISHI_ORIGIN = "https://dtako-admin.example";
const APP_ORGS = JSON.stringify({ "dtako-admin": "ohishi-exp" });
const OHISHI_TENANT_ACL = JSON.stringify({ "ohishi-exp": [PROD_TENANT] });
const OHISHI_USER_ACL = JSON.stringify({ "ohishi-exp": ["orgwide@example.com"] });

/** ohishi-exp と分類される origin を持つ env (app-orgs を KV に入れる)。 */
function ohishiEnv(overrides: Partial<Env> = {}): Env {
  return makeEnv({
    AUTH_CONFIG: createMockKV({ "app-orgs": APP_ORGS }),
    TENANT_ACL: OHISHI_TENANT_ACL,
    USER_ACL: OHISHI_USER_ACL,
    ...overrides,
  });
}

async function introspect(env: Env, token: string, origin: string) {
  const res = await handleAuthIntrospect(
    req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token, origin }) }),
    env,
  );
  return (await res.json()) as { active: boolean; org_wide?: boolean; role?: string };
}

describe("POST /auth/introspect — org_wide", () => {
  it("org_wide:true when the email is on USER_ACL (tenant not allowlisted)", async () => {
    const token = await jwt({ tenant_id: OTHER_TENANT, email: "orgwide@example.com" });
    const body = await introspect(ohishiEnv(), token, OHISHI_ORIGIN);
    expect(body.active).toBe(true);
    expect(body.org_wide).toBe(true);
  });

  // ★ 早期 return の穴の陰性対照。tenant でも email でも通る人は、
  //   matchesOrgAllowlist を流用した実装だと tenant 側で早期 return して
  //   org_wide:false になる。
  it("org_wide:true even when the tenant is ALSO on TENANT_ACL", async () => {
    const token = await jwt({ tenant_id: PROD_TENANT, email: "orgwide@example.com" });
    const body = await introspect(ohishiEnv(), token, OHISHI_ORIGIN);
    expect(body.active).toBe(true);
    expect(body.org_wide).toBe(true);
  });

  it("org_wide:false for a tenant-allowlisted user who is not on USER_ACL", async () => {
    const token = await jwt({ tenant_id: PROD_TENANT, email: "someone@example.com" });
    const body = await introspect(ohishiEnv(), token, OHISHI_ORIGIN);
    expect(body.active).toBe(true);
    expect(body.org_wide).toBe(false);
  });

  it("org_wide is case-insensitive on the email", async () => {
    const token = await jwt({ tenant_id: OTHER_TENANT, email: "OrgWide@Example.COM" });
    const body = await introspect(ohishiEnv(), token, OHISHI_ORIGIN);
    expect(body.org_wide).toBe(true);
  });

  it("org_wide:false when USER_ACL is emptied (negative control)", async () => {
    const token = await jwt({ tenant_id: PROD_TENANT, email: "orgwide@example.com" });
    const empty = ohishiEnv({ USER_ACL: JSON.stringify({ "ohishi-exp": [] }) });
    const body = await introspect(empty, token, OHISHI_ORIGIN);
    expect(body.active).toBe(true);
    expect(body.org_wide).toBe(false);
  });

  it("org_wide:false when USER_ACL is unset / malformed (fail-closed)", async () => {
    const token = await jwt({ tenant_id: PROD_TENANT, email: "orgwide@example.com" });
    for (const acl of [undefined, "not-json", JSON.stringify({ "ohishi-exp": "nope" })]) {
      const body = await introspect(ohishiEnv({ USER_ACL: acl }), token, OHISHI_ORIGIN);
      expect(body.active).toBe(true);
      expect(body.org_wide).toBe(false);
    }
  });

  it("org_wide:false for a non-ohishi-exp (ippoan) origin even if the email is listed", async () => {
    const token = await jwt({ tenant_id: PROD_TENANT, email: "orgwide@example.com" });
    const body = await introspect(ohishiEnv(), token, APP_ORIGIN);
    expect(body.active).toBe(true);
    expect(body.org_wide).toBe(false);
  });

  it("org_wide:false when app-orgs KV is missing (org unclassifiable → fail-closed)", async () => {
    const token = await jwt({ tenant_id: PROD_TENANT, email: "orgwide@example.com" });
    const noOrgs = makeEnv({ AUTH_CONFIG: createMockKV({}), USER_ACL: OHISHI_USER_ACL });
    const body = await introspect(noOrgs, token, OHISHI_ORIGIN);
    expect(body.active).toBe(true);
    expect(body.org_wide).toBe(false);
  });

  // ★ この直しの本体。TENANT_ACL で通っている人は、これまで USER_ACL に一度も
  //   触らずに済んでいた (matchesOrgAllowlist の早期 return)。org_wide は必ず
  //   USER_ACL を読むので、要素の型崩れで introspect ごと落ちてはいけない。
  it("tenant-allowlisted user still gets active:true / org_wide:false when USER_ACL elements are malformed", async () => {
    const token = await jwt({ tenant_id: PROD_TENANT, email: "someone@example.com" });
    const env = ohishiEnv({ USER_ACL: JSON.stringify({ "ohishi-exp": [1, null, { a: 1 }] }) });
    const body = await introspect(env, token, OHISHI_ORIGIN);
    expect(body.active).toBe(true);
    expect(body.org_wide).toBe(false);
  });

  it("org_wide is independent of role — an admin is not org-wide by itself", async () => {
    const token = await jwt({ tenant_id: PROD_TENANT, email: "someone@example.com", role: "admin" });
    const body = await introspect(ohishiEnv(), token, OHISHI_ORIGIN);
    expect(body.role).toBe("admin");
    expect(body.org_wide).toBe(false);
  });

  it("org_wide is absent from every active:false response (no info leak)", async () => {
    const env = ohishiEnv();
    const expired = await jwt({
      tenant_id: PROD_TENANT,
      email: "orgwide@example.com",
      exp: Math.floor(Date.now() / 1000) - 10,
    });
    const denied = await jwt({ tenant_id: OTHER_TENANT, email: "nobody@example.com" });

    for (const [token, origin] of [
      [expired, OHISHI_ORIGIN],
      [denied, OHISHI_ORIGIN], // ACL で落ちる
      ["not-a-jwt", OHISHI_ORIGIN],
    ] as const) {
      const body = await introspect(env, token, origin);
      expect(body.active).toBe(false);
      expect("org_wide" in body).toBe(false);
    }

    // origin 欠落 / URL 不正 / body 不正 / 401 / 503 も同様。
    const res401 = await handleAuthIntrospect(
      req({ auth: "wrong-secret", body: JSON.stringify({ token: expired, origin: OHISHI_ORIGIN }) }),
      env,
    );
    expect("org_wide" in ((await res401.json()) as object)).toBe(false);

    const res503 = await handleAuthIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: expired, origin: OHISHI_ORIGIN }) }),
      ohishiEnv({ JWT_SECRET: undefined }),
    );
    expect("org_wide" in ((await res503.json()) as object)).toBe(false);
  });

  it("adding org_wide does not change any allow/deny outcome", async () => {
    const env = ohishiEnv();
    // USER_ACL で通る人 / TENANT_ACL で通る人 / どちらでも通らない人。
    const viaUser = await jwt({ tenant_id: OTHER_TENANT, email: "orgwide@example.com" });
    const viaTenant = await jwt({ tenant_id: PROD_TENANT, email: "someone@example.com" });
    const neither = await jwt({ tenant_id: OTHER_TENANT, email: "someone@example.com" });

    expect((await introspect(env, viaUser, OHISHI_ORIGIN)).active).toBe(true);
    expect((await introspect(env, viaTenant, OHISHI_ORIGIN)).active).toBe(true);
    expect((await introspect(env, neither, OHISHI_ORIGIN)).active).toBe(false);
  });
});
