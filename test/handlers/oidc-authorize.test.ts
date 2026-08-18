import { describe, it, expect } from "vitest";
import { handleOidcAuthorize } from "../../src/handlers/oidc-authorize";
import { createMockEnv, createMockKV, TEST_JWT_SECRET, type MockKV } from "../helpers/mock-env";
// cookie を実際に発行しているのは本番の signJwt (UTF-8 safe)。テスト用 helper
// (test-jwt.ts) は btoa 直呼びで多バイト claim を扱えないため、こちらを使う。
import { signJwt } from "../../src/lib/jwt";
import type { Env } from "../../src/index";
import type { OidcCodeRecord } from "../../src/lib/oidc-authcode";

const REDIRECT_URI = "https://team.cloudflareaccess.com/cdn-cgi/access/callback";
const CLIENTS = JSON.stringify([
  { client_id: "cf-access", client_secret: "s3cret", redirect_uris: [REDIRECT_URI] },
]);

function envWith(overrides: Partial<Env> = {}): Env {
  return createMockEnv({
    MCP_OAUTH_KV: createMockKV(),
    ACCESS_OIDC_CLIENTS: CLIENTS,
    ...overrides,
  });
}

function authorizeUrl(params: Record<string, string> = {}): string {
  const u = new URL("https://auth.test.example/oidc/authorize");
  const defaults: Record<string, string> = {
    response_type: "code",
    client_id: "cf-access",
    redirect_uri: REDIRECT_URI,
    state: "st-1",
    scope: "openid email",
  };
  for (const [k, v] of Object.entries({ ...defaults, ...params })) {
    if (v !== "") u.searchParams.set(k, v);
  }
  return u.toString();
}

/** 有効な logi_auth_token を持つリクエストを作る。 */
async function requestWithSession(
  url: string,
  claims: Record<string, unknown> = {},
): Promise<Request> {
  const jwt = await signJwt(
    {
      // verifyJwt は exp 必須。signJwt は補わないので fixture 側で明示する。
      exp: Math.floor(Date.now() / 1000) + 3600,
      sub: "user-1",
      email: "taro@ippoan.org",
      name: "大石 太郎",
      tenant_id: "tenant-1",
      role: "admin",
      env: "prod",
      ...claims,
    },
    TEST_JWT_SECRET,
  );
  return new Request(url, { headers: { Cookie: `logi_auth_token=${jwt}` } });
}

/** 発行された code の KV レコードを取り出す。 */
function storedCode(env: Env): { code: string; record: OidcCodeRecord } {
  const data = (env.MCP_OAUTH_KV as unknown as MockKV)._data;
  const key = Object.keys(data).find((k) => k.startsWith("oidc:code:"))!;
  return { code: key.slice("oidc:code:".length), record: JSON.parse(data[key]!) as OidcCodeRecord };
}

describe("GET /oidc/authorize — silent SSO (the whole point of this surface)", () => {
  it("issues a code WITHOUT bouncing to any IdP when a valid session cookie exists", async () => {
    const env = envWith();
    const res = await handleOidcAuthorize(await requestWithSession(authorizeUrl()), env);

    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    // 外部 IdP (GitHub / Google) にも /login にも飛ばず、まっすぐ client に戻る。
    expect(loc.origin + loc.pathname).toBe(REDIRECT_URI);
    expect(loc.searchParams.get("code")).toBeTruthy();
    expect(loc.searchParams.get("state")).toBe("st-1");
  });

  it("carries iss on the success redirect (RFC 9207 mix-up defence)", async () => {
    const env = envWith();
    const res = await handleOidcAuthorize(await requestWithSession(authorizeUrl()), env);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.searchParams.get("iss")).toBe("https://auth.test.example/oidc");
  });

  it("copies identity from the session into the stored code", async () => {
    const env = envWith();
    await handleOidcAuthorize(await requestWithSession(authorizeUrl()), env);
    const { record } = storedCode(env);
    expect(record.claims).toEqual({
      sub: "user-1",
      email: "taro@ippoan.org",
      name: "大石 太郎",
      tenant_id: "tenant-1",
      role: "admin",
    });
    expect(record.client_id).toBe("cf-access");
    expect(record.redirect_uri).toBe(REDIRECT_URI);
    expect(record.scope).toBe("openid email");
  });

  it("stores nonce and code_challenge when supplied", async () => {
    const env = envWith();
    await handleOidcAuthorize(
      await requestWithSession(
        authorizeUrl({ nonce: "n-9", code_challenge: "chal", code_challenge_method: "S256" }),
      ),
      env,
    );
    const { record } = storedCode(env);
    expect(record.nonce).toBe("n-9");
    expect(record.code_challenge).toBe("chal");
  });

  it("omits nonce / code_challenge when not supplied (no empty-string keys)", async () => {
    const env = envWith();
    await handleOidcAuthorize(await requestWithSession(authorizeUrl()), env);
    const { record } = storedCode(env);
    expect(record.nonce).toBeUndefined();
    expect(record.code_challenge).toBeUndefined();
  });

  it("defaults scope to openid when the client omits it", async () => {
    const env = envWith();
    await handleOidcAuthorize(await requestWithSession(authorizeUrl({ scope: "" })), env);
    expect(storedCode(env).record.scope).toBe("openid");
  });

  it("carries optional claims only when present in the session", async () => {
    const env = envWith();
    const jwt = await signJwt(
      { exp: Math.floor(Date.now() / 1000) + 3600, sub: "u2", email: "b@ippoan.org", env: "prod" },
      TEST_JWT_SECRET,
    );
    await handleOidcAuthorize(
      new Request(authorizeUrl(), { headers: { Cookie: `logi_auth_token=${jwt}` } }),
      env,
    );
    expect(storedCode(env).record.claims).toEqual({ sub: "u2", email: "b@ippoan.org" });
  });

  it("includes org_slug when the session carries it", async () => {
    const env = envWith();
    await handleOidcAuthorize(
      await requestWithSession(authorizeUrl(), { org_slug: "ippoan" }),
      env,
    );
    expect(storedCode(env).record.claims.org_slug).toBe("ippoan");
  });

  it("picks the valid cookie when a stale duplicate shadows it (Refs #387)", async () => {
    const env = envWith();
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const stale = await signJwt({ exp, sub: "old", email: "old@x", env: "staging" }, TEST_JWT_SECRET);
    const good = await signJwt(
      { exp, sub: "user-1", email: "taro@ippoan.org", env: "prod" },
      TEST_JWT_SECRET,
    );
    const res = await handleOidcAuthorize(
      new Request(authorizeUrl(), {
        headers: { Cookie: `logi_auth_token=${stale}; logi_auth_token=${good}` },
      }),
      env,
    );
    expect(res.status).toBe(302);
    expect(storedCode(env).record.claims.sub).toBe("user-1");
  });

  it("omits state from the redirect when the client did not send one", async () => {
    const env = envWith();
    const res = await handleOidcAuthorize(
      await requestWithSession(authorizeUrl({ state: "" })),
      env,
    );
    expect(new URL(res.headers.get("Location")!).searchParams.has("state")).toBe(false);
  });
});

describe("GET /oidc/authorize — falling back to login", () => {
  it("sends the user to /login with this authorize URL as the return target", async () => {
    const env = envWith();
    const res = await handleOidcAuthorize(new Request(authorizeUrl()), env);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.origin + loc.pathname).toBe("https://auth.test.example/login");
    const back = new URL(loc.searchParams.get("redirect_uri")!);
    expect(back.pathname).toBe("/oidc/authorize");
    // 元の query を落とすと login 後に client へ戻れなくなるので、そのまま持ち回る。
    expect(back.searchParams.get("client_id")).toBe("cf-access");
    expect(back.searchParams.get("state")).toBe("st-1");
    expect(back.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
  });

  it.each([
    ["an expired session", { exp: Math.floor(Date.now() / 1000) - 10 }],
    ["a session from another environment (#218 cross-env replay)", { env: "staging" }],
    ["a session with no sub", { sub: "" }],
    ["a session with no email", { email: "" }],
  ])("falls back to login for %s", async (_label, claims) => {
    const env = envWith();
    const jwt = await signJwt(
      { exp: Math.floor(Date.now() / 1000) + 3600, sub: "u", email: "a@x", env: "prod", ...claims },
      TEST_JWT_SECRET,
    );
    const res = await handleOidcAuthorize(
      new Request(authorizeUrl(), { headers: { Cookie: `logi_auth_token=${jwt}` } }),
      env,
    );
    expect(new URL(res.headers.get("Location")!).pathname).toBe("/login");
  });

  it("falls back to login when the cookie is signed with the wrong secret", async () => {
    const env = envWith();
    const jwt = await signJwt(
      { exp: Math.floor(Date.now() / 1000) + 3600, sub: "u", email: "a@x", env: "prod" },
      "a-different-secret!!",
    );
    const res = await handleOidcAuthorize(
      new Request(authorizeUrl(), { headers: { Cookie: `logi_auth_token=${jwt}` } }),
      env,
    );
    expect(new URL(res.headers.get("Location")!).pathname).toBe("/login");
  });

  it("falls back to login for a structurally broken cookie (not a JWT at all)", async () => {
    const env = envWith();
    const res = await handleOidcAuthorize(
      new Request(authorizeUrl(), { headers: { Cookie: "logi_auth_token=not-a-jwt" } }),
      env,
    );
    expect(new URL(res.headers.get("Location")!).pathname).toBe("/login");
  });

  it.each([
    ["sub", { sub: 12345 }],
    ["email", { email: { nested: true } }],
  ])("falls back to login when %s is not a string", async (_label, claims) => {
    const env = envWith();
    const jwt = await signJwt(
      { exp: Math.floor(Date.now() / 1000) + 3600, sub: "u", email: "a@x", env: "prod", ...claims },
      TEST_JWT_SECRET,
    );
    const res = await handleOidcAuthorize(
      new Request(authorizeUrl(), { headers: { Cookie: `logi_auth_token=${jwt}` } }),
      env,
    );
    expect(new URL(res.headers.get("Location")!).pathname).toBe("/login");
  });

  it("ignores non-string optional claims rather than copying them through", async () => {
    const env = envWith();
    const jwt = await signJwt(
      {
        exp: Math.floor(Date.now() / 1000) + 3600,
        sub: "u",
        email: "a@x",
        env: "prod",
        name: 42,
        tenant_id: [],
        role: null,
        org_slug: 7,
      },
      TEST_JWT_SECRET,
    );
    await handleOidcAuthorize(
      new Request(authorizeUrl(), { headers: { Cookie: `logi_auth_token=${jwt}` } }),
      env,
    );
    expect(storedCode(env).record.claims).toEqual({ sub: "u", email: "a@x" });
  });

  it("falls back to login when JWT_SECRET is unavailable", async () => {
    const env = envWith({ JWT_SECRET: undefined });
    const res = await handleOidcAuthorize(await requestWithSession(authorizeUrl()), env);
    expect(new URL(res.headers.get("Location")!).pathname).toBe("/login");
  });

  it("uses the request origin when AUTH_WORKER_ORIGIN is unset", async () => {
    const env = envWith({ AUTH_WORKER_ORIGIN: "" });
    const res = await handleOidcAuthorize(new Request(authorizeUrl()), env);
    expect(res.headers.get("Location")!.startsWith("https://auth.test.example/login")).toBe(true);
  });
});

describe("GET /oidc/authorize — rejections", () => {
  it("returns 400 when client_id is absent entirely", async () => {
    const res = await handleOidcAuthorize(
      await requestWithSession(authorizeUrl({ client_id: "" })),
      envWith(),
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 (not a redirect) for an unknown client_id", async () => {
    const res = await handleOidcAuthorize(
      await requestWithSession(authorizeUrl({ client_id: "nope" })),
      envWith(),
    );
    expect(res.status).toBe(400);
  });

  it("returns 400 for an unregistered redirect_uri — never redirects there (open redirect)", async () => {
    const res = await handleOidcAuthorize(
      await requestWithSession(authorizeUrl({ redirect_uri: "https://evil.example/steal" })),
      envWith(),
    );
    expect(res.status).toBe(400);
    expect(res.headers.get("Location")).toBeNull();
  });

  it("returns 400 when redirect_uri is missing entirely", async () => {
    const res = await handleOidcAuthorize(
      await requestWithSession(authorizeUrl({ redirect_uri: "" })),
      envWith(),
    );
    expect(res.status).toBe(400);
  });

  it("redirects an unsupported response_type back to the client as an error", async () => {
    const res = await handleOidcAuthorize(
      await requestWithSession(authorizeUrl({ response_type: "token" })),
      envWith(),
    );
    const loc = new URL(res.headers.get("Location")!);
    expect(loc.origin + loc.pathname).toBe(REDIRECT_URI);
    expect(loc.searchParams.get("error")).toBe("unsupported_response_type");
    expect(loc.searchParams.get("state")).toBe("st-1");
    expect(loc.searchParams.get("iss")).toBe("https://auth.test.example/oidc");
  });

  it("rejects a non-S256 code_challenge_method", async () => {
    const res = await handleOidcAuthorize(
      await requestWithSession(
        authorizeUrl({ code_challenge: "c", code_challenge_method: "plain" }),
      ),
      envWith(),
    );
    expect(new URL(res.headers.get("Location")!).searchParams.get("error")).toBe("invalid_request");
  });

  it("rejects a code_challenge with no method at all", async () => {
    const res = await handleOidcAuthorize(
      await requestWithSession(authorizeUrl({ code_challenge: "c" })),
      envWith(),
    );
    expect(new URL(res.headers.get("Location")!).searchParams.get("error")).toBe("invalid_request");
  });

  it("omits state from the error redirect when none was sent", async () => {
    const res = await handleOidcAuthorize(
      await requestWithSession(authorizeUrl({ response_type: "token", state: "" })),
      envWith(),
    );
    expect(new URL(res.headers.get("Location")!).searchParams.has("state")).toBe(false);
  });

  it("returns 503 when the KV namespace is not bound", async () => {
    const res = await handleOidcAuthorize(
      await requestWithSession(authorizeUrl()),
      envWith({ MCP_OAUTH_KV: undefined }),
    );
    expect(res.status).toBe(503);
  });

  it("returns 503 when the client registry is not configured", async () => {
    const res = await handleOidcAuthorize(
      await requestWithSession(authorizeUrl()),
      envWith({ ACCESS_OIDC_CLIENTS: undefined }),
    );
    expect(res.status).toBe(503);
  });
});
