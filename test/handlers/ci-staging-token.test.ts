import { describe, it, expect, vi, beforeEach, afterAll, beforeAll } from "vitest";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";

// Refs ippoan/ci-dashboard#520: staging の CI 用 dev token の発行口。
// GitHub の JWKS は鍵を生成して fetch を差し替える (外部に通信しない)。
vi.mock("../../src/lib/acl", () => ({
  checkOrgAccess: vi.fn(async () => true),
  checkAppTenant: vi.fn(() => true),
}));
vi.mock("../../src/lib/alc-backend-route", async (orig) =>
  (await import("../helpers/fake-alc-route")).fakeAlcRouteFactory(await orig<object>()),
);

import {
  CI_STAGING_TOKEN_PATH,
  CI_TOKEN_TTL_SEC,
  handleCiStagingToken,
} from "../../src/handlers/ci-staging-token";
import { handleAlcProxy } from "../../src/handlers/alc-proxy";
import { DEV_TOKEN_TTL_SEC } from "../../src/lib/dev-login";
import { _clearGithubJwksCache, GITHUB_OIDC_ISSUER, GITHUB_OIDC_JWKS_URL } from "../../src/lib/github-oidc";
import { verifyJwt } from "../../src/lib/jwt";
import worker from "../../src/index";

const AUD = "auth-worker-staging-ci";
const REPO = "ippoan/alc-app";
const TENANT = "11111111-1111-1111-1111-111111111111";
const SUBJECT = "22222222-2222-2222-2222-222222222222";
const KID = "test-kid-1";
const PROXY_SECRET = "test-internal-shared-secret-32!!";

let keyPair: CryptoKeyPair;
let otherKeyPair: CryptoKeyPair;
let publicJwk: JsonWebKey;

const originalFetch = globalThis.fetch;
let jwksFetchCount = 0;

beforeAll(async () => {
  const gen = () =>
    crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    ) as Promise<CryptoKeyPair>;
  keyPair = await gen();
  otherKeyPair = await gen();
  publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
});

afterAll(() => {
  globalThis.fetch = originalFetch;
});

function mockJwks(keys: unknown[] | null = null, status = 200) {
  jwksFetchCount = 0;
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url === GITHUB_OIDC_JWKS_URL) {
      jwksFetchCount++;
      return new Response(
        JSON.stringify({ keys: keys ?? [{ ...publicJwk, kid: KID, alg: "RS256", use: "sig" }] }),
        { status },
      );
    }
    return new Response("ok", { status: 200 });
  }) as unknown as typeof fetch;
}

const b64url = (data: string | Uint8Array) =>
  Buffer.from(typeof data === "string" ? new TextEncoder().encode(data) : data).toString("base64url");

async function makeOidc(
  overrides: Record<string, unknown> = {},
  opts: { kid?: string | null; alg?: string; key?: CryptoKey } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header: Record<string, unknown> = { alg: opts.alg ?? "RS256", typ: "JWT" };
  if (opts.kid !== null) header.kid = opts.kid ?? KID;
  const payload = {
    iss: GITHUB_OIDC_ISSUER,
    aud: AUD,
    repository: REPO,
    repository_owner: "ippoan",
    run_id: "123456",
    ref: "refs/heads/main",
    sub: `repo:${REPO}:ref:refs/heads/main`,
    iat: now,
    nbf: now - 5,
    exp: now + 300,
    ...overrides,
  };
  const unsigned = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    opts.key ?? keyPair.privateKey,
    new TextEncoder().encode(unsigned),
  );
  return `${unsigned}.${b64url(new Uint8Array(sig))}`;
}

const STAGING_VARS = {
  WORKER_ENV: "staging",
  CI_TOKEN_ALLOWED_REPOS: `${REPO}, ippoan/other-repo`,
  CI_TOKEN_AUDIENCE: AUD,
  CI_TOKEN_TENANT_ID: TENANT,
  CI_TOKEN_SUBJECT: SUBJECT,
  CI_TOKEN_EMAIL: "admin@example.com",
  CI_TOKEN_ROLE: "admin",
};

function env(overrides: Record<string, unknown> = {}) {
  return createMockEnv({ ...STAGING_VARS, INTERNAL_SHARED_SECRET: PROXY_SECRET, ...overrides });
}

function req(token: string | null, method = "POST") {
  const headers: Record<string, string> = {};
  if (token !== null) headers["Authorization"] = `Bearer ${token}`;
  return new Request(`https://auth-staging.test.example${CI_STAGING_TOKEN_PATH}`, { method, headers });
}

describe("POST /api/ci/staging-token (Refs ippoan/ci-dashboard#520)", () => {
  beforeEach(() => {
    _clearGithubJwksCache();
    mockJwks();
  });

  it("正しい OIDC → 200 で dev token (token_kind=dev・TTL が上限以内・tenant/subject が設定値)", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const oidc = await makeOidc();
    const res = await handleCiStagingToken(req(oidc), env());
    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
    const body = (await res.json()) as { token: string; expires_at: number };
    const claims = await verifyJwt(body.token, TEST_JWT_SECRET, "staging");
    expect(claims).not.toBeNull();
    expect(claims!.token_kind).toBe("dev");
    expect(claims!.tenant_id).toBe(TENANT);
    expect(claims!.sub).toBe(SUBJECT);
    expect(claims!.email).toBe("admin@example.com");
    expect(claims!.role).toBe("admin");
    expect(claims!.aud).toBeUndefined();
    expect(claims!.exp).toBe(body.expires_at);
    const ttl = (claims!.exp as number) - (claims!.iat as number);
    expect(ttl).toBe(CI_TOKEN_TTL_SEC);
    expect(ttl).toBeLessThanOrEqual(DEV_TOKEN_TTL_SEC);

    // 構造化ログ 1 行。token の値 (発行した token も OIDC token も) は出さない
    const lines = logSpy.mock.calls.map((c) => String(c[0]));
    const issued = lines.filter((l) => l.includes("ci-staging-token-issued"));
    expect(issued).toHaveLength(1);
    expect(JSON.parse(issued[0]!)).toEqual({
      msg: "ci-staging-token-issued",
      repository: REPO,
      run_id: "123456",
      ref: "refs/heads/main",
      exp: body.expires_at,
    });
    for (const l of lines) {
      expect(l).not.toContain(body.token);
      expect(l).not.toContain(oidc);
    }
  });

  it("JWKS は cache され、2 回目は取りに行かない", async () => {
    expect((await handleCiStagingToken(req(await makeOidc()), env())).status).toBe(200);
    expect((await handleCiStagingToken(req(await makeOidc()), env())).status).toBe(200);
    expect(jwksFetchCount).toBe(1);
  });

  it("発行した token で alc-proxy に POST すると 403 (read-only が効く)、GET は通る", async () => {
    const body = (await (await handleCiStagingToken(req(await makeOidc()), env())).json()) as {
      token: string;
    };
    const proxyReq = (method: string) =>
      new Request("https://auth-staging.test.example/alc-proxy/api/employees", {
        method,
        headers: {
          Authorization: `Bearer ${body.token}`,
          "X-Alc-Proxy-Origin": "https://alc-staging.ippoan.org",
          "X-Alc-Proxy-Secret": PROXY_SECRET,
          "content-type": "application/json",
        },
        body: method === "POST" ? "{}" : undefined,
      });
    const post = await handleAlcProxy(proxyReq("POST"), env());
    expect(post.status).toBe(403);
    expect(((await post.json()) as { error: string }).error).toBe("dev_token_write_forbidden");
    const get = await handleAlcProxy(proxyReq("GET"), env());
    expect(get.status).toBe(200);
  });

  describe("OIDC が不正なら 401 (理由は返さずログにだけ)", () => {
    const cases: [string, () => Promise<string>, string][] = [
      ["署名不正 (別の鍵)", () => makeOidc({}, { key: otherKeyPair.privateKey }), "signature"],
      ["iss 違い", () => makeOidc({ iss: "https://evil.example" }), "iss"],
      ["aud 違い", () => makeOidc({ aud: "other-aud" }), "aud"],
      ["期限切れ (時計ずれ 60 秒を超える)", () => makeOidc({ exp: Math.floor(Date.now() / 1000) - 61 }), "exp"],
      ["nbf が未来", () => makeOidc({ nbf: Math.floor(Date.now() / 1000) + 120 }), "nbf"],
      ["iat が未来", () => makeOidc({ iat: Math.floor(Date.now() / 1000) + 120 }), "iat"],
      ["repository が allowlist 外", () => makeOidc({ repository: "ippoan/not-allowed" }), "repository"],
      ["owner 違い", () => makeOidc({ repository: "evil/alc-app", repository_owner: "evil" }), "repository_owner"],
      ["repository は一致でも owner 違い", () => makeOidc({ repository_owner: "evil" }), "repository_owner"],
      ["alg が RS256 でない", () => makeOidc({}, { alg: "HS256" }), "alg"],
      ["kid が無い", () => makeOidc({}, { kid: null }), "kid"],
      ["知らない kid", () => makeOidc({}, { kid: "unknown" }), "unknown_kid"],
      ["形が JWT でない", async () => "not-a-jwt", "shape"],
    ];
    for (const [name, make, reason] of cases) {
      it(name, async () => {
        const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
        const token = await make();
        const res = await handleCiStagingToken(req(token), env());
        expect(res.status).toBe(401);
        expect(await res.json()).toEqual({ error: "unauthorized" });
        const logged = warn.mock.calls.map((c) => String(c[0]));
        expect(logged.some((l) => JSON.parse(l).reason === reason)).toBe(true);
        for (const l of logged) expect(l).not.toContain(token);
      });
    }

    it("Bearer が無い", async () => {
      vi.spyOn(console, "warn").mockImplementation(() => {});
      expect((await handleCiStagingToken(req(null), env())).status).toBe(401);
    });

    it("JWKS が取れない", async () => {
      vi.spyOn(console, "warn").mockImplementation(() => {});
      mockJwks(null, 500);
      expect((await handleCiStagingToken(req(await makeOidc()), env())).status).toBe(401);
    });
  });

  describe("設定が欠けている (= 本番相当) なら発行しない", () => {
    const missing: [string, Record<string, unknown>][] = [
      ["WORKER_ENV が prod", { WORKER_ENV: "prod" }],
      ["CI_TOKEN_ALLOWED_REPOS 無し", { CI_TOKEN_ALLOWED_REPOS: undefined }],
      ["CI_TOKEN_ALLOWED_REPOS が ippoan 以外だけ", { CI_TOKEN_ALLOWED_REPOS: "evil/alc-app" }],
      ["CI_TOKEN_AUDIENCE 無し", { CI_TOKEN_AUDIENCE: undefined }],
      ["CI_TOKEN_TENANT_ID 無し", { CI_TOKEN_TENANT_ID: undefined }],
      ["CI_TOKEN_SUBJECT 無し", { CI_TOKEN_SUBJECT: "" }],
      ["CI_TOKEN_EMAIL 無し", { CI_TOKEN_EMAIL: undefined }],
      ["CI_TOKEN_ROLE 無し", { CI_TOKEN_ROLE: undefined }],
    ];
    for (const [name, overrides] of missing) {
      it(`${name} → 404`, async () => {
        const res = await handleCiStagingToken(req(await makeOidc()), env(overrides));
        expect(res.status).toBe(404);
        expect(jwksFetchCount).toBe(0);
      });
    }

    it("本番の Env (createMockEnv の既定、CI_TOKEN_* 無し) は index の route でも 404", async () => {
      const res = await worker.fetch(req(await makeOidc()), createMockEnv());
      expect(res.status).toBe(404);
      expect(jwksFetchCount).toBe(0);
    });
  });

  it("staging の設定なら index の route から届く", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const res = await worker.fetch(req(await makeOidc()), env());
    expect(res.status).toBe(200);
  });

  it("POST 以外は 405", async () => {
    expect((await handleCiStagingToken(req(await makeOidc(), "GET"), env())).status).toBe(405);
  });

  it("JWT_SECRET が無ければ 503", async () => {
    expect((await handleCiStagingToken(req(await makeOidc()), env({ JWT_SECRET: undefined }))).status).toBe(
      503,
    );
  });
});
