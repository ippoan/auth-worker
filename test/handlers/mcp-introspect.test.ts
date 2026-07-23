import { describe, it, expect } from "vitest";
import { handleMcpIntrospect } from "../../src/handlers/mcp-introspect";
import {
  createMockEnv,
  createMockKV,
  type MockKV,
} from "../helpers/mock-env";
import type { Env } from "../../src/index";
import { signMcpJwt } from "../../src/lib/mcp-jwt";
import { encryptWithKey } from "../../src/lib/mcp-crypto";

const ISSUER = "https://auth.test.example";
const TEST_MCP_JWT_SECRET = "test-mcp-jwt-secret-32chars!";
const TEST_SSO_KEY = "test-sso-encryption-key-material!";
const TEST_INTERNAL_SECRET = "test-internal-shared-secret-32chr";
const AUD = "github-mcp-server-rs";

function envWithKv(overrides: Partial<Env> = {}): { env: Env; kv: MockKV } {
  const kv = createMockKV() as MockKV;
  const env = createMockEnv({
    MCP_OAUTH_KV: kv,
    AUTH_WORKER_ORIGIN: ISSUER,
    MCP_JWT_SECRET: TEST_MCP_JWT_SECRET,
    SSO_ENCRYPTION_KEY: TEST_SSO_KEY,
    INTERNAL_SHARED_SECRET: TEST_INTERNAL_SECRET,
    ...overrides,
  });
  return { env, kv };
}

function req(opts: { auth?: string | null; body?: BodyInit | null; contentType?: string }): Request {
  const headers: Record<string, string> = {};
  if (opts.auth !== null && opts.auth !== undefined) headers.Authorization = opts.auth;
  if (opts.contentType !== undefined) headers["Content-Type"] = opts.contentType;
  else headers["Content-Type"] = "application/json";
  return new Request(`${ISSUER}/mcp/introspect`, {
    method: "POST",
    headers,
    body: opts.body ?? null,
  });
}

async function makeValidJwt(login = "alice", scope = "read:user"): Promise<string> {
  return signMcpJwt(
    { sub: `github:${login}`, github_login: login, scope, aud: AUD },
    TEST_MCP_JWT_SECRET,
    3600,
  );
}

describe("POST /mcp/introspect — env guards", () => {
  it("returns 503 active:false when MCP_OAUTH_KV not bound", async () => {
    const env = createMockEnv({
      MCP_OAUTH_KV: undefined,
      MCP_JWT_SECRET: TEST_MCP_JWT_SECRET,
      SSO_ENCRYPTION_KEY: TEST_SSO_KEY,
      INTERNAL_SHARED_SECRET: TEST_INTERNAL_SECRET,
    });
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(503);
    const body = await res.json() as { active: boolean };
    expect(body.active).toBe(false);
  });

  it("returns 503 when MCP_JWT_SECRET missing", async () => {
    const { env } = envWithKv({ MCP_JWT_SECRET: undefined });
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("returns 503 when SSO_ENCRYPTION_KEY missing", async () => {
    const { env } = envWithKv({ SSO_ENCRYPTION_KEY: "" });
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("returns 503 when INTERNAL_SHARED_SECRET missing", async () => {
    const { env } = envWithKv({ INTERNAL_SHARED_SECRET: undefined });
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(503);
  });
});

describe("POST /mcp/introspect — internal auth", () => {
  it("returns 401 when Authorization header missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpIntrospect(
      req({ auth: null, body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 401 when Authorization value mismatches (different length)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpIntrospect(
      req({ auth: "wrong", body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 401 when Authorization value mismatches (same length)", async () => {
    const { env } = envWithKv();
    const wrong = "x".repeat(TEST_INTERNAL_SECRET.length);
    const res = await handleMcpIntrospect(
      req({ auth: wrong, body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(401);
  });

  // Multi-secret support: `INTERNAL_SHARED_SECRET` (legacy) + any
  // `INTERNAL_SHARED_SECRET_<consumer>` binding is accepted. issue #189.
  it("accepts a request authenticated by a per-consumer INTERNAL_SHARED_SECRET_* binding", async () => {
    const CI_DASHBOARD_SECRET = "ci-dashboard-internal-shared-32chr!";
    // The per-consumer key is dynamic on Env so we widen here. `createMockEnv`
    // passes the override through; introspect's `resolveAllSharedSecrets`
    // iterates `Object.keys(env)` so any string-valued key starting with
    // `INTERNAL_SHARED_SECRET` becomes an accepted secret.
    const { env, kv } = envWithKv(
      { INTERNAL_SHARED_SECRET_CI_DASHBOARD: CI_DASHBOARD_SECRET } as unknown as Partial<Env>,
    );
    const jwt = await makeValidJwt("alice");
    const enc = await encryptWithKey("gh_test_token", TEST_SSO_KEY);
    kv._data["github_token:github:alice"] = enc;
    const res = await handleMcpIntrospect(
      req({ auth: CI_DASHBOARD_SECRET, body: JSON.stringify({ token: jwt }) }),
      env,
    );
    expect(res.status).toBe(200);
    const json = await res.json<{ active: boolean }>();
    expect(json.active).toBe(true);
  });

  it("rejects 401 when neither legacy nor per-consumer secret matches", async () => {
    const { env } = envWithKv(
      { INTERNAL_SHARED_SECRET_CI_DASHBOARD: "ci-dashboard-internal-shared-32chr!" } as unknown as Partial<Env>,
    );
    const res = await handleMcpIntrospect(
      req({ auth: "neither-of-the-two", body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(401);
  });

  // `resolveAllSharedSecrets` must silently drop bindings that fail to resolve
  // to a usable string so a single broken per-consumer entry doesn't take the
  // whole handler down (issue #189). Exercises three code paths at once:
  //  - `resolveSecretBinding` final `return null` (object without `.get`)
  //  - `resolveSecretBinding` catch branch (`.get()` rejects)
  //  - `resolveAllSharedSecrets` loop's `if (value)` false branch (both above)
  it("ignores INTERNAL_SHARED_SECRET_* bindings that fail to resolve (no .get / .get throws)", async () => {
    const { env, kv } = envWithKv({
      INTERNAL_SHARED_SECRET_BROKEN: { foo: 1 },
      INTERNAL_SHARED_SECRET_THROWS: {
        get: () => Promise.reject(new Error("kv unavailable")),
      },
    } as unknown as Partial<Env>);
    const jwt = await makeValidJwt("alice");
    const enc = await encryptWithKey("gh_test_token", TEST_SSO_KEY);
    kv._data["github_token:github:alice"] = enc;
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: jwt }) }),
      env,
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as { active: boolean }).active).toBe(true);
  });
});

describe("POST /mcp/introspect — body parsing", () => {
  it("returns active:false when body is not JSON", async () => {
    const { env } = envWithKv();
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: "not-json{" }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { active: boolean };
    expect(body.active).toBe(false);
  });

  it("returns active:false when token field missing", async () => {
    const { env } = envWithKv();
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({}) }),
      env,
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });

  it("returns active:false when token is not a string", async () => {
    const { env } = envWithKv();
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: 123 }) }),
      env,
    );
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });

  it("returns active:false when token is empty string", async () => {
    const { env } = envWithKv();
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: "" }) }),
      env,
    );
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });
});

describe("POST /mcp/introspect — JWT verification", () => {
  it("returns active:false for invalid JWT (wrong signature)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: "a.b.c" }) }),
      env,
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });

  it("returns active:false for expired JWT", async () => {
    const { env } = envWithKv();
    const expired = await signMcpJwt(
      { sub: "github:alice", github_login: "alice", scope: "", aud: AUD },
      TEST_MCP_JWT_SECRET,
      -10,
    );
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: expired }) }),
      env,
    );
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });
});

describe("POST /mcp/introspect — Bearer JWT auth (mode 1)", () => {
  it("returns active:true when Authorization: Bearer <jwt> alone (no body token)", async () => {
    const { env, kv } = envWithKv();
    const jwt = await makeValidJwt("yhonda-ohishi", "read:user");
    const encrypted = await encryptWithKey("gho_real_token", TEST_SSO_KEY);
    kv._data["github_token:github:yhonda-ohishi"] = encrypted;

    const res = await handleMcpIntrospect(
      // body 無しでも Bearer JWT だけで認証 + introspect が成立
      req({ auth: `Bearer ${jwt}`, body: null }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as {
      active: boolean;
      github_login: string;
      github_token: string;
    };
    expect(body.active).toBe(true);
    expect(body.github_login).toBe("yhonda-ohishi");
    expect(body.github_token).toBe("gho_real_token");
  });

  it("Bearer JWT header takes precedence over body.token even if mismatched", async () => {
    const { env, kv } = envWithKv();
    const aliceJwt = await makeValidJwt("alice");
    const bobJwt = await makeValidJwt("bob");
    const aliceEncrypted = await encryptWithKey("gho_alice", TEST_SSO_KEY);
    kv._data["github_token:github:alice"] = aliceEncrypted;

    const res = await handleMcpIntrospect(
      // header は alice の JWT、body は bob の JWT — header を採用
      req({ auth: `Bearer ${aliceJwt}`, body: JSON.stringify({ token: bobJwt }) }),
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { active: boolean; github_login: string };
    expect(body.active).toBe(true);
    expect(body.github_login).toBe("alice");
  });

  it("returns 401 when Bearer JWT signature is invalid (no fallback to shared secret)", async () => {
    const { env } = envWithKv();
    const res = await handleMcpIntrospect(
      req({ auth: "Bearer a.b.c", body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns 401 when Bearer JWT is expired", async () => {
    const { env } = envWithKv();
    const expired = await signMcpJwt(
      { sub: "github:alice", github_login: "alice", scope: "", aud: AUD },
      TEST_MCP_JWT_SECRET,
      -10,
    );
    const res = await handleMcpIntrospect(
      req({ auth: `Bearer ${expired}` }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("returns active:false (not 401) when Bearer JWT valid but no KV record", async () => {
    const { env } = envWithKv();
    const jwt = await makeValidJwt("noone");
    const res = await handleMcpIntrospect(
      req({ auth: `Bearer ${jwt}` }),
      env,
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });
});

describe("POST /mcp/introspect — URL aud allowlist (Refs ippoan/secrets-inventory#43)", () => {
  it("accepts URL aud matching an entry in MCP_RESOURCE_ORIGINS_ALLOWLIST", async () => {
    const { env, kv } = envWithKv({
      MCP_RESOURCE_ORIGINS_ALLOWLIST: "https://security-inventory.ippoan.org",
    } as unknown as Partial<Env>);
    const jwt = await signMcpJwt(
      {
        sub: "github:alice",
        github_login: "alice",
        scope: "mcp.read",
        aud: "https://security-inventory.ippoan.org/mcp",
      },
      TEST_MCP_JWT_SECRET,
      3600,
    );
    const encrypted = await encryptWithKey("gho_inv_token", TEST_SSO_KEY);
    kv._data["github_token:github:alice"] = encrypted;

    const res = await handleMcpIntrospect(req({ auth: `Bearer ${jwt}` }), env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { active: boolean; github_token: string };
    expect(body.active).toBe(true);
    expect(body.github_token).toBe("gho_inv_token");
  });

  it("rejects URL aud whose origin is NOT in MCP_RESOURCE_ORIGINS_ALLOWLIST", async () => {
    const { env } = envWithKv({
      MCP_RESOURCE_ORIGINS_ALLOWLIST: "https://security-inventory.ippoan.org",
    } as unknown as Partial<Env>);
    const jwt = await signMcpJwt(
      {
        sub: "github:alice",
        github_login: "alice",
        scope: "",
        aud: "https://evil.example/mcp",
      },
      TEST_MCP_JWT_SECRET,
      3600,
    );
    const res = await handleMcpIntrospect(req({ auth: `Bearer ${jwt}` }), env);
    expect(res.status).toBe(401);
  });

  it("still accepts the legacy literal aud 'github-mcp-server-rs' (regression guard)", async () => {
    const { env, kv } = envWithKv();
    const jwt = await makeValidJwt("alice");
    const encrypted = await encryptWithKey("gho_legacy", TEST_SSO_KEY);
    kv._data["github_token:github:alice"] = encrypted;
    const res = await handleMcpIntrospect(req({ auth: `Bearer ${jwt}` }), env);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { active: boolean }).active).toBe(true);
  });

  // ippoan/mcp-relay-rs#23: ref-files-mcp-server-rs aud JWT が
  // `pair-grant-via-oat` で mint されるのに `/mcp/introspect` で 401 になっていた
  // 片肺問題の regression。default literal allowlist に両 aud が入っている
  // ことを保証する。
  it("accepts the literal aud 'ref-files-mcp-server-rs' from default allowlist (mcp-relay-rs#23)", async () => {
    const { env, kv } = envWithKv();
    const jwt = await signMcpJwt(
      {
        sub: "github:alice",
        github_login: "alice",
        scope: "mcp.read mcp.write",
        aud: "ref-files-mcp-server-rs",
      },
      TEST_MCP_JWT_SECRET,
      3600,
    );
    const encrypted = await encryptWithKey("gho_ref_files", TEST_SSO_KEY);
    kv._data["github_token:github:alice"] = encrypted;
    const res = await handleMcpIntrospect(req({ auth: `Bearer ${jwt}` }), env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { active: boolean; github_token: string };
    expect(body.active).toBe(true);
    expect(body.github_token).toBe("gho_ref_files");
  });

  it("MCP_JWT_AUDIENCE_ALLOWLIST env overrides the default literal allowlist", async () => {
    const { env, kv } = envWithKv({
      MCP_JWT_AUDIENCE_ALLOWLIST: "future-binary-rs",
    } as unknown as Partial<Env>);
    const encrypted = await encryptWithKey("gho_future", TEST_SSO_KEY);
    kv._data["github_token:github:alice"] = encrypted;

    // future-binary-rs (env で許可された literal) は 200
    const allowed = await signMcpJwt(
      { sub: "github:alice", github_login: "alice", scope: "", aud: "future-binary-rs" },
      TEST_MCP_JWT_SECRET,
      3600,
    );
    const res1 = await handleMcpIntrospect(req({ auth: `Bearer ${allowed}` }), env);
    expect(res1.status).toBe(200);

    // env override 下では default の github-mcp-server-rs literal は弾かれる
    const denied = await signMcpJwt(
      { sub: "github:alice", github_login: "alice", scope: "", aud: "github-mcp-server-rs" },
      TEST_MCP_JWT_SECRET,
      3600,
    );
    const res2 = await handleMcpIntrospect(req({ auth: `Bearer ${denied}` }), env);
    expect(res2.status).toBe(401);
  });

  it("rejects non-URL non-legacy aud (`new URL(...)` throws → predicate returns false)", async () => {
    const { env } = envWithKv();
    const jwt = await signMcpJwt(
      {
        sub: "github:alice",
        github_login: "alice",
        scope: "",
        aud: "not-a-url-not-the-legacy-literal",
      },
      TEST_MCP_JWT_SECRET,
      3600,
    );
    const res = await handleMcpIntrospect(req({ auth: `Bearer ${jwt}` }), env);
    expect(res.status).toBe(401);
  });
});

describe("POST /mcp/introspect — github_token recovery", () => {
  it("returns active:false when github_token:{sub} missing from KV", async () => {
    const { env } = envWithKv();
    const jwt = await makeValidJwt("alice");
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: jwt }) }),
      env,
    );
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });

  it("returns active:false when decrypt fails (wrong key in KV)", async () => {
    const { env, kv } = envWithKv();
    const jwt = await makeValidJwt("alice");
    // poison KV: encrypted with a *different* key
    const poisoned = await encryptWithKey("gho_real_token", "different-key-material-junk!");
    kv._data["github_token:github:alice"] = poisoned;
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: jwt }) }),
      env,
    );
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });

  it("returns active:true + claims + decrypted github_token on success", async () => {
    const { env, kv } = envWithKv();
    const jwt = await makeValidJwt("yhonda-ohishi", "read:user");
    const encrypted = await encryptWithKey("gho_real_github_token", TEST_SSO_KEY);
    kv._data["github_token:github:yhonda-ohishi"] = encrypted;

    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: jwt }) }),
      env,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = await res.json() as {
      active: boolean;
      scope: string;
      sub: string;
      github_login: string;
      github_token: string;
      exp: number;
    };
    expect(body.active).toBe(true);
    expect(body.scope).toBe("read:user");
    expect(body.sub).toBe("github:yhonda-ohishi");
    expect(body.github_login).toBe("yhonda-ohishi");
    expect(body.github_token).toBe("gho_real_github_token");
    expect(typeof body.exp).toBe("number");
  });
});

// MCP OAuth に Google IdP を追加: sub が `google:` prefix の JWT は github_token
// KV lookup を skip し、email だけを積んで active:true を返す。
describe("POST /mcp/introspect — Google IdP flow (sub prefix google:)", () => {
  async function makeGoogleJwt(email = "alice@example.com", scope = "mcp.read"): Promise<string> {
    return signMcpJwt(
      { sub: `google:${email}`, email, scope, aud: AUD },
      TEST_MCP_JWT_SECRET,
      3600,
    );
  }

  it("returns active:true with email and WITHOUT touching KV (no github_token stored for google sub)", async () => {
    const { env, kv } = envWithKv();
    const jwt = await makeGoogleJwt("alice@example.com", "mcp.read");
    // github_token:{sub} を意図的に置かない — KV lookup が発生したら active:false になるはず。
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: jwt }) }),
      env,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = (await res.json()) as {
      active: boolean;
      scope: string;
      sub: string;
      email: string;
      github_login?: string;
      github_token?: string;
      exp: number;
    };
    expect(body.active).toBe(true);
    expect(body.scope).toBe("mcp.read");
    expect(body.sub).toBe("google:alice@example.com");
    expect(body.email).toBe("alice@example.com");
    expect(body.github_login).toBeUndefined();
    expect(body.github_token).toBeUndefined();
    expect(typeof body.exp).toBe("number");
    // KV に github_token:google:* が書かれていないこと (そもそも lookup していない証拠)
    expect(Object.keys(kv._data).some((k) => k.startsWith("github_token:google:"))).toBe(false);
  });

  it("works via Bearer JWT auth (mode 1) too", async () => {
    const { env } = envWithKv();
    const jwt = await makeGoogleJwt("bob@example.com");
    const res = await handleMcpIntrospect(req({ auth: `Bearer ${jwt}` }), env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { active: boolean; sub: string; email: string };
    expect(body.active).toBe(true);
    expect(body.sub).toBe("google:bob@example.com");
    expect(body.email).toBe("bob@example.com");
  });

  it("SSO_ENCRYPTION_KEY missing does not affect the google flow (no decrypt needed)", async () => {
    const { env } = envWithKv({ SSO_ENCRYPTION_KEY: "still-set-but-unused" });
    const jwt = await makeGoogleJwt("carol@example.com");
    const res = await handleMcpIntrospect(req({ auth: `Bearer ${jwt}` }), env);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { active: boolean }).active).toBe(true);
  });
});

// `INTERNAL_SHARED_SECRET` can be either a plain string (legacy `wrangler
// secret put`, still used by these mock-env fixtures) or a Secrets Store
// binding (`{ get(): Promise<string> }`). The handler unwraps both through
// `resolveSecretBinding` (via `resolveAllSharedSecrets`); cover the
// object-shaped branch here so the dual-mode helper stays at 100% line +
// branch coverage.
describe("POST /mcp/introspect — Secrets Store binding (dual-mode)", () => {
  it("unwraps a SecretsStoreSecret-shaped binding via async .get()", async () => {
    const binding = {
      get: async () => TEST_INTERNAL_SECRET,
    } as unknown as SecretsStoreSecret;
    const { env, kv } = envWithKv({ INTERNAL_SHARED_SECRET: binding });
    const jwt = await makeValidJwt("alice", "read:user");
    const encrypted = await encryptWithKey("gho_via_store", TEST_SSO_KEY);
    kv._data["github_token:github:alice"] = encrypted;

    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: jwt }) }),
      env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { active: boolean; github_token: string };
    expect(body.active).toBe(true);
    expect(body.github_token).toBe("gho_via_store");
  });

  it("returns 503 when the SecretsStoreSecret binding's .get() throws", async () => {
    const binding = {
      get: async () => {
        throw new Error("secrets store unavailable");
      },
    } as unknown as SecretsStoreSecret;
    const { env } = envWithKv({ INTERNAL_SHARED_SECRET: binding });
    const res = await handleMcpIntrospect(
      req({ auth: TEST_INTERNAL_SECRET, body: JSON.stringify({ token: "x" }) }),
      env,
    );
    expect(res.status).toBe(503);
    expect(((await res.json()) as { active: boolean }).active).toBe(false);
  });
});
