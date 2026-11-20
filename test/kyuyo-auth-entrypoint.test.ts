import { describe, it, expect } from "vitest";
import { createMockEnv, createMockKV, TEST_JWT_SECRET } from "./helpers/mock-env";
import { signTestJwt } from "./helpers/test-jwt";
import type { Env } from "../src/index";
import { KyuyoAuthEntrypoint } from "../src/kyuyo-auth-entrypoint";
import { signMcpJwt, type McpJwtPayload } from "../src/lib/mcp-jwt";

/** テスト固有のダミー値 (本番の値ではない)。 */
const TENANT = "11111111-1111-1111-1111-111111111111";
const OTHER_TENANT = "22222222-2222-2222-2222-222222222222";
const ALLOWED = JSON.stringify(["a@example.com", "b@example.com"]);
const KYUYO_ORIGIN = "https://dtako.ippoan.org";

function env(kv: Record<string, string> = { "kyuyo-allowed-emails": ALLOWED }, overrides: Partial<Env> = {}): Env {
  return createMockEnv({ AUTH_CONFIG: createMockKV(kv), ...overrides });
}

/** `[[services]] entrypoint = "KyuyoAuthEntrypoint"` 越しの呼び出しを再現する。 */
function rpc(e: Env = env()): KyuyoAuthEntrypoint {
  return new KyuyoAuthEntrypoint({} as unknown as ExecutionContext, e);
}

async function jwt(payload: Record<string, unknown> = {}, secret = TEST_JWT_SECRET): Promise<string> {
  return signTestJwt(
    {
      env: "prod",
      tenant_id: TENANT,
      email: "a@example.com",
      role: "viewer",
      sub: "google:1",
      exp: Math.floor(Date.now() / 1000) + 3600,
      ...payload,
    },
    secret,
  );
}

async function authorize(token: string, e?: Env) {
  const out = await rpc(e).authorize(token);
  expect(out.contentType).toBe("application/json");
  return { status: out.status, body: JSON.parse(out.body) as Record<string, unknown> };
}

describe("KyuyoAuthEntrypoint#authorize (ohishi-exp/rust-ichibanboshi#322) — 許可", () => {
  it("200: 一覧にある email", async () => {
    expect(await authorize(await jwt())).toEqual({
      status: 200,
      body: { allowed: true, email: "a@example.com" },
    });
  });

  it("200: 大文字小文字・前後空白が違っても一致し、email は小文字化して返す", async () => {
    const e = env({ "kyuyo-allowed-emails": JSON.stringify(["  B@Example.COM "]) });
    expect(await authorize(await jwt({ email: " b@EXAMPLE.com  " }), e)).toEqual({
      status: 200,
      body: { allowed: true, email: "b@example.com" },
    });
  });

  it("200: org ACL (app-orgs + TENANT_ACL) を通るテナントなら許可 (下の 401 の陽性対照)", async () => {
    const e = env(
      { "kyuyo-allowed-emails": ALLOWED, "app-orgs": JSON.stringify({ dtako: "ohishi-exp" }) },
      { TENANT_ACL: JSON.stringify({ "ohishi-exp": [TENANT] }) },
    );
    expect((await authorize(await jwt(), e)).status).toBe(200);
  });

  it("一覧から外すと即座に 403 (キャッシュしない読み)", async () => {
    const kv = createMockKV({ "kyuyo-allowed-emails": ALLOWED });
    const e = createMockEnv({ AUTH_CONFIG: kv });
    const token = await jwt();
    expect((await authorize(token, e)).status).toBe(200);
    await kv.put("kyuyo-allowed-emails", JSON.stringify(["b@example.com"]));
    expect((await authorize(token, e)).status).toBe(403);
  });
});

describe("KyuyoAuthEntrypoint#authorize — 403", () => {
  it("一覧に無い email", async () => {
    expect(await authorize(await jwt({ email: "c@example.com" }))).toEqual({
      status: 403,
      body: { error: "forbidden" },
    });
  });

  it("email claim が無い", async () => {
    expect((await authorize(await jwt({ email: undefined }))).status).toBe(403);
  });
});

describe("KyuyoAuthEntrypoint#authorize — 401", () => {
  const unauthorized = { status: 401, body: { error: "unauthorized" } };

  it("空 token", async () => {
    expect(await authorize("")).toEqual(unauthorized);
  });

  it("string 以外の token", async () => {
    expect(await authorize(undefined as unknown as string)).toEqual(unauthorized);
  });

  it("署名不正", async () => {
    expect(await authorize(await jwt({}, "another-secret-32chars-padding!!"))).toEqual(unauthorized);
  });

  it("exp 切れ", async () => {
    expect(await authorize(await jwt({ exp: Math.floor(Date.now() / 1000) - 10 }))).toEqual(unauthorized);
  });

  it("env claim 不一致 (staging の token)", async () => {
    expect(await authorize(await jwt({ env: "staging" }))).toEqual(unauthorized);
  });

  it("org ACL で弾かれるテナント", async () => {
    const e = env(
      { "kyuyo-allowed-emails": ALLOWED, "app-orgs": JSON.stringify({ dtako: "ohishi-exp" }) },
      { TENANT_ACL: JSON.stringify({ "ohishi-exp": [OTHER_TENANT] }) },
    );
    expect(await authorize(await jwt(), e)).toEqual(unauthorized);
  });

  it("APP_TENANT_ACL で dtako origin に許可されていないテナント", async () => {
    const e = env(undefined, {
      APP_TENANT_ACL: JSON.stringify({ apps: { [KYUYO_ORIGIN]: [OTHER_TENANT] } }),
    });
    expect(await authorize(await jwt(), e)).toEqual(unauthorized);
  });
});

describe("KyuyoAuthEntrypoint#authorize — 503 (fail-closed)", () => {
  const unset = { status: 503, body: { error: "kyuyo_allowlist_unset" } };

  it.each([
    ["キー無し", {}],
    ["空文字", { "kyuyo-allowed-emails": "" }],
    ["不正 JSON", { "kyuyo-allowed-emails": "[a@example.com" }],
    ["空配列", { "kyuyo-allowed-emails": "[]" }],
    ["配列でない", { "kyuyo-allowed-emails": JSON.stringify({ a: "a@example.com" }) }],
    ["string 以外の要素", { "kyuyo-allowed-emails": JSON.stringify(["a@example.com", 1]) }],
    ["空白だけの要素", { "kyuyo-allowed-emails": JSON.stringify(["  "]) }],
  ])("%s", async (_label, kv: Record<string, string>) => {
    // 一覧に載っているはずの人の正当な token でも 503 (空の一覧で全員拒否にはしない)
    expect(await authorize(await jwt(), env(kv))).toEqual(unset);
  });

  it("JWT_SECRET 未設定は server_error", async () => {
    expect(await authorize(await jwt(), env(undefined, { JWT_SECRET: undefined }))).toEqual({
      status: 503,
      body: { error: "server_error" },
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// authorizeMcp (Refs #p414) — kyuyo-mcp の binding_jwt (MCP_JWT_SECRET) 用
// ─────────────────────────────────────────────────────────────────────────────

/** テスト固有のダミー値 (本番の値ではない)。 */
const TEST_MCP_JWT_SECRET = "test-mcp-jwt-secret-32chars!";
const MCP_ISS = "https://auth-staging.ippoan.org";
const MCP_AUD = "https://kyuyo-mcp.ippoan.org/mcp";

function mcpEnv(kv: Record<string, string> = { "kyuyo-allowed-emails": ALLOWED }, overrides: Partial<Env> = {}): Env {
  return env(kv, { MCP_JWT_SECRET: TEST_MCP_JWT_SECRET, ...overrides } as Partial<Env>);
}

async function mcpJwt(
  claims: Partial<Omit<McpJwtPayload, "exp" | "iat">> = {},
  { secret = TEST_MCP_JWT_SECRET, ttl = 3600 }: { secret?: string; ttl?: number } = {},
): Promise<string> {
  return signMcpJwt(
    { sub: "google:a@example.com", email: "a@example.com", scope: "mcp.read", aud: MCP_AUD, iss: MCP_ISS, ...claims },
    secret,
    ttl,
  );
}

async function authorizeMcp(token: string, e: Env = mcpEnv()) {
  const out = await rpc(e).authorizeMcp(token);
  expect(out.contentType).toBe("application/json");
  return { status: out.status, body: JSON.parse(out.body) as Record<string, unknown> };
}

describe("KyuyoAuthEntrypoint#authorizeMcp — 許可", () => {
  it("① 200: 正しい binding_jwt + 一覧にある email", async () => {
    expect(await authorizeMcp(await mcpJwt())).toEqual({
      status: 200,
      body: { allowed: true, email: "a@example.com" },
    });
  });

  it("200: aud が kyuyo-mcp の origin そのもの (path 無し) でも通る", async () => {
    expect((await authorizeMcp(await mcpJwt({ aud: "https://kyuyo-mcp.ippoan.org" }))).status).toBe(200);
  });

  it("200: email は前後空白・大文字小文字を正規化して照合し、小文字で返す", async () => {
    const e = mcpEnv({ "kyuyo-allowed-emails": JSON.stringify(["  B@Example.COM "]) });
    expect(await authorizeMcp(await mcpJwt({ email: " b@EXAMPLE.com " }), e)).toEqual({
      status: 200,
      body: { allowed: true, email: "b@example.com" },
    });
  });

  it("tenant の origin ACL は当てない (authorize なら 401 になる設定でも 200)", async () => {
    const e = mcpEnv(
      { "kyuyo-allowed-emails": ALLOWED, "app-orgs": JSON.stringify({ dtako: "ohishi-exp" }) },
      {
        TENANT_ACL: JSON.stringify({ "ohishi-exp": [OTHER_TENANT] }),
        APP_TENANT_ACL: JSON.stringify({ apps: { [KYUYO_ORIGIN]: [OTHER_TENANT] } }),
      },
    );
    expect((await authorizeMcp(await mcpJwt(), e)).status).toBe(200);
  });
});

describe("KyuyoAuthEntrypoint#authorizeMcp — 403", () => {
  it("② 一覧に無い email", async () => {
    expect(await authorizeMcp(await mcpJwt({ sub: "google:c@example.com", email: "c@example.com" }))).toEqual({
      status: 403,
      body: { error: "forbidden" },
    });
  });

  it("一覧から外すと即座に 403 (キャッシュしない読み)", async () => {
    const kv = createMockKV({ "kyuyo-allowed-emails": ALLOWED });
    const e = createMockEnv({ AUTH_CONFIG: kv, MCP_JWT_SECRET: TEST_MCP_JWT_SECRET } as Partial<Env>);
    const token = await mcpJwt();
    expect((await authorizeMcp(token, e)).status).toBe(200);
    await kv.put("kyuyo-allowed-emails", JSON.stringify(["b@example.com"]));
    expect((await authorizeMcp(token, e)).status).toBe(403);
  });
});

describe("KyuyoAuthEntrypoint#authorizeMcp — 401", () => {
  const unauthorized = { status: 401, body: { error: "unauthorized" } };

  it("空 token", async () => {
    expect(await authorizeMcp("")).toEqual(unauthorized);
  });

  it("string 以外の token", async () => {
    expect(await authorizeMcp(undefined as unknown as string)).toEqual(unauthorized);
  });

  it("③ 署名不正 (別の鍵)", async () => {
    expect(await authorizeMcp(await mcpJwt({}, { secret: "another-mcp-secret-32chars-pad!!" }))).toEqual(unauthorized);
  });

  it("③ 期限切れ", async () => {
    expect(await authorizeMcp(await mcpJwt({}, { ttl: -10 }))).toEqual(unauthorized);
  });

  it.each([
    ["本番の auth-worker", "https://auth.ippoan.org"],
    ["知らない発行元", "https://evil.example.com"],
    ["末尾スラッシュ違い", "https://auth-staging.ippoan.org/"],
  ])("③ iss 違い: %s", async (_label, iss) => {
    expect(await authorizeMcp(await mcpJwt({ iss }))).toEqual(unauthorized);
  });

  it("③ iss の無い旧 token", async () => {
    expect(await authorizeMcp(await mcpJwt({ iss: undefined }))).toEqual(unauthorized);
  });

  it.each([
    ["他の MCP (gmail-mcp)", "https://gmail-mcp.ippoan.org/mcp"],
    ["host の接尾辞が似ているだけ", "https://kyuyo-mcp.ippoan.org.evil.example.com/mcp"],
    ["http", "http://kyuyo-mcp.ippoan.org/mcp"],
    ["URL でない literal (github-mcp-server-rs)", "github-mcp-server-rs"],
  ])("③ aud 違い: %s", async (_label, aud) => {
    expect(await authorizeMcp(await mcpJwt({ aud }))).toEqual(unauthorized);
  });

  it("GitHub flow の token (email 無し・sub が github:)", async () => {
    expect(
      await authorizeMcp(await mcpJwt({ sub: "github:someone", email: undefined, github_login: "someone" })),
    ).toEqual(unauthorized);
  });

  it("sub が google: でない (email はあっても)", async () => {
    expect(await authorizeMcp(await mcpJwt({ sub: "github:a" }))).toEqual(unauthorized);
  });

  it("④ ブラウザ JWT (JWT_SECRET 署名) は 401 — 鍵が同じでも claim が合わない", async () => {
    // 鍵を同じにしても、ブラウザ JWT には aud/iss が無いので通らない
    const same = mcpEnv(undefined, { MCP_JWT_SECRET: TEST_JWT_SECRET } as Partial<Env>);
    expect(await authorizeMcp(await jwt(), same)).toEqual(unauthorized);
    expect(await authorizeMcp(await jwt())).toEqual(unauthorized);
  });

  it("⑤ binding_jwt を既存 authorize に渡すと 401 のまま", async () => {
    const e = mcpEnv();
    expect((await authorizeMcp(await mcpJwt(), e)).status).toBe(200); // 陽性対照
    // authorize 側の分離は鍵の違いに拠る (本番でも JWT_SECRET と MCP_JWT_SECRET は
    // Secrets Store の別 entry)。authorize の判定はこの PR では変えない。
    expect(await authorize(await mcpJwt(), e)).toEqual(unauthorized);
  });
});

describe("KyuyoAuthEntrypoint#authorizeMcp — 503 (fail-closed)", () => {
  it("MCP_JWT_SECRET 未設定は server_error", async () => {
    expect(await authorizeMcp(await mcpJwt(), mcpEnv(undefined, { MCP_JWT_SECRET: undefined } as Partial<Env>))).toEqual({
      status: 503,
      body: { error: "server_error" },
    });
  });

  it.each([
    ["キー無し", {}],
    ["空配列", { "kyuyo-allowed-emails": "[]" }],
    ["不正 JSON", { "kyuyo-allowed-emails": "[a@example.com" }],
  ])("allowlist %s は kyuyo_allowlist_unset", async (_label, kv: Record<string, string>) => {
    expect(await authorizeMcp(await mcpJwt(), mcpEnv(kv))).toEqual({
      status: 503,
      body: { error: "kyuyo_allowlist_unset" },
    });
  });
});
