import { describe, it, expect } from "vitest";
import { createMockEnv, createMockKV, TEST_JWT_SECRET } from "./helpers/mock-env";
import { signTestJwt } from "./helpers/test-jwt";
import type { Env } from "../src/index";
import { KyuyoAuthEntrypoint } from "../src/kyuyo-auth-entrypoint";

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
