import { describe, it, expect } from "vitest";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { FAKE_ALC_AUTH_SECRET, createFakeAlcAuth } from "../helpers/fake-alc-auth";
import { signTestJwt } from "../helpers/test-jwt";
import type { Env } from "../../src/index";
import {
  MACHINE_CRED_CORS_ORIGINS,
  handleMachineCredentials,
} from "../../src/handlers/api-machine-credentials";
import { createMachineCredential, verifyBasic } from "../../src/lib/machine-credential";

/** テスト固有のダミー UUID (本番の値ではない)。 */
const TENANT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const TENANT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const PURPOSE = "leave-scan";
const BASE = "https://auth.test.example/api/machine-credentials";
const LEAVE = "https://leave.ippoan.org";

function env(credEnv: string | null = "prod", overrides: Partial<Env> = {}): Env {
  return createMockEnv({
    ALC_AUTH: createFakeAlcAuth().fetcher,
    INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET,
    MACHINE_CRED_ENV: credEnv ?? undefined,
    WORKER_ENV: credEnv ?? "prod",
    ...overrides,
  });
}

async function jwt(claims: Record<string, unknown> = {}, secret = TEST_JWT_SECRET): Promise<string> {
  return signTestJwt({ sub: "u1", tenant_id: TENANT_A, role: "admin", ...claims }, secret);
}

function req(
  path: string,
  init: { method?: string; token?: string; body?: unknown; origin?: string; rawBody?: string } = {},
): Request {
  const headers: Record<string, string> = {};
  if (init.token) headers.Authorization = `Bearer ${init.token}`;
  if (init.origin) headers.Origin = init.origin;
  if (init.body !== undefined || init.rawBody !== undefined) headers["Content-Type"] = "application/json";
  return new Request(`${BASE}${path}`, {
    method: init.method ?? "GET",
    headers,
    body: init.rawBody ?? (init.body !== undefined ? JSON.stringify(init.body) : undefined),
  });
}

async function call(e: Env, r: Request): Promise<{ status: number; body: Record<string, unknown>; res: Response }> {
  const res = await handleMachineCredentials(r, e);
  const text = await res.text();
  return { status: res.status, body: text ? (JSON.parse(text) as Record<string, unknown>) : {}, res };
}

async function createVia(e: Env, token: string, label = "複合機") {
  return call(e, req("", { method: "POST", token, body: { purpose: PURPOSE, label } }));
}

describe("POST /api/machine-credentials (作成)", () => {
  it("admin は作成でき、password はこの応答だけ。tenant は JWT のもの", async () => {
    const e = env();
    const { status, body, res } = await createVia(e, await jwt(), "  1F 複合機 ");
    expect(status).toBe(201);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(body).toMatchObject({ purpose: PURPOSE, label: "1F 複合機" });
    const username = body.username as string;
    const password = body.password as string;
    expect(await verifyBasic(e, `Basic ${btoa(`${username}:${password}`)}`, PURPOSE)).toEqual({
      tenantId: TENANT_A,
      username,
    });
    // 一覧には password を出さない
    const list = await call(e, req("", { token: await jwt() }));
    expect(JSON.stringify(list.body)).not.toContain(password);
  });

  it("body の tenant は無視して JWT の tenant を使う", async () => {
    const e = env();
    const { body } = await call(
      e,
      req("", { method: "POST", token: await jwt(), body: { purpose: PURPOSE, label: "x", tenant_id: TENANT_B } }),
    );
    const v = await verifyBasic(e, `Basic ${btoa(`${body.username}:${body.password}`)}`, PURPOSE);
    expect(v?.tenantId).toBe(TENANT_A);
  });

  it("tenant_id が無ければ org を使う", async () => {
    const e = env();
    const { body } = await createVia(e, await jwt({ tenant_id: undefined, org: TENANT_B }));
    const v = await verifyBasic(e, `Basic ${btoa(`${body.username}:${body.password}`)}`, PURPOSE);
    expect(v?.tenantId).toBe(TENANT_B);
  });

  it.each<[string, { body?: unknown; rawBody?: string }, string]>([
    ["JSON でない", { rawBody: "{not json" }, "invalid_json"],
    ["purpose なし", { body: { label: "x" } }, "invalid_purpose"],
    ["purpose が allowlist 外", { body: { purpose: "other", label: "x" } }, "invalid_purpose"],
    ["label が文字列でない", { body: { purpose: PURPOSE, label: 1 } }, "invalid_label"],
    ["label が空", { body: { purpose: PURPOSE, label: "  " } }, "invalid_label"],
    ["body が null", { rawBody: "null" }, "invalid_purpose"],
  ])("%s → 400", async (_n, b, error) => {
    const { status, body } = await call(env(), req("", { method: "POST", token: await jwt(), ...b }));
    expect(status).toBe(400);
    expect(body.error).toBe(error);
  });
});

describe("認可", () => {
  it("★ 401 系は理由を区別しない (token なし / 署名違い / aud 付き / device role / tenant なし)", async () => {
    const e = env();
    const tokens = [
      undefined,
      await jwt({}, "another-secret-not-the-test-one"),
      await jwt({ aud: "device" }),
      await jwt({ role: "device-uploader" }),
      await jwt({ tenant_id: undefined }),
      await jwt({ env: "staging" }), // WORKER_ENV=prod に staging の token
    ];
    for (const token of tokens) {
      const { status, body } = await call(e, req("", { token }));
      expect(status).toBe(401);
      expect(body).toEqual({ error: "Unauthorized" });
    }
  });

  it("JWT_SECRET が無い → 401", async () => {
    const { status } = await call(env("prod", { JWT_SECRET: undefined }), req("", { token: await jwt() }));
    expect(status).toBe(401);
  });

  it("admin でない → 403 (role が無い token も)", async () => {
    for (const claims of [{ role: "member" }, { role: undefined }]) {
      const { status, body } = await call(env(), req("", { token: await jwt(claims) }));
      expect(status).toBe(403);
      expect(body.error).toBe("Forbidden");
    }
  });

  it("★ dev token: prod では GET だけ、書き込みは 403", async () => {
    const e = env("prod");
    const dev = await jwt({ token_kind: "dev" });
    expect((await call(e, req("", { token: dev }))).status).toBe(200);
    const created = await createVia(e, dev);
    expect(created.status).toBe(403);
    expect(created.body.error).toBe("dev_token_write_forbidden");
    const revoke = await call(e, req("/mc_0123456789abcdef/revoke", { method: "POST", token: dev }));
    expect(revoke.status).toBe(403);
  });

  it("★ dev token: staging では作成・失効できる", async () => {
    const e = env("staging");
    const dev = await jwt({ token_kind: "dev" });
    const created = await createVia(e, dev);
    expect(created.status).toBe(201);
    const revoke = await call(e, req(`/${created.body.username}/revoke`, { method: "POST", token: dev }));
    expect(revoke.status).toBe(200);
  });

  it("dev 以外の token_kind (device-key 等) は staging でも書けない", async () => {
    const created = await createVia(env("staging"), await jwt({ token_kind: "device-key" }));
    expect(created.status).toBe(403);
    expect(created.body.error).toBe("dev_token_write_forbidden");
  });

  it("MACHINE_CRED_ENV が無い環境は 503 (認可より前)", async () => {
    const { status, body } = await call(env(null), req("", { token: await jwt() }));
    expect(status).toBe(503);
    expect(body.error).toBe("machine_credentials_unavailable");
  });
});

describe("GET /api/machine-credentials (一覧)", () => {
  it("自 tenant の分だけ返す。purpose で絞れる", async () => {
    const e = env();
    await createMachineCredential(e, TENANT_A, PURPOSE, "A");
    await createMachineCredential(e, TENANT_B, PURPOSE, "B");
    const all = await call(e, req("", { token: await jwt() }));
    expect(all.status).toBe(200);
    const creds = all.body.credentials as { label: string }[];
    expect(creds.map((c) => c.label)).toEqual(["A"]);
    const filtered = await call(e, req(`?purpose=${PURPOSE}`, { token: await jwt() }));
    expect((filtered.body.credentials as unknown[]).length).toBe(1);
  });

  it("purpose が allowlist 外 → 400", async () => {
    const { status, body } = await call(env(), req("?purpose=other", { token: await jwt() }));
    expect(status).toBe(400);
    expect(body.error).toBe("invalid_purpose");
  });
});

describe("POST /api/machine-credentials/<username>/revoke", () => {
  it("自 tenant は失効でき、以後 Basic は通らない", async () => {
    const e = env();
    const c = await createMachineCredential(e, TENANT_A, PURPOSE, "A");
    const { status, body } = await call(e, req(`/${c!.username}/revoke`, { method: "POST", token: await jwt() }));
    expect(status).toBe(200);
    expect(body).toEqual({ revoked: true });
    expect(await verifyBasic(e, `Basic ${btoa(`${c!.username}:${c!.password}`)}`, PURPOSE)).toBeNull();
  });

  it("★ 他 tenant の資格情報は 404 (存在しないのと区別しない) で、有効なまま", async () => {
    const e = env();
    const c = await createMachineCredential(e, TENANT_B, PURPOSE, "B");
    const { status } = await call(e, req(`/${c!.username}/revoke`, { method: "POST", token: await jwt() }));
    expect(status).toBe(404);
    expect(await verifyBasic(e, `Basic ${btoa(`${c!.username}:${c!.password}`)}`, PURPOSE)).not.toBeNull();
    const missing = await call(e, req("/mc_aaaaaaaaaaaaaaaa/revoke", { method: "POST", token: await jwt() }));
    expect(missing.status).toBe(404);
  });
});

describe("path / method", () => {
  it("知らない下位 path → 404、許されない method → 405", async () => {
    const e = env();
    const token = await jwt();
    expect((await call(e, req("/mc_0123456789abcdef", { token }))).status).toBe(404);
    expect((await call(e, req("/x/revoke/extra", { method: "POST", token }))).status).toBe(404);
    expect((await call(e, req("", { method: "DELETE", token }))).status).toBe(405);
    expect((await call(e, req("/mc_0123456789abcdef/revoke", { token }))).status).toBe(405);
  });
});

describe("CORS", () => {
  it.each(MACHINE_CRED_CORS_ORIGINS)("%s は Origin をそのまま返す (preflight と本応答)", async (origin) => {
    const pre = await handleMachineCredentials(req("", { method: "OPTIONS", origin }), env());
    expect(pre.status).toBe(204);
    expect(pre.headers.get("Access-Control-Allow-Origin")).toBe(origin);
    expect(pre.headers.get("Access-Control-Allow-Headers")).toBe("Authorization, Content-Type");
    expect(pre.headers.get("Access-Control-Allow-Methods")).toBe("GET, POST, OPTIONS");
    expect(pre.headers.get("Vary")).toBe("Origin");
    const res = await handleMachineCredentials(req("", { origin, token: await jwt() }), env());
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(origin);
  });

  it("許可外の Origin・Origin なしには CORS ヘッダを付けない", async () => {
    for (const origin of ["https://evil.example", undefined]) {
      const pre = await handleMachineCredentials(req("", { method: "OPTIONS", origin }), env());
      expect(pre.headers.get("Access-Control-Allow-Origin")).toBeNull();
      const res = await handleMachineCredentials(req("", { origin, token: await jwt() }), env());
      expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
    }
  });

  it("エラー応答にも許可 Origin の CORS ヘッダが付く (画面がエラーを読めるように)", async () => {
    const res = await handleMachineCredentials(req("", { origin: LEAVE }), env());
    expect(res.status).toBe(401);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(LEAVE);
  });
});
