/**
 * `/api/sso/*` (SSO 設定) — alc-auth-worker (`ALC_AUTH`) の内部口を叩く (Refs ippoan/rust-alc-api#680)。
 * client secret はここで `SSO_ENCRYPTION_KEY` で暗号化し、alc-auth-worker には暗号文だけを渡す。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMockEnv, TEST_JWT_SECRET } from "../helpers/mock-env";
import { makeJwt, TEST_TENANT_ID } from "../helpers/live-env";
import { createFakeAlcAuth, FAKE_ALC_AUTH_SECRET, type FakeAlcAuth } from "../helpers/fake-alc-auth";
import { handleSsoList, handleSsoUpsert, handleSsoDelete } from "../../src/handlers/api-sso";
import { decryptWithKey } from "../../src/lib/mcp-crypto";
import type { Env } from "../../src/index";

const ROW = {
  provider: "lineworks",
  client_id: "cid",
  external_org_id: "org",
  enabled: true,
  woff_id: null,
  created_at: "2026-10-25T00:00:00Z",
  updated_at: "2026-10-25T00:00:01Z",
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function withAlcAuth(
  respond: (req: Request) => Response,
  extra: Partial<Env> = {},
): { env: Env; alcAuth: FakeAlcAuth } {
  const alcAuth = createFakeAlcAuth({ override: respond });
  return {
    alcAuth,
    env: createMockEnv({ ALC_AUTH: alcAuth.fetcher, INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET, ...extra }),
  };
}

function req(body?: unknown, token: string | null = makeJwt(TEST_JWT_SECRET)): Request {
  return new Request("https://auth.test.example/api/sso/x", {
    method: body === undefined ? "GET" : "POST",
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

const upsertBody = (extra: Record<string, unknown> = {}) => ({
  provider: "lineworks",
  clientId: "cid",
  clientSecret: "plain-secret",
  externalOrgId: "org",
  enabled: true,
  ...extra,
});

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response("cloud run should not be called", { status: 599 })));
});

describe("認可", () => {
  it("token 無しは 401・admin でなければ 403・書き込みは開発用の token なら 403", async () => {
    const { env, alcAuth } = withAlcAuth(() => json(200, { configs: [] }));
    expect((await handleSsoList(req(undefined, null), env)).status).toBe(401);
    expect((await handleSsoList(req(undefined, makeJwt(TEST_JWT_SECRET, { role: "viewer" })), env)).status).toBe(403);
    const dev = makeJwt(TEST_JWT_SECRET, { token_kind: "dev" });
    expect((await handleSsoUpsert(req(upsertBody(), dev), env)).status).toBe(403);
    expect((await handleSsoDelete(req({ provider: "lineworks" }, dev), env)).status).toBe(403);
    expect(alcAuth.calls).toHaveLength(0);
  });
});

describe("handleSsoList", () => {
  it("JWT の会社の設定を引き、画面の形 (camelCase、secret は持っている印だけ) にして返す", async () => {
    const { env, alcAuth } = withAlcAuth(() => json(200, { configs: [ROW] }));
    const res = await handleSsoList(req(), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      configs: [
        {
          provider: "lineworks",
          clientId: "cid",
          hasClientSecret: true,
          externalOrgId: "org",
          enabled: true,
          woffId: "",
          createdAt: ROW.created_at,
          updatedAt: ROW.updated_at,
        },
      ],
    });
    expect(new URL(alcAuth.calls[0]!.url).pathname).toBe(`/internal/tenants/${TEST_TENANT_ID}/sso-configs`);
  });

  it("alc-auth-worker の失敗は 502", async () => {
    const { env } = withAlcAuth(() => json(500, {}));
    expect((await handleSsoList(req(), env)).status).toBe(502);
  });
});

describe("handleSsoUpsert", () => {
  it("secret を SSO_ENCRYPTION_KEY で暗号化して PUT し、画面の形で返す (平文は送らない)", async () => {
    const { env, alcAuth } = withAlcAuth(() => json(200, { ...ROW, woff_id: "w" }));
    const res = await handleSsoUpsert(req(upsertBody({ woffId: "w" })), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      provider: "lineworks",
      clientId: "cid",
      hasClientSecret: true,
      externalOrgId: "org",
      woffId: "w",
      enabled: true,
    });
    const call = alcAuth.calls[0]!;
    expect(call.method).toBe("PUT");
    expect(new URL(call.url).pathname).toBe(`/internal/tenants/${TEST_TENANT_ID}/sso-configs/lineworks`);
    expect(call.body).not.toContain("plain-secret");
    const sent = JSON.parse(call.body) as Record<string, unknown>;
    expect(sent).toMatchObject({ client_id: "cid", external_org_id: "org", woff_id: "w", enabled: true });
    expect(await decryptWithKey(sent.client_secret_encrypted as string, "test-sso-encryption-key")).toBe(
      "plain-secret",
    );
  });

  it("空の secret は null で送る (変えない)。woffId・enabled の省略は null・true", async () => {
    const { env, alcAuth } = withAlcAuth(() => json(200, ROW));
    const res = await handleSsoUpsert(
      req({ provider: "lineworks", clientId: "cid", clientSecret: "", externalOrgId: "org" }),
      env,
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as { woffId: string }).woffId).toBe("");
    expect(JSON.parse(alcAuth.calls[0]!.body)).toEqual({
      client_id: "cid",
      client_secret_encrypted: null,
      external_org_id: "org",
      woff_id: null,
      enabled: true,
    });
  });

  it("必須が欠ければ 400 (alc-auth-worker を呼ばない)", async () => {
    const { env, alcAuth } = withAlcAuth(() => json(200, ROW));
    for (const k of ["provider", "clientId", "externalOrgId"]) {
      const res = await handleSsoUpsert(req(upsertBody({ [k]: "" })), env);
      expect(res.status).toBe(400);
    }
    expect(alcAuth.calls).toHaveLength(0);
  });

  it("SSO_ENCRYPTION_KEY が無ければ 500 (alc-auth-worker を呼ばない)", async () => {
    const { env, alcAuth } = withAlcAuth(() => json(200, ROW), { SSO_ENCRYPTION_KEY: undefined as never });
    const res = await handleSsoUpsert(req(upsertBody()), env);
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "sso_encryption_key_missing" });
    expect(alcAuth.calls).toHaveLength(0);
  });

  it("alc-auth-worker の 4xx (secret 無しの新規・他社と衝突) はそのまま返す", async () => {
    for (const [status, code] of [
      [400, "secret_required"],
      [409, "sso_config_conflict"],
    ] as const) {
      const { env } = withAlcAuth(() => json(status, { error: code }));
      const res = await handleSsoUpsert(req(upsertBody()), env);
      expect(res.status).toBe(status);
      expect(await res.json()).toEqual({ error: code });
    }
  });
});

describe("handleSsoDelete", () => {
  it("provider の設定を消し {success:true}", async () => {
    const { env, alcAuth } = withAlcAuth(() => new Response(null, { status: 204 }));
    const res = await handleSsoDelete(req({ provider: "lineworks" }), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true });
    expect(alcAuth.calls[0]!.method).toBe("DELETE");
    expect(new URL(alcAuth.calls[0]!.url).pathname).toBe(
      `/internal/tenants/${TEST_TENANT_ID}/sso-configs/lineworks`,
    );
  });

  it("provider 無しは 400、無い設定は 404 をそのまま返す", async () => {
    const { env, alcAuth } = withAlcAuth(() => json(404, { error: "sso_config_not_found" }));
    expect((await handleSsoDelete(req({}), env)).status).toBe(400);
    expect(alcAuth.calls).toHaveLength(0);
    const res = await handleSsoDelete(req({ provider: "lineworks" }), env);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "sso_config_not_found" });
  });
});
