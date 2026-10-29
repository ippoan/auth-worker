/**
 * ログインの内部口 8 本の行き先の切り替え (Refs ohishi-exp/rust-leave-worker#1)。
 * `ALC_AUTH_LOGIN=1` + `ALC_AUTH` + `INTERNAL_SHARED_SECRET` → alc-auth-worker (`/internal/auth/...`)、
 * それ以外 → 404 で fail-closed (Cloud Run への退避は撤去済み、fetch は一切しない)。
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import {
  findUserByLineId,
  recipientsByLineId,
  registerLineRecipient,
  resolveSsoConfig,
  saveRefreshToken,
  upsertGoogleUser,
  upsertLineUser,
  upsertLineworksUser,
} from "../../src/lib/alc-internal";
import { createFakeAlcAuth, FAKE_ALC_AUTH_SECRET, type FakeAlcAuth } from "../helpers/fake-alc-auth";
import type { Env } from "../../src/index";

const USER = {
  id: "u-1",
  tenant_id: "t-1",
  email: "a@example.com",
  name: "A",
  role: "admin",
  google_sub: null,
  lineworks_id: null,
  line_user_id: null,
  slug: null,
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

/** 8 口それぞれの呼び方・期待する path・method・body・正常応答と戻り値。 */
const CASES: Array<{
  name: string;
  call: (env: Env) => Promise<unknown>;
  path: string;
  method: "GET" | "POST";
  body?: unknown;
  ok: () => Response;
  expected: unknown;
}> = [
  {
    name: "sso-config",
    call: (env) => resolveSsoConfig(env, "google", "example.com"),
    path: "/internal/auth/sso-config?provider=google&domain=example.com",
    method: "GET",
    ok: () => json(200, { tenant_id: "t-1" }),
    expected: { tenant_id: "t-1" },
  },
  {
    name: "upsert-lineworks",
    call: (env) =>
      upsertLineworksUser(env, { tenant_id: "t-1", lineworks_id: "lw-1", email: "a@example.com", name: "A" }),
    path: "/internal/auth/users/upsert-lineworks",
    method: "POST",
    body: { tenant_id: "t-1", lineworks_id: "lw-1", email: "a@example.com", name: "A" },
    ok: () => json(200, USER),
    expected: USER,
  },
  {
    name: "refresh-token",
    call: (env) => saveRefreshToken(env, { user_id: "u-1", refresh_hash: "h", expires_at: "2026-10-13T00:00:00Z" }),
    path: "/internal/auth/refresh-token",
    method: "POST",
    body: { user_id: "u-1", refresh_hash: "h", expires_at: "2026-10-13T00:00:00Z" },
    ok: () => new Response(null, { status: 204 }),
    expected: undefined,
  },
  {
    name: "users/by-line-id",
    call: (env) => findUserByLineId(env, "U 1"),
    path: "/internal/auth/users/by-line-id?line_user_id=U%201",
    method: "GET",
    ok: () => json(200, USER),
    expected: USER,
  },
  {
    name: "upsert-google",
    call: (env) => upsertGoogleUser(env, { google_sub: "g-1", email: "a@example.com", name: "A" }),
    path: "/internal/auth/users/upsert-google",
    method: "POST",
    body: { google_sub: "g-1", email: "a@example.com", name: "A" },
    ok: () => json(200, USER),
    expected: USER,
  },
  {
    name: "upsert-line",
    call: (env) => upsertLineUser(env, { tenant_id: "t-1", line_user_id: "U1", name: "A" }),
    path: "/internal/auth/users/upsert-line",
    method: "POST",
    body: { tenant_id: "t-1", line_user_id: "U1", name: "A" },
    ok: () => json(200, USER),
    expected: USER,
  },
  {
    name: "recipients/register-line",
    call: (env) => registerLineRecipient(env, { tenant_id: "t-1", name: "A", line_user_id: "U1" }),
    path: "/internal/auth/recipients/register-line",
    method: "POST",
    body: { tenant_id: "t-1", name: "A", line_user_id: "U1" },
    ok: () => new Response(null, { status: 204 }),
    expected: undefined,
  },
  {
    name: "recipients/by-line-id",
    call: (env) => recipientsByLineId(env, "U1"),
    path: "/internal/auth/recipients/by-line-id?line_user_id=U1",
    method: "GET",
    ok: () => json(200, [{ tenant_id: "t-1", name: "A" }]),
    expected: [{ tenant_id: "t-1", name: "A" }],
  },
];

function env(overrides: Record<string, unknown> = {}): Env {
  return { JWT_SECRET: "s", WORKER_ENV: "staging", ...overrides } as unknown as Env;
}

/** 応答を `respond` で決める fake の ALC_AUTH と、それを持つ env。 */
function switched(respond: (req: Request) => Response): { env: Env; alcAuth: FakeAlcAuth } {
  const alcAuth = createFakeAlcAuth({ override: respond });
  return {
    alcAuth,
    env: env({ ALC_AUTH_LOGIN: "1", ALC_AUTH: alcAuth.fetcher, INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET }),
  };
}

let cloudRun: ReturnType<typeof vi.fn>;

beforeEach(() => {
  cloudRun = vi.fn(async () => new Response("cloud run should not be called", { status: 599 }));
  vi.stubGlobal("fetch", cloudRun);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe.each(CASES)("$name", (c) => {
  it("スイッチ有り → ALC_AUTH を /internal/auth/... で共有 secret 付きで呼ぶ (fetch は呼ばない)", async () => {
    const { env: e, alcAuth } = switched(() => c.ok());
    await expect(c.call(e)).resolves.toEqual(c.expected);
    expect(cloudRun).not.toHaveBeenCalled();
    expect(alcAuth.calls).toHaveLength(1);
    const call = alcAuth.calls[0]!;
    expect(call.url).toBe(`https://alc-auth${c.path}`);
    expect(call.method).toBe(c.method);
    expect(call.headers.get("X-Internal-Shared-Secret")).toBe(FAKE_ALC_AUTH_SECRET);
    expect(call.headers.get("Authorization")).toBeNull();
    if (c.body === undefined) {
      expect(call.body).toBe("");
      expect(call.headers.get("Content-Type")).toBeNull();
    } else {
      expect(JSON.parse(call.body)).toEqual(c.body);
      expect(call.headers.get("Content-Type")).toBe("application/json");
    }
  });

  it("スイッチ有りでも 500 は throw", async () => {
    const { env: e } = switched(() => json(500, { error: "internal_error" }));
    await expect(c.call(e)).rejects.toThrow(/failed: 500/);
  });

  it("スイッチ無し → ALC_AUTH も fetch も呼ばず 404 で throw (fail-closed)", async () => {
    const alcAuth = createFakeAlcAuth({ override: () => c.ok() });
    await expect(
      c.call(env({ ALC_AUTH: alcAuth.fetcher, INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET })),
    ).rejects.toThrow(/failed: 404/);
    expect(alcAuth.calls).toHaveLength(0);
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("スイッチ有りでも binding か secret が欠けたら 404 で fail-closed", () => {
  it.each([
    ["ALC_AUTH 無し", { ALC_AUTH_LOGIN: "1", INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET }],
    ["INTERNAL_SHARED_SECRET 無し", { ALC_AUTH_LOGIN: "1", ALC_AUTH: createFakeAlcAuth().fetcher }],
  ])("%s", async (_label, overrides) => {
    await expect(findUserByLineId(env(overrides), "U1")).rejects.toThrow(/by-line-id failed: 404/);
    expect(cloudRun).not.toHaveBeenCalled();
  });

  it("ALC_AUTH_LOGIN が 1 以外は ALC_AUTH を呼ばず 404", async () => {
    const alcAuth = createFakeAlcAuth();
    await expect(
      findUserByLineId(
        env({ ALC_AUTH_LOGIN: "true", ALC_AUTH: alcAuth.fetcher, INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET }),
        "U1",
      ),
    ).rejects.toThrow(/by-line-id failed: 404/);
    expect(alcAuth.calls).toHaveLength(0);
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("sso-config の 404", () => {
  it("alc-auth-worker の sso_config_not_found は null", async () => {
    const { env: e } = switched(() => json(404, { error: "sso_config_not_found" }));
    await expect(resolveSsoConfig(e, "google", "example.com")).resolves.toBeNull();
  });

  it("alc-auth-worker の本文空の 404 (共有 secret の不一致) は throw", async () => {
    const { env: e } = switched(() => new Response(null, { status: 404 }));
    await expect(resolveSsoConfig(e, "google", "example.com")).rejects.toThrow(/sso-config failed: 404/);
  });

  it("alc-auth-worker の別の error の 404 も throw", async () => {
    const { env: e } = switched(() => json(404, { error: "not_found" }));
    await expect(resolveSsoConfig(e, "google", "example.com")).rejects.toThrow(/sso-config failed: 404/);
  });

  it("共有 secret が違えば fake は本文空の 404 → throw (実物と同じ形)", async () => {
    const alcAuth = createFakeAlcAuth({ secret: "other" });
    const e = env({ ALC_AUTH_LOGIN: "1", ALC_AUTH: alcAuth.fetcher, INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET });
    await expect(resolveSsoConfig(e, "google", "example.com")).rejects.toThrow(/sso-config failed: 404/);
  });

  it("スイッチ無しの 404 (fail-closed) は「設定なし」の null にせず throw", async () => {
    await expect(resolveSsoConfig(env(), "google", "example.com")).rejects.toThrow(/sso-config failed: 404/);
    expect(cloudRun).not.toHaveBeenCalled();
  });
});

describe("alc-auth-worker の応答の読み方 (今の呼び手のまま)", () => {
  it("by-line-id の 200 null は null (無し)", async () => {
    const { env: e } = switched(() => json(200, null));
    await expect(findUserByLineId(e, "U1")).resolves.toBeNull();
  });

  it("upsert-google の 403 no_tenant_for_email は null", async () => {
    const { env: e } = switched(() => json(403, { error: "no_tenant_for_email" }));
    await expect(upsertGoogleUser(e, { google_sub: "g", email: "a@example.com", name: "A" })).resolves.toBeNull();
  });

  it("不正な入力の 400 は throw", async () => {
    const { env: e } = switched(() => json(400, { error: "invalid_body" }));
    await expect(upsertLineUser(e, { tenant_id: "t", line_user_id: "U", name: "A" })).rejects.toThrow(/failed: 400/);
  });
});
