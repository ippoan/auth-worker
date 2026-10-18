import { describe, it, expect } from "vitest";
import {
  MACHINE_CRED_LABEL_MAX,
  MACHINE_CRED_PURPOSES,
  createMachineCredential,
  getActiveMachineCredential,
  isMachineCredPurpose,
  listMachineCredentials,
  machineCredEnvName,
  revokeMachineCredential,
  rotateMachineCredential,
  verifyBasic,
  type MachineCredEnv,
} from "../../src/lib/machine-credential";
import { sha256Hex } from "../../src/lib/device";
import { FAKE_ALC_AUTH_SECRET, createFakeAlcAuth, type FakeAlcAuth } from "../helpers/fake-alc-auth";

/** テスト固有のダミー UUID (本番の値ではない)。 */
const TENANT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const TENANT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const PURPOSE = "leave-scan";

function env(name: string | null = "prod", fake: FakeAlcAuth = createFakeAlcAuth()): MachineCredEnv & { fake: FakeAlcAuth } {
  return {
    ALC_AUTH: fake.fetcher,
    INTERNAL_SHARED_SECRET: FAKE_ALC_AUTH_SECRET,
    MACHINE_CRED_ENV: name ?? undefined,
    fake,
  };
}

function basic(username: string, password: string): string {
  return `Basic ${btoa(`${username}:${password}`)}`;
}

async function create(e: MachineCredEnv, tenant = TENANT_A, label = "複合機 1F") {
  const c = await createMachineCredential(e, tenant, PURPOSE, label);
  if (!c) throw new Error("create failed");
  return c;
}

describe("purpose allowlist / env name", () => {
  it("allowlist は leave-scan と fuel-utran だけ", () => {
    expect(MACHINE_CRED_PURPOSES).toEqual(["leave-scan", "fuel-utran"]);
    expect(isMachineCredPurpose("leave-scan")).toBe(true);
    expect(isMachineCredPurpose("fuel-utran")).toBe(true);
    expect(isMachineCredPurpose("other")).toBe(false);
    expect(isMachineCredPurpose(undefined)).toBe(false);
  });

  it("MACHINE_CRED_ENV は決まった形だけ受ける", () => {
    expect(machineCredEnvName({ MACHINE_CRED_ENV: "prod" })).toBe("prod");
    expect(machineCredEnvName({ MACHINE_CRED_ENV: "staging" })).toBe("staging");
    expect(machineCredEnvName({})).toBeNull();
    expect(machineCredEnvName({ MACHINE_CRED_ENV: "" })).toBeNull();
    expect(machineCredEnvName({ MACHINE_CRED_ENV: "prod:x" })).toBeNull();
  });
});

describe("createMachineCredential", () => {
  it("username = mc_ + 16 hex、password = 18 byte の base64url (24 文字)。alc-auth-worker には hash だけ", async () => {
    const e = env();
    const c = await create(e);
    expect(c.username).toMatch(/^mc_[0-9a-f]{16}$/);
    expect(c.password).toMatch(/^[A-Za-z0-9_-]{24}$/);

    const row = e.fake.rows.get(c.username);
    expect(row).toMatchObject({
      username: c.username,
      tenant_id: TENANT_A,
      purpose: PURPOSE,
      label: "複合機 1F",
      revoked: false,
    });
    expect(row!.secret_hash).toBe(await sha256Hex(c.password));
  });

  it("★ 送る本文は {username, tenant_id, purpose, label, secret_hash} だけで、password を含まない", async () => {
    const e = env();
    const c = await create(e);
    expect(e.fake.calls).toHaveLength(1);
    const call = e.fake.calls[0]!;
    expect(call.method).toBe("POST");
    expect(new URL(call.url).pathname).toBe("/internal/machine-credentials");
    expect(call.headers.get("Content-Type")).toBe("application/json");
    const body = JSON.parse(call.body) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(["label", "purpose", "secret_hash", "tenant_id", "username"]);
    expect(body.secret_hash).toBe(await sha256Hex(c.password));
    expect(call.body).not.toContain(c.password);
  });

  it("★ 全部の口に X-Internal-Shared-Secret を付ける", async () => {
    const e = env();
    const c = await create(e);
    await verifyBasic(e, basic(c.username, c.password), PURPOSE);
    await getActiveMachineCredential(e, c.username);
    await listMachineCredentials(e, TENANT_A);
    await revokeMachineCredential(e, TENANT_A, c.username);
    expect(e.fake.calls.map((x) => `${x.method} ${new URL(x.url).pathname}`)).toEqual([
      "POST /internal/machine-credentials",
      `GET /internal/machine-credentials/${c.username}`,
      `GET /internal/machine-credentials/${c.username}`,
      "GET /internal/machine-credentials",
      `POST /internal/machine-credentials/${c.username}/revoke`,
    ]);
    for (const x of e.fake.calls) expect(x.headers.get("X-Internal-Shared-Secret")).toBe(FAKE_ALC_AUTH_SECRET);
  });

  it("label は前後の空白を落として送る", async () => {
    const e = env();
    const c = await create(e, TENANT_A, "  2F  ");
    expect(e.fake.rows.get(c.username)!.label).toBe("2F");
  });

  it.each<[string, MachineCredEnv & { fake: FakeAlcAuth }, unknown, unknown, unknown]>([
    ["環境名なし", env(null), TENANT_A, PURPOSE, "x"],
    ["tenant が空", env(), "", PURPOSE, "x"],
    ["tenant が文字列でない", env(), 1, PURPOSE, "x"],
    ["purpose が allowlist に無い", env(), TENANT_A, "other", "x"],
    ["label が文字列でない", env(), TENANT_A, PURPOSE, 1],
    ["label が空白だけ", env(), TENANT_A, PURPOSE, "   "],
    ["label が長すぎる", env(), TENANT_A, PURPOSE, "x".repeat(MACHINE_CRED_LABEL_MAX + 1)],
  ])("%s → null (alc-auth-worker を呼ばない)", async (_name, e, tenant, purpose, label) => {
    const c = await createMachineCredential(e, tenant as string, purpose as string, label as string);
    expect(c).toBeNull();
    expect(e.fake.calls).toEqual([]);
  });

  it("label の上限ちょうどは通る", async () => {
    expect(await createMachineCredential(env(), TENANT_A, PURPOSE, "x".repeat(MACHINE_CRED_LABEL_MAX))).not.toBeNull();
  });

  it("会社が無い (404 tenant_not_found)・username の重複 (409) → null", async () => {
    const noTenant = env("prod", createFakeAlcAuth({ tenants: [TENANT_B] }));
    expect(await createMachineCredential(noTenant, TENANT_A, PURPOSE, "x")).toBeNull();
    expect(noTenant.fake.rows.size).toBe(0);

    const taken = env("prod", createFakeAlcAuth({ override: () => new Response('{"error":"username_taken"}', { status: 409 }) }));
    expect(await createMachineCredential(taken, TENANT_A, PURPOSE, "x")).toBeNull();
  });
});

describe("verifyBasic", () => {
  it("正しい Basic → tenant と username", async () => {
    const e = env();
    const c = await create(e);
    expect(await verifyBasic(e, basic(c.username, c.password), PURPOSE)).toEqual({
      tenantId: TENANT_A,
      username: c.username,
    });
  });

  it("不在 / 失効 / 用途違い / password 違い / 形の不正はすべて null (区別しない)", async () => {
    const e = env();
    const c = await create(e);
    const wrongPurposeUser = "mc_0123456789abcdef";
    e.fake.rows.set(wrongPurposeUser, {
      username: wrongPurposeUser,
      tenant_id: TENANT_A,
      purpose: "other",
      label: "x",
      secret_hash: await sha256Hex("pw"),
      created_at: new Date().toISOString(),
      revoked: false,
    });

    const cases = [
      basic("mc_aaaaaaaaaaaaaaaa", c.password), // 不在
      basic(c.username, `${c.password}x`), // password 違い
      basic(wrongPurposeUser, "pw"), // 用途違い
      basic("device:abc", "pw"), // username の形が違う (alc-auth-worker を引かない)
      "Bearer abc", // Basic でない
      "", // 空
    ];
    for (const a of cases) expect(await verifyBasic(e, a, PURPOSE)).toBeNull();
    expect(e.fake.calls.some((x) => x.url.includes("device"))).toBe(false);

    await revokeMachineCredential(e, TENANT_A, c.username);
    expect(await verifyBasic(e, basic(c.username, c.password), PURPOSE)).toBeNull();
  });

  it("口 4 の応答の形が違う (欄が欠ける・型が違う) → null", async () => {
    const e = env();
    const c = await create(e);
    const good = { tenant_id: TENANT_A, purpose: PURPOSE, secret_hash: await sha256Hex(c.password), revoked: false };
    for (const patch of [{ tenant_id: 1 }, { purpose: null }, { secret_hash: undefined }, { revoked: "false" }]) {
      const bad = env("prod", createFakeAlcAuth({ override: () => Response.json({ ...good, ...patch }) }));
      expect(await verifyBasic(bad, basic(c.username, c.password), PURPOSE)).toBeNull();
    }
    // 対照: 同じ形で欄が揃っていれば通る
    const ok = env("prod", createFakeAlcAuth({ override: () => Response.json(good) }));
    expect(await verifyBasic(ok, basic(c.username, c.password), PURPOSE)).not.toBeNull();
  });

  it("purpose が allowlist に無い / 環境名なし → null (alc-auth-worker を引かない)", async () => {
    const e = env();
    const c = await create(e);
    const before = e.fake.calls.length;
    expect(await verifyBasic(e, basic(c.username, c.password), "other")).toBeNull();
    expect(
      await verifyBasic({ ...e, MACHINE_CRED_ENV: undefined }, basic(c.username, c.password), PURPOSE),
    ).toBeNull();
    expect(e.fake.calls.length).toBe(before);
  });

  it("★ staging の資格情報は prod の alc-auth-worker (別の DB) では照合できない", async () => {
    const staging = env("staging");
    const prod = env("prod");
    const c = await create(staging);
    expect(await verifyBasic(staging, basic(c.username, c.password), PURPOSE)).not.toBeNull();
    expect(await verifyBasic(prod, basic(c.username, c.password), PURPOSE)).toBeNull();
  });
});

describe("rotateMachineCredential", () => {
  // fake の内部口には rotate が無い (404) ので、応答は override で与え、送った本文は calls で見る。
  const rotateOk = (req: Request) =>
    req.url.endsWith("/rotate") ? Response.json({ rotated: true }) : undefined;

  it("成功: 同じ username と 24 文字の新しい password。本文は {tenant_id, secret_hash}", async () => {
    const e = env("prod", createFakeAlcAuth({ override: rotateOk }));
    const r = await rotateMachineCredential(e, TENANT_A, "mc_0123456789abcdef");
    expect(r?.username).toBe("mc_0123456789abcdef");
    expect(r?.password).toHaveLength(24);
    const call = e.fake.calls.at(-1)!;
    expect(call.method).toBe("POST");
    expect(call.url).toMatch(/\/internal\/machine-credentials\/mc_0123456789abcdef\/rotate$/);
    expect(JSON.parse(call.body)).toEqual({ tenant_id: TENANT_A, secret_hash: await sha256Hex(r!.password) });
  });

  it("内部口が 404 → null (不在・失効済み・他社は区別しない)", async () => {
    const e = env();
    expect(await rotateMachineCredential(e, TENANT_A, "mc_0123456789abcdef")).toBeNull();
  });

  it("200 でも rotated:true でなければ null", async () => {
    const e = env("prod", createFakeAlcAuth({ override: () => Response.json({ rotated: false }) }));
    expect(await rotateMachineCredential(e, TENANT_A, "mc_0123456789abcdef")).toBeNull();
  });

  it("tenant が空 / username の形が違う → null (内部口を引かない)", async () => {
    const e = env("prod", createFakeAlcAuth({ override: rotateOk }));
    expect(await rotateMachineCredential(e, "", "mc_0123456789abcdef")).toBeNull();
    expect(await rotateMachineCredential(e, TENANT_A, "../x")).toBeNull();
    expect(e.fake.calls).toHaveLength(0);
  });
});

describe("revokeMachineCredential", () => {
  it("★ 他 tenant の資格情報は revoke できない (false・行は有効なまま)", async () => {
    const e = env();
    const c = await create(e, TENANT_A);
    expect(await revokeMachineCredential(e, TENANT_B, c.username)).toBe(false);
    expect(e.fake.rows.get(c.username)!.revoked).toBe(false);
    expect(await verifyBasic(e, basic(c.username, c.password), PURPOSE)).not.toBeNull();
  });

  it("自 tenant は true。2 回目も true (冪等)。送る本文は {tenant_id}", async () => {
    const e = env();
    const c = await create(e);
    expect(await revokeMachineCredential(e, TENANT_A, c.username)).toBe(true);
    expect(e.fake.rows.get(c.username)!.revoked).toBe(true);
    expect(await revokeMachineCredential(e, TENANT_A, c.username)).toBe(true);
    expect(JSON.parse(e.fake.calls.at(-1)!.body)).toEqual({ tenant_id: TENANT_A });
  });

  it("不在 / 環境名なし / tenant が空 / username の形が違う → false", async () => {
    const e = env();
    const c = await create(e);
    expect(await revokeMachineCredential(e, TENANT_A, "mc_aaaaaaaaaaaaaaaa")).toBe(false);
    expect(await revokeMachineCredential(env(null, e.fake), TENANT_A, c.username)).toBe(false);
    expect(await revokeMachineCredential(e, "", c.username)).toBe(false);
    expect(await revokeMachineCredential(e, TENANT_A, "../x")).toBe(false);
    expect(e.fake.rows.get(c.username)!.revoked).toBe(false);
  });

  it("200 でも revoked:true でなければ false", async () => {
    const e = env("prod", createFakeAlcAuth({ override: () => Response.json({ revoked: false }) }));
    expect(await revokeMachineCredential(e, TENANT_A, "mc_aaaaaaaaaaaaaaaa")).toBe(false);
  });
});

describe("getActiveMachineCredential", () => {
  it("有効なら tenant と purpose を返す (hash・label・created_at は空)。失効・不在・環境名なしは null", async () => {
    const e = env();
    const c = await create(e);
    expect(await getActiveMachineCredential(e, c.username)).toEqual({
      username: c.username,
      tenant_id: TENANT_A,
      purpose: PURPOSE,
      label: "",
      secret_hash: "",
      created_at: "",
      revoked: false,
    });
    expect(await getActiveMachineCredential(env(null, e.fake), c.username)).toBeNull();
    expect(await getActiveMachineCredential(e, "mc_aaaaaaaaaaaaaaaa")).toBeNull();
    expect(await getActiveMachineCredential(e, 1 as unknown as string)).toBeNull();
    await revokeMachineCredential(e, TENANT_A, c.username);
    expect(await getActiveMachineCredential(e, c.username)).toBeNull();
  });
});

describe("listMachineCredentials", () => {
  it("自 tenant の分だけ、password も hash も返さない。失効済みも revoked:true で出る", async () => {
    const e = env();
    const a1 = await create(e, TENANT_A, "1F");
    const a2 = await create(e, TENANT_A, "2F");
    await create(e, TENANT_B, "他社");
    await revokeMachineCredential(e, TENANT_A, a2.username);

    const list = await listMachineCredentials(e, TENANT_A);
    expect(list.map((x) => x.username).sort()).toEqual([a1.username, a2.username].sort());
    for (const item of list) {
      expect(Object.keys(item).sort()).toEqual(["created_at", "label", "purpose", "revoked", "username"]);
      expect(JSON.stringify(item)).not.toContain(a1.password);
    }
    expect(list.find((x) => x.username === a2.username)?.revoked).toBe(true);
    expect(list.find((x) => x.username === a1.username)?.revoked).toBe(false);
  });

  it("purpose で絞れる (query に載せる)", async () => {
    const e = env();
    await create(e);
    expect(await listMachineCredentials(e, TENANT_A, PURPOSE)).toHaveLength(1);
    expect(new URL(e.fake.calls.at(-1)!.url).searchParams.get("purpose")).toBe(PURPOSE);
    expect(await listMachineCredentials(e, TENANT_A, "other")).toEqual([]);
    expect(new URL(e.fake.calls.at(-1)!.url).searchParams.get("tenant_id")).toBe(TENANT_A);
  });

  it("形の合わない行・頼んでいない用途の行は出さない", async () => {
    const ok = { username: "mc_0123456789abcdef", purpose: PURPOSE, label: "x", created_at: "2026-10-13T00:00:00.000Z", revoked: false };
    const credentials = [
      ok,
      null,
      "x",
      { ...ok, username: 1 },
      { ...ok, purpose: "other" },
      { ...ok, label: null },
      { ...ok, created_at: 0 },
      { ...ok, revoked: "no" },
    ];
    const e = env("prod", createFakeAlcAuth({ override: () => Response.json({ credentials }) }));
    expect(await listMachineCredentials(e, TENANT_A)).toEqual([ok]);
    const other = env("prod", createFakeAlcAuth({ override: () => Response.json({ credentials: [ok] }) }));
    // 口が絞り損ねても、頼んだ用途と違う行は出さない
    expect(await listMachineCredentials(other, TENANT_A, "x-other")).toEqual([]);
  });

  it("credentials が配列でない → 空", async () => {
    const e = env("prod", createFakeAlcAuth({ override: () => Response.json({ credentials: {} }) }));
    expect(await listMachineCredentials(e, TENANT_A)).toEqual([]);
  });

  it("環境が違う (別の DB)・環境名なし・tenant が空 → 空", async () => {
    const staging = env("staging");
    await create(staging);
    expect(await listMachineCredentials(env("prod"), TENANT_A)).toEqual([]);
    expect(await listMachineCredentials(env(null, staging.fake), TENANT_A)).toEqual([]);
    expect(await listMachineCredentials(staging, "")).toEqual([]);
  });
});

describe("★ fail-closed (5 関数とも失敗側の値を返し、throw しない)", () => {
  const USER = "mc_0123456789abcdef";
  const PASSWORD = "pw";

  async function seeded(e: MachineCredEnv & { fake: FakeAlcAuth }) {
    e.fake.rows.set(USER, {
      username: USER,
      tenant_id: TENANT_A,
      purpose: PURPOSE,
      label: "x",
      secret_hash: await sha256Hex(PASSWORD),
      created_at: new Date().toISOString(),
      revoked: false,
    });
    return e;
  }

  async function all(e: MachineCredEnv) {
    return {
      verify: await verifyBasic(e, basic(USER, PASSWORD), PURPOSE),
      active: await getActiveMachineCredential(e, USER),
      create: await createMachineCredential(e, TENANT_A, PURPOSE, "x"),
      list: await listMachineCredentials(e, TENANT_A),
      revoke: await revokeMachineCredential(e, TENANT_A, USER),
    };
  }

  const FAILED = { verify: null, active: null, create: null, list: [], revoke: false };

  it("対照: 正常な fake では 5 関数とも成功側", async () => {
    const r = await all(await seeded(env()));
    expect(r.verify).not.toBeNull();
    expect(r.active).not.toBeNull();
    expect(r.create).not.toBeNull();
    expect(r.list).toHaveLength(2);
    expect(r.revoke).toBe(true);
  });

  it.each<[string, (e: MachineCredEnv & { fake: FakeAlcAuth }) => MachineCredEnv]>([
    ["ALC_AUTH binding が無い", (e) => ({ ...e, ALC_AUTH: undefined })],
    ["INTERNAL_SHARED_SECRET が無い", (e) => ({ ...e, INTERNAL_SHARED_SECRET: undefined })],
    [
      "INTERNAL_SHARED_SECRET の Secrets Store が throw",
      (e) => ({ ...e, INTERNAL_SHARED_SECRET: { get: () => Promise.reject(new Error("down")) } as unknown as SecretsStoreSecret }),
    ],
    ["MACHINE_CRED_ENV が無い", (e) => ({ ...e, MACHINE_CRED_ENV: undefined })],
    ["MACHINE_CRED_ENV が不正", (e) => ({ ...e, MACHINE_CRED_ENV: "prod:x" })],
    ["共有 secret が合わない (口は 404 で本文なし)", (e) => ({ ...e, INTERNAL_SHARED_SECRET: "wrong" })],
  ])("%s → 失敗側", async (_n, mutate) => {
    const e = await seeded(env());
    expect(await all(mutate(e))).toEqual(FAILED);
    expect(e.fake.rows.get(USER)!.revoked).toBe(false);
  });

  it.each<[string, () => Response | Promise<Response>]>([
    ["500", () => new Response("oops", { status: 500 })],
    ["503", () => Response.json({ ok: true }, { status: 503 })],
    ["400", () => Response.json({ error: "invalid_body" }, { status: 400 })],
    ["302", () => new Response(null, { status: 302, headers: { Location: "https://example.invalid/" } })],
    ["壊れた JSON", () => new Response("{not json", { status: 200 })],
    ["JSON が null", () => new Response("null", { status: 200 })],
    ["JSON が配列", () => Response.json([])],
    ["404 (本文の文字列に依らず無い扱い)", () => Response.json({ error: "anything" }, { status: 404 })],
  ])("alc-auth-worker が %s → 失敗側", async (_n, res) => {
    const e = await seeded(env("prod", createFakeAlcAuth({ override: () => res() as Response })));
    expect(await all(e)).toEqual(FAILED);
  });

  it("通信が throw → 失敗側", async () => {
    const e = env();
    const throwing = { fetch: () => Promise.reject(new TypeError("network")) } as unknown as Fetcher;
    expect(await all({ ...e, ALC_AUTH: throwing })).toEqual(FAILED);
  });
});
