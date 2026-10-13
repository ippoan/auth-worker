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
  verifyBasic,
  type MachineCredEnv,
  type MachineCredentialRecord,
} from "../../src/lib/machine-credential";
import { sha256Hex } from "../../src/lib/device";
import { createMockKV, type MockKV } from "../helpers/mock-env";

/** テスト固有のダミー UUID (本番の値ではない)。 */
const TENANT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const TENANT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const PURPOSE = "leave-scan";

function env(name: string | null = "prod", kv: KVNamespace = createMockKV()): MachineCredEnv {
  return { AUTH_CONFIG: kv, MACHINE_CRED_ENV: name ?? undefined };
}

function basic(username: string, password: string): string {
  return `Basic ${btoa(`${username}:${password}`)}`;
}

async function create(e: MachineCredEnv, tenant = TENANT_A, label = "複合機 1F") {
  const c = await createMachineCredential(e, tenant, PURPOSE, label);
  if (!c) throw new Error("create failed");
  return c;
}

/** list を 1 件ずつの頁に分けて返す KV (cursor の続きを辿るかの確認用)。 */
function pagedKV(base: KVNamespace): KVNamespace {
  return {
    ...base,
    get: base.get.bind(base),
    put: base.put.bind(base),
    list: async (opts?: { prefix?: string; cursor?: string }) => {
      const all = await base.list({ prefix: opts?.prefix });
      const i = opts?.cursor ? Number(opts.cursor) : 0;
      const last = i + 1 >= all.keys.length;
      return last
        ? { keys: all.keys.slice(i, i + 1), list_complete: true, cacheStatus: null }
        : { keys: all.keys.slice(i, i + 1), list_complete: false, cursor: String(i + 1), cacheStatus: null };
    },
  } as unknown as KVNamespace;
}

describe("purpose allowlist / env name", () => {
  it("allowlist は leave-scan だけ", () => {
    expect(MACHINE_CRED_PURPOSES).toEqual(["leave-scan"]);
    expect(isMachineCredPurpose("leave-scan")).toBe(true);
    expect(isMachineCredPurpose("other")).toBe(false);
    expect(isMachineCredPurpose(undefined)).toBe(false);
  });

  it("MACHINE_CRED_ENV は key に使える形だけ受ける", () => {
    expect(machineCredEnvName({ MACHINE_CRED_ENV: "prod" })).toBe("prod");
    expect(machineCredEnvName({ MACHINE_CRED_ENV: "staging" })).toBe("staging");
    expect(machineCredEnvName({})).toBeNull();
    expect(machineCredEnvName({ MACHINE_CRED_ENV: "" })).toBeNull();
    expect(machineCredEnvName({ MACHINE_CRED_ENV: "prod:x" })).toBeNull();
  });
});

describe("createMachineCredential", () => {
  it("username = mc_ + 16 hex、password = 32 byte の base64url。KV には hash だけ", async () => {
    const kv = createMockKV() as MockKV;
    const e = env("prod", kv);
    const c = await create(e);
    expect(c.username).toMatch(/^mc_[0-9a-f]{16}$/);
    expect(c.password).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const raw = kv._data[`mcred:prod:${c.username}`];
    expect(raw).toBeDefined();
    const rec = JSON.parse(raw!) as MachineCredentialRecord;
    expect(rec).toMatchObject({
      username: c.username,
      tenant_id: TENANT_A,
      purpose: PURPOSE,
      label: "複合機 1F",
      revoked: false,
    });
    expect(rec.secret_hash).toBe(await sha256Hex(c.password));
    expect(raw).not.toContain(c.password);
    expect(new Date(rec.created_at).toISOString()).toBe(rec.created_at);
    expect(kv._data[`mcred-tenant:prod:${TENANT_A}:${c.username}`]).toBe("1");
    // device credential の置き場には書かない
    expect(Object.keys(kv._data).some((k) => k.startsWith("device:"))).toBe(false);
  });

  it("label は前後の空白を落として保存する", async () => {
    const kv = createMockKV() as MockKV;
    const c = await create(env("prod", kv), TENANT_A, "  2F  ");
    expect((JSON.parse(kv._data[`mcred:prod:${c.username}`]!) as MachineCredentialRecord).label).toBe("2F");
  });

  it.each<[string, MachineCredEnv, unknown, unknown, unknown]>([
    ["環境名なし", env(null), TENANT_A, PURPOSE, "x"],
    ["tenant が空", env(), "", PURPOSE, "x"],
    ["tenant が文字列でない", env(), 1, PURPOSE, "x"],
    ["tenant に : を含む", env(), "a:b", PURPOSE, "x"],
    ["purpose が allowlist に無い", env(), TENANT_A, "other", "x"],
    ["label が文字列でない", env(), TENANT_A, PURPOSE, 1],
    ["label が空白だけ", env(), TENANT_A, PURPOSE, "   "],
    ["label が長すぎる", env(), TENANT_A, PURPOSE, "x".repeat(MACHINE_CRED_LABEL_MAX + 1)],
  ])("%s → null (何も書かない)", async (_name, e, tenant, purpose, label) => {
    const c = await createMachineCredential(e, tenant as string, purpose as string, label as string);
    expect(c).toBeNull();
    expect(Object.keys((e.AUTH_CONFIG as MockKV)._data)).toEqual([]);
  });

  it("label の上限ちょうどは通る", async () => {
    expect(await createMachineCredential(env(), TENANT_A, PURPOSE, "x".repeat(MACHINE_CRED_LABEL_MAX))).not.toBeNull();
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
    const kv = createMockKV() as MockKV;
    const e = env("prod", kv);
    const c = await create(e);
    const wrongPurposeUser = "mc_0123456789abcdef";
    kv._data[`mcred:prod:${wrongPurposeUser}`] = JSON.stringify({
      username: wrongPurposeUser,
      tenant_id: TENANT_A,
      purpose: "other",
      label: "x",
      secret_hash: await sha256Hex("pw"),
      created_at: new Date().toISOString(),
      revoked: false,
    });
    kv._data["mcred:prod:mc_ffffffffffffffff"] = "{not json";

    const cases = [
      basic("mc_aaaaaaaaaaaaaaaa", c.password), // 不在
      basic(c.username, `${c.password}x`), // password 違い
      basic(wrongPurposeUser, "pw"), // 用途違い
      basic("mc_ffffffffffffffff", "pw"), // record が壊れている
      basic("device:abc", "pw"), // username の形が違う (KV を引かない)
      "Bearer abc", // Basic でない
      "", // 空
    ];
    for (const a of cases) expect(await verifyBasic(e, a, PURPOSE)).toBeNull();

    await revokeMachineCredential(e, TENANT_A, c.username);
    expect(await verifyBasic(e, basic(c.username, c.password), PURPOSE)).toBeNull();
  });

  it("purpose が allowlist に無い / 環境名なし → null", async () => {
    const e = env();
    const c = await create(e);
    expect(await verifyBasic(e, basic(c.username, c.password), "other")).toBeNull();
    expect(
      await verifyBasic({ ...e, MACHINE_CRED_ENV: undefined }, basic(c.username, c.password), PURPOSE),
    ).toBeNull();
  });

  it("★ staging の資格情報は MACHINE_CRED_ENV=prod では照合できない (同じ KV namespace でも)", async () => {
    const kv = createMockKV();
    const c = await create(env("staging", kv));
    expect(await verifyBasic(env("staging", kv), basic(c.username, c.password), PURPOSE)).not.toBeNull();
    expect(await verifyBasic(env("prod", kv), basic(c.username, c.password), PURPOSE)).toBeNull();
  });
});

describe("revokeMachineCredential", () => {
  it("★ 他 tenant の資格情報は revoke できない (false・record は有効なまま)", async () => {
    const e = env();
    const c = await create(e, TENANT_A);
    expect(await revokeMachineCredential(e, TENANT_B, c.username)).toBe(false);
    expect(await verifyBasic(e, basic(c.username, c.password), PURPOSE)).not.toBeNull();
  });

  it("自 tenant は true。2 回目も true (冪等、書き直さない)", async () => {
    const kv = createMockKV() as MockKV;
    const e = env("prod", kv);
    const c = await create(e);
    expect(await revokeMachineCredential(e, TENANT_A, c.username)).toBe(true);
    const after = kv._data[`mcred:prod:${c.username}`];
    expect((JSON.parse(after!) as MachineCredentialRecord).revoked).toBe(true);
    expect(await revokeMachineCredential(e, TENANT_A, c.username)).toBe(true);
    expect(kv._data[`mcred:prod:${c.username}`]).toBe(after);
  });

  it("不在 / 環境名なし → false", async () => {
    const e = env();
    const c = await create(e);
    expect(await revokeMachineCredential(e, TENANT_A, "mc_aaaaaaaaaaaaaaaa")).toBe(false);
    expect(await revokeMachineCredential(env(null, e.AUTH_CONFIG), TENANT_A, c.username)).toBe(false);
  });
});

describe("getActiveMachineCredential", () => {
  it("有効なら record、失効・不在・環境名なしは null", async () => {
    const e = env();
    const c = await create(e);
    expect((await getActiveMachineCredential(e, c.username))?.tenant_id).toBe(TENANT_A);
    expect(await getActiveMachineCredential(env(null, e.AUTH_CONFIG), c.username)).toBeNull();
    expect(await getActiveMachineCredential(e, "mc_aaaaaaaaaaaaaaaa")).toBeNull();
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

  it("purpose で絞れる", async () => {
    const e = env();
    await create(e);
    expect(await listMachineCredentials(e, TENANT_A, PURPOSE)).toHaveLength(1);
    expect(await listMachineCredentials(e, TENANT_A, "other")).toEqual([]);
  });

  it("索引だけ残った行・索引と本体の tenant が食い違う行は出さない", async () => {
    const kv = createMockKV() as MockKV;
    const e = env("prod", kv);
    const b = await create(e, TENANT_B);
    kv._data[`mcred-tenant:prod:${TENANT_A}:mc_aaaaaaaaaaaaaaaa`] = "1"; // 本体なし
    kv._data[`mcred-tenant:prod:${TENANT_A}:${b.username}`] = "1"; // 本体は TENANT_B
    expect(await listMachineCredentials(e, TENANT_A)).toEqual([]);
  });

  it("list の頁を cursor で最後まで辿る", async () => {
    const kv = createMockKV();
    const e = env("prod", pagedKV(kv));
    await create(e, TENANT_A, "1");
    await create(e, TENANT_A, "2");
    await create(e, TENANT_A, "3");
    expect(await listMachineCredentials(e, TENANT_A)).toHaveLength(3);
  });

  it("環境が違う・環境名なし・tenant が空や : 入り → 空", async () => {
    const kv = createMockKV();
    await create(env("staging", kv));
    expect(await listMachineCredentials(env("prod", kv), TENANT_A)).toEqual([]);
    expect(await listMachineCredentials(env(null, kv), TENANT_A)).toEqual([]);
    expect(await listMachineCredentials(env("staging", kv), "")).toEqual([]);
    expect(await listMachineCredentials(env("staging", kv), "a:b")).toEqual([]);
  });
});
