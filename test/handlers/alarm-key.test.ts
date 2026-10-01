import { describe, it, expect, vi } from "vitest";
import {
  handleAlarmKeyRegister,
  handleAlarmKeyList,
  handleAlarmKeyRevoke,
} from "../../src/handlers/alarm-key";
import { DEVELOPER_EMAILS } from "../../src/lib/developer";
import { createMockKV, type MockKV } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";
import type { Env } from "../../src/index";

const SECRET = "alarm-key-test-secret";
const ENV = "staging";
const ISSUER = "https://auth.ippoan.org";

/** makeEnv と同じ KV だが、`_data` を直接いじって壊れた JSON を仕込めるように返す。 */
function makeEnvWithKv(): { env: Env; kv: MockKV } {
  const kv = createMockKV() as unknown as MockKV;
  const env = {
    AUTH_CONFIG: kv,
    JWT_SECRET: SECRET,
    WORKER_ENV: ENV,
  } as unknown as Env;
  return { env, kv };
}

function makeEnv(overrides: Record<string, unknown> = {}): Env {
  return {
    AUTH_CONFIG: createMockKV(),
    JWT_SECRET: SECRET,
    WORKER_ENV: ENV,
    ...overrides,
  } as unknown as Env;
}

async function opCookie(claims: Record<string, unknown> = {}): Promise<Record<string, string>> {
  const token = await signTestJwt(
    { tenant_id: "tenant-1", email: "op@example.com", env: ENV, ...claims },
    SECRET,
  );
  return { Cookie: `logi_auth_token=${token}` };
}

function postJson(path: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`${ISSUER}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

function getReq(path: string, headers: Record<string, string> = {}): Request {
  return new Request(`${ISSUER}${path}`, { method: "GET", headers });
}

/** base64url encode raw bytes (no padding), mirroring production `decodeBase64Url`'s counterpart. */
function b64url(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** 32-byte deterministic "pubkey" for tests, varying by seed byte so different keys → different fingerprints. */
function fakePubkey(seed: number): string {
  const bytes = new Uint8Array(32);
  bytes.fill(seed);
  return b64url(bytes);
}

const originHeaders = { Origin: ISSUER };

async function withOpCookieAndOrigin(
  claims: Record<string, unknown> = {},
): Promise<Record<string, string>> {
  return { ...(await opCookie(claims)), ...originHeaders };
}

describe("handleAlarmKeyRegister", () => {
  it("registers a new alarm key and returns its fingerprint", async () => {
    const env = makeEnv();
    const res = await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: fakePubkey(1), label: "cab-1", usage: "kiosk" },
        await withOpCookieAndOrigin(),
      ),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { fingerprint: string };
    expect(data.fingerprint).toMatch(/^[0-9a-f]{16}$/);
  });

  it("401 without a session cookie", async () => {
    const env = makeEnv();
    const res = await handleAlarmKeyRegister(
      postJson("/device/setup/alarm-key", { pubkey: fakePubkey(2), label: "x", usage: "kiosk" }, originHeaders),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("403 bad_origin when Origin header doesn't match the issuer", async () => {
    const env = makeEnv();
    const res = await handleAlarmKeyRegister(
      postJson("/device/setup/alarm-key", { pubkey: fakePubkey(3), label: "x", usage: "kiosk" }, await opCookie()),
      env,
    );
    expect(res.status).toBe(403);
    expect((await res.json()) as { error: string }).toEqual({ error: "bad_origin" });
  });

  it("400 when pubkey isn't valid base64url of 32 raw bytes", async () => {
    const env = makeEnv();
    const res = await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: "not-base64url-32-bytes", label: "x", usage: "kiosk" },
        await withOpCookieAndOrigin(),
      ),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when pubkey decodes to the wrong length", async () => {
    const env = makeEnv();
    const shortKey = b64url(new Uint8Array(16));
    const res = await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: shortKey, label: "x", usage: "kiosk" },
        await withOpCookieAndOrigin(),
      ),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400 when label is empty or too long", async () => {
    const env = makeEnv();
    const empty = await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: fakePubkey(4), label: "", usage: "kiosk" },
        await withOpCookieAndOrigin(),
      ),
      env,
    );
    expect(empty.status).toBe(400);

    const tooLong = await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: fakePubkey(5), label: "x".repeat(65), usage: "kiosk" },
        await withOpCookieAndOrigin(),
      ),
      env,
    );
    expect(tooLong.status).toBe(400);
  });

  it("409 when the same pubkey (fingerprint) is already registered", async () => {
    const env = makeEnv();
    const headers = await withOpCookieAndOrigin();
    const pubkey = fakePubkey(6);
    const first = await handleAlarmKeyRegister(
      postJson("/device/setup/alarm-key", { pubkey, label: "cab-1", usage: "kiosk" }, headers),
      env,
    );
    expect(first.status).toBe(200);
    const second = await handleAlarmKeyRegister(
      postJson("/device/setup/alarm-key", { pubkey, label: "cab-1-dup", usage: "kiosk" }, headers),
      env,
    );
    expect(second.status).toBe(409);
  });

  it.each([
    ["usage が無い", undefined],
    ["空文字", ""],
    ["未知の値", "admin"],
    ["畳んだ旧用途 (Refs ippoan/alc-app#353)", "admin-login"],
    ["大文字違い", "KIOSK"],
    ["文字列でない", 1],
    ["配列 (集合にしない)", ["kiosk"]],
  ])("400 when usage is invalid: %s (record も索引も書かない)", async (_label, usage) => {
    const { env, kv } = makeEnvWithKv();
    const res = await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: fakePubkey(14), label: "cab-1", usage },
        await withOpCookieAndOrigin(),
      ),
      env,
    );
    expect(res.status).toBe(400);
    expect(Object.keys(kv._data).filter((k) => k.startsWith("alarmkey"))).toEqual([]);
  });

  it.each(["kiosk", "tenko-manager", "bp-station"])(
    "registers with usage=%s and stores it on the record",
    async (usage) => {
      const { env, kv } = makeEnvWithKv();
      const res = await handleAlarmKeyRegister(
        postJson(
          "/device/setup/alarm-key",
          { pubkey: fakePubkey(15), label: "cab-1", usage },
          await withOpCookieAndOrigin(),
        ),
        env,
      );
      expect(res.status).toBe(200);
      const { fingerprint } = (await res.json()) as { fingerprint: string };
      const stored = JSON.parse(kv._data[`alarmkey:${fingerprint}`]!) as { usage: string };
      expect(stored.usage).toBe(usage);
    },
  );
});

describe("handleAlarmKeyList", () => {
  it("lists registered keys for the operator's tenant, without the pubkey field", async () => {
    const env = makeEnv();
    const headers = await withOpCookieAndOrigin();
    await handleAlarmKeyRegister(
      postJson("/device/setup/alarm-key", { pubkey: fakePubkey(7), label: "cab-1", usage: "kiosk" }, headers),
      env,
    );
    const res = await handleAlarmKeyList(
      getReq("/device/setup/alarm-keys", await withOpCookieAndOrigin()),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      keys: Array<{
        fingerprint: string;
        label: string;
        usage: string;
        created_at: number;
        revoked_at?: number;
      }>;
    };
    expect(data.keys).toHaveLength(1);
    expect(data.keys[0]!.label).toBe("cab-1");
    expect(data.keys[0]!.usage).toBe("kiosk");
    expect(data.keys[0]!.revoked_at).toBeUndefined();
    expect(data.keys[0]).not.toHaveProperty("pubkey");
  });

  it("shows each key's usage (tenko-manager / kiosk)", async () => {
    const env = makeEnv();
    const headers = await withOpCookieAndOrigin();
    for (const [seed, label, usage] of [
      [16, "voice", "tenko-manager"],
      [17, "cores3", "kiosk"],
    ] as const) {
      const reg = await handleAlarmKeyRegister(
        postJson("/device/setup/alarm-key", { pubkey: fakePubkey(seed), label, usage }, headers),
        env,
      );
      expect(reg.status).toBe(200);
    }
    const res = await handleAlarmKeyList(getReq("/device/setup/alarm-keys", headers), env);
    const data = (await res.json()) as { keys: Array<{ label: string; usage: string }> };
    expect(data.keys.map((k) => [k.label, k.usage])).toEqual([
      ["voice", "tenko-manager"],
      ["cores3", "kiosk"],
    ]);
  });

  it("401 without a session cookie", async () => {
    const env = makeEnv();
    const res = await handleAlarmKeyList(getReq("/device/setup/alarm-keys"), env);
    expect(res.status).toBe(401);
  });

  it("200 with a session cookie but no Origin header (same-origin browser GET)", async () => {
    const env = makeEnv();
    const headers = await opCookie();
    await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: fakePubkey(19), label: "cab-1", usage: "kiosk" },
        await withOpCookieAndOrigin(),
      ),
      env,
    );
    const res = await handleAlarmKeyList(getReq("/device/setup/alarm-keys", headers), env);
    expect(res.status).toBe(200);
    const data = (await res.json()) as { keys: Array<{ label: string }> };
    expect(data.keys.map((k) => k.label)).toEqual(["cab-1"]);
  });

  it("does not include another tenant's keys", async () => {
    const env = makeEnv();
    await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: fakePubkey(8), label: "tenant-1-key", usage: "kiosk" },
        await withOpCookieAndOrigin({ tenant_id: "tenant-1" }),
      ),
      env,
    );
    await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: fakePubkey(9), label: "tenant-2-key", usage: "kiosk" },
        await withOpCookieAndOrigin({ tenant_id: "tenant-2" }),
      ),
      env,
    );
    const res = await handleAlarmKeyList(
      getReq("/device/setup/alarm-keys", await withOpCookieAndOrigin({ tenant_id: "tenant-1" })),
      env,
    );
    const data = (await res.json()) as { keys: Array<{ label: string }> };
    expect(data.keys.map((k) => k.label)).toEqual(["tenant-1-key"]);
  });
});

describe("handleAlarmKeyRevoke", () => {
  it("revokes a key owned by the operator's tenant (idempotent, does not delete)", async () => {
    const env = makeEnv();
    const headers = await withOpCookieAndOrigin();
    const reg = await handleAlarmKeyRegister(
      postJson("/device/setup/alarm-key", { pubkey: fakePubkey(10), label: "cab-1", usage: "kiosk" }, headers),
      env,
    );
    const { fingerprint } = (await reg.json()) as { fingerprint: string };

    const res = await handleAlarmKeyRevoke(
      postJson("/device/setup/alarm-key/revoke", { fingerprint }, headers),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { fingerprint: string; revoked_at: number };
    expect(data.fingerprint).toBe(fingerprint);
    expect(typeof data.revoked_at).toBe("number");

    // idempotent: revoking again still 200 and doesn't move revoked_at
    const again = await handleAlarmKeyRevoke(
      postJson("/device/setup/alarm-key/revoke", { fingerprint }, headers),
      env,
    );
    expect(again.status).toBe(200);
    const againData = (await again.json()) as { revoked_at: number };
    expect(againData.revoked_at).toBe(data.revoked_at);

    // and it still shows up in the list, just revoked (not deleted)
    const list = await handleAlarmKeyList(getReq("/device/setup/alarm-keys", headers), env);
    const listData = (await list.json()) as { keys: Array<{ fingerprint: string; revoked_at?: number }> };
    expect(listData.keys.find((k) => k.fingerprint === fingerprint)?.revoked_at).toBe(
      data.revoked_at,
    );
  });

  it("401 without a session cookie", async () => {
    const env = makeEnv();
    const res = await handleAlarmKeyRevoke(
      postJson("/device/setup/alarm-key/revoke", { fingerprint: "0000000000000000" }, originHeaders),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("403 bad_origin when Origin header doesn't match the issuer", async () => {
    const env = makeEnv();
    const res = await handleAlarmKeyRevoke(
      postJson(
        "/device/setup/alarm-key/revoke",
        { fingerprint: "0000000000000000" },
        await opCookie(),
      ),
      env,
    );
    expect(res.status).toBe(403);
    expect((await res.json()) as { error: string }).toEqual({ error: "bad_origin" });
  });

  it("400 when fingerprint is missing", async () => {
    const env = makeEnv();
    const res = await handleAlarmKeyRevoke(
      postJson("/device/setup/alarm-key/revoke", {}, await withOpCookieAndOrigin()),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("403 (not_found text) when the fingerprint doesn't exist", async () => {
    const env = makeEnv();
    const res = await handleAlarmKeyRevoke(
      postJson(
        "/device/setup/alarm-key/revoke",
        { fingerprint: "ffffffffffffffff" },
        await withOpCookieAndOrigin(),
      ),
      env,
    );
    expect(res.status).toBe(403);
    expect((await res.json()) as { error: string }).toEqual({ error: "not_found" });
  });

  it("403 (same not_found text, doesn't leak existence) when the key belongs to another tenant", async () => {
    const env = makeEnv();
    const reg = await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: fakePubkey(11), label: "tenant-1-key", usage: "kiosk" },
        await withOpCookieAndOrigin({ tenant_id: "tenant-1" }),
      ),
      env,
    );
    const { fingerprint } = (await reg.json()) as { fingerprint: string };

    const res = await handleAlarmKeyRevoke(
      postJson(
        "/device/setup/alarm-key/revoke",
        { fingerprint },
        await withOpCookieAndOrigin({ tenant_id: "tenant-2" }),
      ),
      env,
    );
    expect(res.status).toBe(403);
    expect((await res.json()) as { error: string }).toEqual({ error: "not_found" });

    // and the key is unaffected — still visible & unrevoked to its real tenant
    const list = await handleAlarmKeyList(
      getReq("/device/setup/alarm-keys", await withOpCookieAndOrigin({ tenant_id: "tenant-1" })),
      env,
    );
    const data = (await list.json()) as { keys: Array<{ fingerprint: string; revoked_at?: number }> };
    expect(data.keys.find((k) => k.fingerprint === fingerprint)?.revoked_at).toBeUndefined();
  });
});

/**
 * dev-login (`token_kind: "dev"`) / device-key (`token_kind: "device-key"`) の
 * cookie では登録・失効 (登録系) を 403 で弾く。一覧 (読み取りの照会) は
 * 今までどおり通ることも合わせて確認する。
 */
describe("dev / device-key token: 登録・失効を弾く", () => {
  async function tokenHeaders(tokenKind: string): Promise<Record<string, string>> {
    return { ...(await opCookie({ token_kind: tokenKind })), ...originHeaders };
  }

  it.each(["dev", "device-key"])(
    "POST /device/setup/alarm-key (登録) は token_kind=%s で 403",
    async (tokenKind) => {
      const env = makeEnv();
      const res = await handleAlarmKeyRegister(
        postJson(
          "/device/setup/alarm-key",
          { pubkey: fakePubkey(20), label: "x", usage: "kiosk" },
          await tokenHeaders(tokenKind),
        ),
        env,
      );
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "dev_token_write_forbidden" });
    },
  );

  it.each(["dev", "device-key"])(
    "POST /device/setup/alarm-key/revoke (失効) は token_kind=%s で 403",
    async (tokenKind) => {
      const env = makeEnv();
      const reg = await handleAlarmKeyRegister(
        postJson(
          "/device/setup/alarm-key",
          { pubkey: fakePubkey(21), label: "cab-1", usage: "kiosk" },
          await withOpCookieAndOrigin(),
        ),
        env,
      );
      const { fingerprint } = (await reg.json()) as { fingerprint: string };

      const res = await handleAlarmKeyRevoke(
        postJson(
          "/device/setup/alarm-key/revoke",
          { fingerprint },
          await tokenHeaders(tokenKind),
        ),
        env,
      );
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "dev_token_write_forbidden" });

      // 実際には失効していない (revoked_at が付かない)
      const list = await handleAlarmKeyList(
        getReq("/device/setup/alarm-keys", await withOpCookieAndOrigin()),
        env,
      );
      const data = (await list.json()) as { keys: Array<{ fingerprint: string; revoked_at?: number }> };
      expect(data.keys.find((k) => k.fingerprint === fingerprint)?.revoked_at).toBeUndefined();
    },
  );

  it.each(["dev", "device-key"])(
    "GET /device/setup/alarm-keys (読み取りの照会) は token_kind=%s でも通る",
    async (tokenKind) => {
      const env = makeEnv();
      await handleAlarmKeyRegister(
        postJson(
          "/device/setup/alarm-key",
          { pubkey: fakePubkey(22), label: "cab-1", usage: "kiosk" },
          await withOpCookieAndOrigin(),
        ),
        env,
      );
      const res = await handleAlarmKeyList(
        getReq("/device/setup/alarm-keys", await tokenHeaders(tokenKind)),
        env,
      );
      expect(res.status).toBe(200);
      const data = (await res.json()) as { keys: Array<{ label: string }> };
      expect(data.keys.map((k) => k.label)).toEqual(["cab-1"]);
    },
  );
});

describe("body / KV の壊れたデータに対するフォールバック", () => {
  it("400 when pubkey contains characters that aren't valid base64url at all", async () => {
    const env = makeEnv();
    const res = await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: "!!!not valid base64!!!", label: "x", usage: "kiosk" },
        await withOpCookieAndOrigin(),
      ),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("malformed JSON body is treated as empty body (400 invalid pubkey, not a 500)", async () => {
    const env = makeEnv();
    const headers = await withOpCookieAndOrigin();
    const badBodyReq = new Request(`${ISSUER}/device/setup/alarm-key`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: "{not json",
    });
    const res = await handleAlarmKeyRegister(badBodyReq, env);
    expect(res.status).toBe(400);
  });

  it("a top-level JSON non-object body (e.g. a bare number) is also treated as empty body", async () => {
    const env = makeEnv();
    const headers = await withOpCookieAndOrigin();
    const primitiveBodyReq = new Request(`${ISSUER}/device/setup/alarm-key`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: "42",
    });
    const res = await handleAlarmKeyRegister(primitiveBodyReq, env);
    expect(res.status).toBe(400);
  });

  it("a corrupted alarmkey: record in KV is treated as absent (list skips it, revoke 403s)", async () => {
    const { env, kv } = makeEnvWithKv();
    const headers = await withOpCookieAndOrigin();
    const reg = await handleAlarmKeyRegister(
      postJson("/device/setup/alarm-key", { pubkey: fakePubkey(12), label: "cab-1", usage: "kiosk" }, headers),
      env,
    );
    const { fingerprint } = (await reg.json()) as { fingerprint: string };
    kv._data[`alarmkey:${fingerprint}`] = "{not json";

    const list = await handleAlarmKeyList(getReq("/device/setup/alarm-keys", headers), env);
    const listData = (await list.json()) as { keys: unknown[] };
    expect(listData.keys).toEqual([]);

    const revoke = await handleAlarmKeyRevoke(
      postJson("/device/setup/alarm-key/revoke", { fingerprint }, headers),
      env,
    );
    expect(revoke.status).toBe(403);
  });

  it("a corrupted alarmkeys:<tenant> index in KV falls back to an empty list", async () => {
    const { env, kv } = makeEnvWithKv();
    const headers = await withOpCookieAndOrigin();
    kv._data["alarmkeys:tenant-1"] = "{not json";

    const list = await handleAlarmKeyList(getReq("/device/setup/alarm-keys", headers), env);
    expect(list.status).toBe(200);
    const listData = (await list.json()) as { keys: unknown[] };
    expect(listData.keys).toEqual([]);
  });

  it("a valid-JSON-but-non-array alarmkeys:<tenant> index also falls back to an empty list", async () => {
    const { env, kv } = makeEnvWithKv();
    const headers = await withOpCookieAndOrigin();
    kv._data["alarmkeys:tenant-1"] = JSON.stringify({ not: "an array" });

    const list = await handleAlarmKeyList(getReq("/device/setup/alarm-keys", headers), env);
    expect(list.status).toBe(200);
    const listData = (await list.json()) as { keys: unknown[] };
    expect(listData.keys).toEqual([]);
  });

  it("registering with a dangling index entry (record removed, index stale) doesn't duplicate the index", async () => {
    // read-modify-write の索引更新は原子性が無いので、record は在るが索引がまだ
    // 追記される前 (または record だけ後から消えた) 状態を直接シミュレートする。
    const { env, kv } = makeEnvWithKv();
    const headers = await withOpCookieAndOrigin();
    const pubkey = fakePubkey(13);
    const reg = await handleAlarmKeyRegister(
      postJson("/device/setup/alarm-key", { pubkey, label: "cab-1", usage: "kiosk" }, headers),
      env,
    );
    const { fingerprint } = (await reg.json()) as { fingerprint: string };
    // record だけ消し、索引には fingerprint が残っている状態を作る
    delete kv._data[`alarmkey:${fingerprint}`];

    const second = await handleAlarmKeyRegister(
      postJson("/device/setup/alarm-key", { pubkey, label: "cab-1-again", usage: "kiosk" }, headers),
      env,
    );
    expect(second.status).toBe(200);
    const index = JSON.parse(kv._data["alarmkeys:tenant-1"]!) as string[];
    expect(index.filter((f) => f === fingerprint)).toHaveLength(1);
  });
});

/**
 * 開発用かどうかは鍵を登録する時点 (`POST /device/setup/alarm-key` の `dev_device`) で決まる
 * (Refs ippoan/alc-app#387)。明示できるのは「開発者アカウントが Google でログインした session」だけ。
 * 作り直した鍵への差し替えは `replaces_pubkey`。
 * 開発者のメールアドレスの値はテストに書かない (登録簿の先頭を借りる)。
 */
describe("handleAlarmKeyRegister の dev_device と replaces_pubkey (Refs ippoan/alc-app#387)", () => {
  const DEV_EMAIL = DEVELOPER_EMAILS[0]!;
  const PATH = "/device/setup/alarm-key";

  /** 開発者が Google で入った session (dev_device を明示できる唯一の形)。 */
  async function devHeaders(claims: Record<string, unknown> = {}): Promise<Record<string, string>> {
    return withOpCookieAndOrigin({ email: DEV_EMAIL, idp: "google", ...claims });
  }
  /** 開発者でない管理者の session。 */
  async function opHeaders(claims: Record<string, unknown> = {}): Promise<Record<string, string>> {
    return withOpCookieAndOrigin({ idp: "google", ...claims });
  }

  /** 登録して fingerprint を返す (失敗したら status で落とす)。 */
  async function register(
    env: Env,
    body: Record<string, unknown>,
    headers: Record<string, string>,
  ): Promise<string> {
    const res = await handleAlarmKeyRegister(postJson(PATH, body, headers), env);
    expect(res.status).toBe(200);
    return ((await res.json()) as { fingerprint: string }).fingerprint;
  }
  const readRecord = (kv: MockKV, fingerprint: string) =>
    JSON.parse(kv._data[`alarmkey:${fingerprint}`]!) as Record<string, unknown>;
  /** KV の中身の写し (拒否された request が何も書かないことの確認用)。 */
  const snapshot = (kv: MockKV) => JSON.stringify(kv._data);

  it("開発者 + dev_device:true → record が dev / dev_device:false → 欄ごと無い", async () => {
    const { env, kv } = makeEnvWithKv();
    const dev = await register(env, { pubkey: fakePubkey(40), label: "a", usage: "kiosk", dev_device: true }, await devHeaders());
    expect(readRecord(kv, dev).dev_device).toBe(true);
    const prod = await register(env, { pubkey: fakePubkey(41), label: "b", usage: "kiosk", dev_device: false }, await devHeaders());
    expect(readRecord(kv, prod)).not.toHaveProperty("dev_device");
  });

  it("明示なし + 新規 → 本番 (開発者の session でも)", async () => {
    const { env, kv } = makeEnvWithKv();
    const a = await register(env, { pubkey: fakePubkey(42), label: "a", usage: "kiosk" }, await opHeaders());
    const b = await register(env, { pubkey: fakePubkey(43), label: "b", usage: "kiosk" }, await devHeaders());
    expect(readRecord(kv, a)).not.toHaveProperty("dev_device");
    expect(readRecord(kv, b)).not.toHaveProperty("dev_device");
  });

  it.each([
    ["開発者でない管理者 (Google ログイン)", { email: "op@example.com", idp: "google" }],
    ["開発者の email だが idp なし (LINE WORKS のログイン・古い cookie)", { email: DEV_EMAIL }],
    ["開発者の email だが idp が別の値", { email: DEV_EMAIL, idp: "lineworks" }],
    ["email の無い session", { email: "", idp: "google" }],
  ])("%s が dev_device を送ると true でも false でも 403、何も書かれない", async (_name, claims) => {
    const { env, kv } = makeEnvWithKv();
    const old = await register(env, { pubkey: fakePubkey(44), label: "a", usage: "kiosk", dev_device: true }, await devHeaders());
    const before = snapshot(kv);
    for (const dev of [true, false]) {
      for (const extra of [{ label: "b", usage: "kiosk" }, { replaces_pubkey: fakePubkey(44) }]) {
        const res = await handleAlarmKeyRegister(
          postJson(PATH, { pubkey: fakePubkey(45), dev_device: dev, ...extra }, await withOpCookieAndOrigin(claims)),
          env,
        );
        expect(res.status).toBe(403);
        expect(await res.json()).toEqual({ error: "developer_google_session_required" });
      }
    }
    expect(snapshot(kv)).toBe(before);
    expect(readRecord(kv, old)).not.toHaveProperty("revoked_at");
  });

  it.each(["dev", "device-key"])(
    "開発者の email + idp=google でも token_kind=%s は 403 dev_token_write_forbidden (今までどおり)",
    async (tokenKind) => {
      const { env, kv } = makeEnvWithKv();
      const res = await handleAlarmKeyRegister(
        postJson(
          PATH,
          { pubkey: fakePubkey(46), label: "a", usage: "kiosk", dev_device: true },
          await devHeaders({ token_kind: tokenKind }),
        ),
        env,
      );
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "dev_token_write_forbidden" });
      expect(snapshot(kv)).toBe("{}");
    },
  );

  it.each([
    ["文字列 \"true\"", "true"],
    ["数値 1", 1],
    ["null", null],
  ])("dev_device が boolean でない (%s) は 400 (何も書かれない)", async (_name, value) => {
    const { env, kv } = makeEnvWithKv();
    const res = await handleAlarmKeyRegister(
      postJson(PATH, { pubkey: fakePubkey(47), label: "a", usage: "kiosk", dev_device: value }, await devHeaders()),
      env,
    );
    expect(res.status).toBe(400);
    expect(snapshot(kv)).toBe("{}");
  });

  it("replaces_pubkey: 新 record が古い record の label / usage を写し (body の値は見ない)、古い record は失効する", async () => {
    const { env, kv } = makeEnvWithKv();
    const old = await register(env, { pubkey: fakePubkey(50), label: "cab-1", usage: "tenko-manager" }, await opHeaders());
    const oldBefore = readRecord(kv, old);
    const next = await register(
      env,
      { pubkey: fakePubkey(51), replaces_pubkey: fakePubkey(50), label: "ignored", usage: "kiosk" },
      await opHeaders(),
    );
    expect(next).not.toBe(old);
    const rec = readRecord(kv, next);
    expect(rec).toMatchObject({ pubkey: fakePubkey(51), tenant_id: "tenant-1", label: "cab-1", usage: "tenko-manager" });
    expect(rec).not.toHaveProperty("revoked_at");
    expect(rec).not.toHaveProperty("dev_device");
    // 古い record は失効時刻が付くだけ (ほかの欄は不変)
    const oldAfter = readRecord(kv, old);
    expect(typeof oldAfter.revoked_at).toBe("number");
    expect(oldAfter).toEqual({ ...oldBefore, revoked_at: oldAfter.revoked_at });
    // 一覧には両方 (新 = 有効、旧 = 失効済み)
    expect(JSON.parse(kv._data["alarmkeys:tenant-1"]!)).toEqual([old, next]);
  });

  it("replaces_pubkey: label / usage を送らなくても通る (画面の書き直しの body)", async () => {
    const { env, kv } = makeEnvWithKv();
    await register(env, { pubkey: fakePubkey(52), label: "cab-1", usage: "kiosk" }, await opHeaders());
    const next = await register(
      env,
      { pubkey: fakePubkey(53), replaces_pubkey: fakePubkey(52), dev_device: true },
      await devHeaders(),
    );
    expect(readRecord(kv, next)).toMatchObject({ label: "cab-1", usage: "kiosk", dev_device: true });
  });

  it("replaces_pubkey + 明示なし: 古い record が dev → 新も dev (引き継ぎ) / 本番 → 本番", async () => {
    const { env, kv } = makeEnvWithKv();
    await register(env, { pubkey: fakePubkey(54), label: "a", usage: "kiosk", dev_device: true }, await devHeaders());
    const carried = await register(env, { pubkey: fakePubkey(55), replaces_pubkey: fakePubkey(54) }, await opHeaders());
    expect(readRecord(kv, carried).dev_device).toBe(true);

    await register(env, { pubkey: fakePubkey(56), label: "b", usage: "kiosk" }, await opHeaders());
    const plain = await register(env, { pubkey: fakePubkey(57), replaces_pubkey: fakePubkey(56) }, await devHeaders());
    expect(readRecord(kv, plain)).not.toHaveProperty("dev_device");
  });

  it("replaces_pubkey + 開発者 + dev_device:false: 古い record が dev → 新は本番 (欄ごと無い)", async () => {
    const { env, kv } = makeEnvWithKv();
    const old = await register(env, { pubkey: fakePubkey(58), label: "a", usage: "kiosk", dev_device: true }, await devHeaders());
    const next = await register(
      env,
      { pubkey: fakePubkey(59), replaces_pubkey: fakePubkey(58), dev_device: false },
      await devHeaders(),
    );
    expect(readRecord(kv, next)).not.toHaveProperty("dev_device");
    expect(readRecord(kv, old).dev_device).toBe(true);
    expect(typeof readRecord(kv, old).revoked_at).toBe("number");
  });

  it("replaces_pubkey: 別テナント・失効済み・不在・形式不正・用途なしの旧 record は 409 replaced_key_not_found で何も書かれない", async () => {
    const { env, kv } = makeEnvWithKv();
    // 別テナントの鍵
    await register(env, { pubkey: fakePubkey(60), label: "other", usage: "kiosk" }, await opHeaders({ tenant_id: "tenant-2" }));
    // 失効済みの鍵
    const revoked = await register(env, { pubkey: fakePubkey(61), label: "revoked", usage: "kiosk" }, await opHeaders());
    await handleAlarmKeyRevoke(
      postJson("/device/setup/alarm-key/revoke", { fingerprint: revoked }, await opHeaders()),
      env,
    );
    // 用途を持たない旧形式の record (使用不可)
    const legacy = await register(env, { pubkey: fakePubkey(62), label: "legacy", usage: "kiosk" }, await opHeaders());
    const legacyRecord = readRecord(kv, legacy);
    delete legacyRecord.usage;
    kv._data[`alarmkey:${legacy}`] = JSON.stringify(legacyRecord);

    const before = snapshot(kv);
    for (const replaces of [fakePubkey(60), fakePubkey(61), fakePubkey(62), fakePubkey(63), "not-a-pubkey", 1, null]) {
      const res = await handleAlarmKeyRegister(
        postJson(PATH, { pubkey: fakePubkey(64), replaces_pubkey: replaces, dev_device: true }, await devHeaders()),
        env,
      );
      expect(res.status).toBe(409);
      expect(await res.json()).toEqual({ error: "replaced_key_not_found" });
    }
    expect(snapshot(kv)).toBe(before);
  });

  it("replaces_pubkey: 新しい公開鍵が登録済み (古い鍵と同じ鍵を含む) なら 409 already registered で、古い record は失効しない", async () => {
    const { env, kv } = makeEnvWithKv();
    const old = await register(env, { pubkey: fakePubkey(65), label: "a", usage: "kiosk" }, await opHeaders());
    await register(env, { pubkey: fakePubkey(66), label: "b", usage: "kiosk" }, await opHeaders());
    const before = snapshot(kv);
    for (const pubkey of [fakePubkey(65), fakePubkey(66)]) {
      const res = await handleAlarmKeyRegister(
        postJson(PATH, { pubkey, replaces_pubkey: fakePubkey(65) }, await opHeaders()),
        env,
      );
      expect(res.status).toBe(409);
      expect(await res.json()).toEqual({ error: "already registered" });
    }
    expect(snapshot(kv)).toBe(before);
    expect(readRecord(kv, old)).not.toHaveProperty("revoked_at");
  });

  it("replaces_pubkey: 新しい record を保存した後に古い record を失効させる (書き込みの順)", async () => {
    const { env, kv } = makeEnvWithKv();
    const old = await register(env, { pubkey: fakePubkey(67), label: "a", usage: "kiosk" }, await opHeaders());
    const puts: string[] = [];
    const realPut = kv.put.bind(kv);
    (kv as unknown as { put: typeof kv.put }).put = (async (key: string, value: string) => {
      puts.push(key);
      return realPut(key, value);
    }) as typeof kv.put;
    const next = await register(env, { pubkey: fakePubkey(68), replaces_pubkey: fakePubkey(67) }, await opHeaders());
    expect(puts).toEqual([`alarmkey:${next}`, "alarmkeys:tenant-1", `alarmkey:${old}`]);
  });

  it("監査ログは明示したときだけ。登録簿の種別と真偽だけ (fingerprint・tenant・メールアドレスを出さない)", async () => {
    const { env } = makeEnvWithKv();
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      await register(env, { pubkey: fakePubkey(70), label: "a", usage: "kiosk" }, await devHeaders());
      await handleAlarmKeyRegister(
        postJson(PATH, { pubkey: fakePubkey(71), label: "a", usage: "kiosk", dev_device: true }, await opHeaders()),
        env,
      );
      expect(spy.mock.calls).toEqual([]);
      await register(env, { pubkey: fakePubkey(72), replaces_pubkey: fakePubkey(70), dev_device: true }, await devHeaders());
      // 明示なしの引き継ぎ (dev のまま) では出ない
      await register(env, { pubkey: fakePubkey(73), replaces_pubkey: fakePubkey(72) }, await opHeaders());
      await register(env, { pubkey: fakePubkey(74), label: "b", usage: "kiosk", dev_device: false }, await devHeaders());
      expect(spy.mock.calls.map((c) => String(c[0]))).toEqual([
        JSON.stringify({ event: "dev_device_set", registry: "alarm-key", dev_device: true }),
        JSON.stringify({ event: "dev_device_set", registry: "alarm-key", dev_device: false }),
      ]);
    } finally {
      spy.mockRestore();
    }
  });

  it("GET /device/setup/alarm-keys は各行に dev_device を boolean で返す", async () => {
    const { env } = makeEnvWithKv();
    const devFp = await register(env, { pubkey: fakePubkey(75), label: "cab-1", usage: "kiosk", dev_device: true }, await devHeaders());
    const plainFp = await register(env, { pubkey: fakePubkey(76), label: "cab-2", usage: "kiosk" }, await opHeaders());
    const res = await handleAlarmKeyList(getReq("/device/setup/alarm-keys", await opCookie()), env);
    const data = (await res.json()) as { keys: Array<{ fingerprint: string; dev_device: unknown }> };
    const byFp = Object.fromEntries(data.keys.map((k) => [k.fingerprint, k.dev_device]));
    expect(byFp[devFp]).toBe(true);
    expect(byFp[plainFp]).toBe(false);
  });
});
