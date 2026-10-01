import { describe, it, expect, vi } from "vitest";
import {
  handleAlarmKeyRegister,
  handleAlarmKeyList,
  handleAlarmKeyRevoke,
  handleAlarmKeyDevDevice,
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
 * 警告デバイスの鍵を開発用にする・外す口 (Refs ippoan/alc-app#387)。
 * 通すのは「開発者アカウントが Google でログインした session」だけ。
 * 開発者のメールアドレスの値はテストに書かない (登録簿の先頭を借りる)。
 */
describe("handleAlarmKeyDevDevice (Refs ippoan/alc-app#387)", () => {
  const DEV_EMAIL = DEVELOPER_EMAILS[0]!;
  const PATH = "/device/setup/alarm-key/dev-device";

  /** 開発者が Google で入った session (この口を通れる唯一の形)。 */
  async function devHeaders(claims: Record<string, unknown> = {}): Promise<Record<string, string>> {
    return withOpCookieAndOrigin({ email: DEV_EMAIL, idp: "google", ...claims });
  }

  /** tenant-1 に鍵を 1 本登録した env。 */
  async function envWithKey(seed: number) {
    const { env, kv } = makeEnvWithKv();
    const reg = await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: fakePubkey(seed), label: "cab-1", usage: "kiosk" },
        await withOpCookieAndOrigin(),
      ),
      env,
    );
    const { fingerprint } = (await reg.json()) as { fingerprint: string };
    const read = () => JSON.parse(kv._data[`alarmkey:${fingerprint}`]!) as Record<string, unknown>;
    return { env, fingerprint, read };
  }

  it("cookie なしは 401、Origin 違いは 403 bad_origin", async () => {
    const { env, fingerprint, read } = await envWithKey(40);
    const body = { fingerprint, dev_device: true };
    const noCookie = await handleAlarmKeyDevDevice(postJson(PATH, body, originHeaders), env);
    expect(noCookie.status).toBe(401);

    const badOrigin = await handleAlarmKeyDevDevice(
      postJson(PATH, body, { ...(await devHeaders()), Origin: "https://evil.example" }),
      env,
    );
    expect(badOrigin.status).toBe(403);
    expect(await badOrigin.json()).toEqual({ error: "bad_origin" });
    expect(read()).not.toHaveProperty("dev_device");
  });

  it.each(["dev", "device-key"])(
    "開発者の email + idp=google でも token_kind=%s は 403 dev_token_write_forbidden",
    async (tokenKind) => {
      const { env, fingerprint, read } = await envWithKey(41);
      const res = await handleAlarmKeyDevDevice(
        postJson(PATH, { fingerprint, dev_device: true }, await devHeaders({ token_kind: tokenKind })),
        env,
      );
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "dev_token_write_forbidden" });
      expect(read()).not.toHaveProperty("dev_device");
    },
  );

  it.each([
    ["開発者でない管理者 (Google ログイン)", { email: "op@example.com", idp: "google" }],
    ["開発者の email だが idp なし (LINE WORKS のログイン・古い cookie)", { email: DEV_EMAIL }],
    ["開発者の email だが idp が別の値", { email: DEV_EMAIL, idp: "lineworks" }],
    ["email の無い session", { email: "", idp: "google" }],
  ])("%s は 403 developer_google_session_required (書き換えない)", async (_name, claims) => {
    const { env, fingerprint, read } = await envWithKey(42);
    const res = await handleAlarmKeyDevDevice(
      postJson(PATH, { fingerprint, dev_device: true }, await withOpCookieAndOrigin(claims)),
      env,
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "developer_google_session_required" });
    expect(read()).not.toHaveProperty("dev_device");
  });

  it("開発者でない者には、存在する鍵と存在しない鍵で応答が同じ (有無を漏らさない)", async () => {
    const { env, fingerprint } = await envWithKey(43);
    const headers = await withOpCookieAndOrigin({ idp: "google" });
    const existing = await handleAlarmKeyDevDevice(
      postJson(PATH, { fingerprint, dev_device: true }, headers),
      env,
    );
    const missing = await handleAlarmKeyDevDevice(
      postJson(PATH, { fingerprint: "fp-missing", dev_device: true }, headers),
      env,
    );
    expect(existing.status).toBe(403);
    expect(missing.status).toBe(existing.status);
    expect(await missing.text()).toBe(await existing.text());
  });

  it("fingerprint が無ければ 400", async () => {
    const { env } = await envWithKey(44);
    const res = await handleAlarmKeyDevDevice(postJson(PATH, { dev_device: true }, await devHeaders()), env);
    expect(res.status).toBe(400);
  });

  it.each([
    ["文字列 \"true\"", { dev_device: "true" }],
    ["数値 1", { dev_device: 1 }],
    ["null", { dev_device: null }],
    ["欠落", {}],
  ])("dev_device が boolean でない (%s) は 400 (書き換えない)", async (_name, extra) => {
    const { env, fingerprint, read } = await envWithKey(45);
    const res = await handleAlarmKeyDevDevice(
      postJson(PATH, { fingerprint, ...extra }, await devHeaders()),
      env,
    );
    expect(res.status).toBe(400);
    expect(read()).not.toHaveProperty("dev_device");
  });

  it("他 tenant の鍵と不在の鍵は同じ 403 not_found", async () => {
    const { env, fingerprint, read } = await envWithKey(46);
    const otherTenant = await handleAlarmKeyDevDevice(
      postJson(PATH, { fingerprint, dev_device: true }, await devHeaders({ tenant_id: "tenant-2" })),
      env,
    );
    const missing = await handleAlarmKeyDevDevice(
      postJson(PATH, { fingerprint: "fp-missing", dev_device: true }, await devHeaders()),
      env,
    );
    for (const res of [otherTenant, missing]) {
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "not_found" });
    }
    expect(read()).not.toHaveProperty("dev_device");
  });

  it("失効済みの鍵は 409 revoked (書き換えない)", async () => {
    const { env, fingerprint, read } = await envWithKey(47);
    await handleAlarmKeyRevoke(
      postJson("/device/setup/alarm-key/revoke", { fingerprint }, await withOpCookieAndOrigin()),
      env,
    );
    const before = read();
    const res = await handleAlarmKeyDevDevice(
      postJson(PATH, { fingerprint, dev_device: true }, await devHeaders()),
      env,
    );
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "revoked" });
    expect(read()).toEqual(before);
  });

  it("開発者の Google session: true で record に dev_device: true (ほかの欄は不変)、2 回目も同じ", async () => {
    const { env, fingerprint, read } = await envWithKey(48);
    const before = read();
    for (let i = 0; i < 2; i++) {
      const res = await handleAlarmKeyDevDevice(
        postJson(PATH, { fingerprint, dev_device: true }, await devHeaders()),
        env,
      );
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ fingerprint, dev_device: true });
      expect(read()).toEqual({ ...before, dev_device: true });
    }
  });

  it("開発者の Google session: false で欄ごと消える (ほかの欄は不変)、2 回目も同じ", async () => {
    const { env, fingerprint, read } = await envWithKey(49);
    const before = read();
    await handleAlarmKeyDevDevice(
      postJson(PATH, { fingerprint, dev_device: true }, await devHeaders()),
      env,
    );
    for (let i = 0; i < 2; i++) {
      const res = await handleAlarmKeyDevDevice(
        postJson(PATH, { fingerprint, dev_device: false }, await devHeaders()),
        env,
      );
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ fingerprint, dev_device: false });
      expect(read()).not.toHaveProperty("dev_device");
      expect(read()).toEqual(before);
    }
  });

  it("書き換えのログは登録簿の種別と真偽だけ (fingerprint・tenant・メールアドレスを出さない)", async () => {
    const { env, fingerprint } = await envWithKey(50);
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      await handleAlarmKeyDevDevice(
        postJson(PATH, { fingerprint, dev_device: false }, await devHeaders()),
        env,
      );
      expect(spy.mock.calls.map((c) => String(c[0]))).toEqual([
        JSON.stringify({ event: "dev_device_set", registry: "alarm-key", dev_device: false }),
      ]);
    } finally {
      spy.mockRestore();
    }
  });

  it("GET /device/setup/alarm-keys は各行に dev_device を boolean で返す", async () => {
    const { env, fingerprint } = await envWithKey(51);
    const second = await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: fakePubkey(52), label: "cab-2", usage: "kiosk" },
        await withOpCookieAndOrigin(),
      ),
      env,
    );
    const plainFp = ((await second.json()) as { fingerprint: string }).fingerprint;
    await handleAlarmKeyDevDevice(
      postJson(PATH, { fingerprint, dev_device: true }, await devHeaders()),
      env,
    );
    const res = await handleAlarmKeyList(getReq("/device/setup/alarm-keys", await opCookie()), env);
    const data = (await res.json()) as { keys: Array<{ fingerprint: string; dev_device: unknown }> };
    const byFp = Object.fromEntries(data.keys.map((k) => [k.fingerprint, k.dev_device]));
    expect(byFp[fingerprint]).toBe(true);
    expect(byFp[plainFp]).toBe(false);
  });
});
