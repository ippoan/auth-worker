import { describe, it, expect } from "vitest";
import {
  handleAlarmKeyRegister,
  handleAlarmKeyList,
  handleAlarmKeyRevoke,
} from "../../src/handlers/alarm-key";
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
        { pubkey: fakePubkey(1), label: "cab-1" },
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
      postJson("/device/setup/alarm-key", { pubkey: fakePubkey(2), label: "x" }, originHeaders),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("403 bad_origin when Origin header doesn't match the issuer", async () => {
    const env = makeEnv();
    const res = await handleAlarmKeyRegister(
      postJson("/device/setup/alarm-key", { pubkey: fakePubkey(3), label: "x" }, await opCookie()),
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
        { pubkey: "not-base64url-32-bytes", label: "x" },
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
        { pubkey: shortKey, label: "x" },
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
        { pubkey: fakePubkey(4), label: "" },
        await withOpCookieAndOrigin(),
      ),
      env,
    );
    expect(empty.status).toBe(400);

    const tooLong = await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: fakePubkey(5), label: "x".repeat(65) },
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
      postJson("/device/setup/alarm-key", { pubkey, label: "cab-1" }, headers),
      env,
    );
    expect(first.status).toBe(200);
    const second = await handleAlarmKeyRegister(
      postJson("/device/setup/alarm-key", { pubkey, label: "cab-1-dup" }, headers),
      env,
    );
    expect(second.status).toBe(409);
  });
});

describe("handleAlarmKeyList", () => {
  it("lists registered keys for the operator's tenant, without the pubkey field", async () => {
    const env = makeEnv();
    const headers = await withOpCookieAndOrigin();
    await handleAlarmKeyRegister(
      postJson("/device/setup/alarm-key", { pubkey: fakePubkey(7), label: "cab-1" }, headers),
      env,
    );
    const res = await handleAlarmKeyList(
      getReq("/device/setup/alarm-keys", await withOpCookieAndOrigin()),
      env,
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      keys: Array<{ fingerprint: string; label: string; created_at: number; revoked_at?: number }>;
    };
    expect(data.keys).toHaveLength(1);
    expect(data.keys[0]!.label).toBe("cab-1");
    expect(data.keys[0]!.revoked_at).toBeUndefined();
    expect(data.keys[0]).not.toHaveProperty("pubkey");
  });

  it("401 without a session cookie", async () => {
    const env = makeEnv();
    const res = await handleAlarmKeyList(getReq("/device/setup/alarm-keys"), env);
    expect(res.status).toBe(401);
  });

  it("does not include another tenant's keys", async () => {
    const env = makeEnv();
    await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: fakePubkey(8), label: "tenant-1-key" },
        await withOpCookieAndOrigin({ tenant_id: "tenant-1" }),
      ),
      env,
    );
    await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: fakePubkey(9), label: "tenant-2-key" },
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
      postJson("/device/setup/alarm-key", { pubkey: fakePubkey(10), label: "cab-1" }, headers),
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
        { pubkey: fakePubkey(11), label: "tenant-1-key" },
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

describe("body / KV の壊れたデータに対するフォールバック", () => {
  it("400 when pubkey contains characters that aren't valid base64url at all", async () => {
    const env = makeEnv();
    const res = await handleAlarmKeyRegister(
      postJson(
        "/device/setup/alarm-key",
        { pubkey: "!!!not valid base64!!!", label: "x" },
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
      postJson("/device/setup/alarm-key", { pubkey: fakePubkey(12), label: "cab-1" }, headers),
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
      postJson("/device/setup/alarm-key", { pubkey, label: "cab-1" }, headers),
      env,
    );
    const { fingerprint } = (await reg.json()) as { fingerprint: string };
    // record だけ消し、索引には fingerprint が残っている状態を作る
    delete kv._data[`alarmkey:${fingerprint}`];

    const second = await handleAlarmKeyRegister(
      postJson("/device/setup/alarm-key", { pubkey, label: "cab-1-again" }, headers),
      env,
    );
    expect(second.status).toBe(200);
    const index = JSON.parse(kv._data["alarmkeys:tenant-1"]!) as string[];
    expect(index.filter((f) => f === fingerprint)).toHaveLength(1);
  });
});
