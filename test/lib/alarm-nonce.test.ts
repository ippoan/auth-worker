import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import {
  issueAlarmNonce,
  consumeAlarmNonce,
  verifyAlarmSignature,
  buildAlarmSignedMessage,
  ALARM_NONCE_TTL_SEC,
  ALARM_NONCE_PURPOSES,
} from "../../src/lib/alarm-nonce";
import { ALARM_KEY_USAGES, type AlarmKeyUsage } from "../../src/handlers/alarm-key";
import { createMockEnv, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const REDIRECT_URI = "https://app1.test.example/page";
const NONCE = "0123456789abcdef0123456789abcdef";

// Refs ippoan/alc-app#353: `AlarmKeyUsage` (鍵の usage) と `AlarmNoncePurpose`
// (nonce の purpose) は同じ語彙のはずが、以前は別々に手書きしていて
// `admin-login` (usage) と `login` (purpose) が食い違っていた。配列の一致を
// 実行時に検査して固定する (型だけでは足し忘れが出ない)。
describe("AlarmKeyUsage と AlarmNoncePurpose の語彙", () => {
  it("ALARM_KEY_USAGES と ALARM_NONCE_PURPOSES が一致する", () => {
    expect(ALARM_NONCE_PURPOSES).toEqual(ALARM_KEY_USAGES);
  });
});

function kv(env: Env): MockKV {
  return env.AUTH_CONFIG as unknown as MockKV;
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

describe("issueAlarmNonce", () => {
  it("kiosk: purpose だけを持ち redirect_uri を持たない record を TTL 60 で積む", async () => {
    const env = createMockEnv();
    const nonce = await issueAlarmNonce(env, { purpose: "kiosk" });
    expect(nonce).toMatch(/^[0-9a-f]{32}$/);
    const stored = JSON.parse(kv(env)._data[`devnonce:${nonce}`]!) as Record<string, unknown>;
    expect(stored.purpose).toBe("kiosk");
    expect(stored).not.toHaveProperty("redirect_uri");
    expect(stored.exp).toBeGreaterThan(nowSec());
    expect(kv(env)._ttls[`devnonce:${nonce}`]).toBe(ALARM_NONCE_TTL_SEC);
    expect(ALARM_NONCE_TTL_SEC).toBe(60);
  });

  it("redirect_uri 付きでも積める (purpose は問わない)", async () => {
    const env = createMockEnv();
    const nonce = await issueAlarmNonce(env, { purpose: "kiosk", redirectUri: REDIRECT_URI });
    const stored = JSON.parse(kv(env)._data[`devnonce:${nonce}`]!) as Record<string, unknown>;
    expect(stored.purpose).toBe("kiosk");
    expect(stored.redirect_uri).toBe(REDIRECT_URI);
  });
});

describe("consumeAlarmNonce", () => {
  it("purpose が一致すれば record を返し、KV から消す (single-use)", async () => {
    const env = createMockEnv();
    const nonce = await issueAlarmNonce(env, { purpose: "kiosk", redirectUri: REDIRECT_URI });

    const first = await consumeAlarmNonce(env, nonce, "kiosk");
    expect(first).toMatchObject({ purpose: "kiosk", redirect_uri: REDIRECT_URI });
    expect(kv(env)._data[`devnonce:${nonce}`]).toBeUndefined();

    expect(await consumeAlarmNonce(env, nonce, "kiosk")).toBeNull();
  });

  it("purpose が違えば null (その nonce は消費済みになる)", async () => {
    const env = createMockEnv();
    const nonce = await issueAlarmNonce(env, { purpose: "kiosk" });
    expect(await consumeAlarmNonce(env, nonce, "tenko-manager")).toBeNull();
    expect(kv(env)._data[`devnonce:${nonce}`]).toBeUndefined();
    expect(await consumeAlarmNonce(env, nonce, "kiosk")).toBeNull();
  });

  it.each([
    ["purpose の無い record (fail-closed)", { redirect_uri: REDIRECT_URI, exp: nowSec() + 60 }],
    ["未知の purpose", { purpose: "admin", exp: nowSec() + 60 }],
    ["exp が数値でない", { purpose: "kiosk", exp: "soon" }],
    ["期限切れ", { purpose: "kiosk", exp: nowSec() - 1 }],
  ])("%s は null", async (_label, record) => {
    const env = createMockEnv();
    const nonce = "d".repeat(32);
    kv(env)._data[`devnonce:${nonce}`] = JSON.stringify(record);
    expect(await consumeAlarmNonce(env, nonce, "kiosk")).toBeNull();
    expect(await consumeAlarmNonce(env, nonce, "tenko-manager")).toBeNull();
  });

  it("record が無い / JSON として壊れている → null", async () => {
    const env = createMockEnv();
    expect(await consumeAlarmNonce(env, "e".repeat(32), "kiosk")).toBeNull();
    kv(env)._data[`devnonce:${"f".repeat(32)}`] = "{not json";
    expect(await consumeAlarmNonce(env, "f".repeat(32), "kiosk")).toBeNull();
  });
});

describe("verifyAlarmSignature の用途 (usage) 照合", () => {
  /**
   * ed25519 の鍵対を作り、`alarmkey:<fp>` に record を積んで、NONCE (ASCII) への署名と
   * 一緒に返す。usage が null なら usage を持たない record にする。
   */
  function seedSignedKey(
    env: Env,
    usage: string | null,
  ): { pubkeyB64: string; sigB64: string; fp: string } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const pubDer = publicKey.export({ format: "der", type: "spki" });
    const pubRaw = pubDer.subarray(pubDer.length - 32);
    const fp = crypto.createHash("sha256").update(pubRaw).digest("hex").slice(0, 16);
    kv(env)._data[`alarmkey:${fp}`] = JSON.stringify({
      pubkey: pubRaw.toString("base64url"),
      tenant_id: "tenant-1",
      label: "test",
      ...(usage === null ? {} : { usage }),
      created_at: 1_700_000_000,
    });
    const sig = crypto.sign(null, Buffer.from(NONCE, "ascii"), privateKey);
    return { pubkeyB64: pubRaw.toString("base64url"), sigB64: sig.toString("base64url"), fp };
  }

  it.each<AlarmKeyUsage>(["kiosk", "tenko-manager"])("用途 %s が一致すれば鍵を返す", async (usage) => {
    const env = createMockEnv();
    const { pubkeyB64, sigB64, fp } = seedSignedKey(env, usage);
    const verified = await verifyAlarmSignature(env, { pubkeyB64, sigB64, nonce: NONCE, usage });
    expect(verified?.fingerprint).toBe(fp);
    expect(verified?.record.usage).toBe(usage);
  });

  it.each<[AlarmKeyUsage, AlarmKeyUsage]>([
    ["kiosk", "tenko-manager"],
    ["tenko-manager", "kiosk"],
  ])("用途 %s の鍵を %s の口で使うと null", async (registered, requested) => {
    const env = createMockEnv();
    const { pubkeyB64, sigB64 } = seedSignedKey(env, registered);
    expect(
      await verifyAlarmSignature(env, { pubkeyB64, sigB64, nonce: NONCE, usage: requested }),
    ).toBeNull();
  });

  it.each<AlarmKeyUsage>(["kiosk", "tenko-manager"])(
    "usage を持たない record は %s の口でも null (fail-closed)",
    async (usage) => {
      const env = createMockEnv();
      const { pubkeyB64, sigB64 } = seedSignedKey(env, null);
      expect(await verifyAlarmSignature(env, { pubkeyB64, sigB64, nonce: NONCE, usage })).toBeNull();
    },
  );

  it("未知の usage 値を持つ record も null", async () => {
    const env = createMockEnv();
    const { pubkeyB64, sigB64 } = seedSignedKey(env, "admin");
    expect(
      await verifyAlarmSignature(env, { pubkeyB64, sigB64, nonce: NONCE, usage: "kiosk" }),
    ).toBeNull();
  });

  it("pubkey/sig が base64url として不正 (decode throws) は null", async () => {
    const env = createMockEnv();
    seedSignedKey(env, "kiosk");
    expect(
      await verifyAlarmSignature(env, {
        pubkeyB64: "!!!not valid base64!!!",
        sigB64: "y",
        nonce: NONCE,
        usage: "kiosk",
      }),
    ).toBeNull();
  });

  it("decode 後の pubkey/sig の長さが不正 (32B/64B でない) は null", async () => {
    const env = createMockEnv();
    seedSignedKey(env, "kiosk");
    expect(
      await verifyAlarmSignature(env, {
        pubkeyB64: Buffer.from(new Uint8Array(10)).toString("base64url"), // 正しい base64url、長さが違う
        sigB64: Buffer.from(new Uint8Array(64)).toString("base64url"),
        nonce: NONCE,
        usage: "kiosk",
      }),
    ).toBeNull();
  });

  it("登録済み record の pubkey が壊れている (decode throws) は null", async () => {
    const env = createMockEnv();
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const pubDer = publicKey.export({ format: "der", type: "spki" });
    const pubRaw = pubDer.subarray(pubDer.length - 32);
    const fp = crypto.createHash("sha256").update(pubRaw).digest("hex").slice(0, 16);
    kv(env)._data[`alarmkey:${fp}`] = JSON.stringify({
      pubkey: "!!!corrupt!!!",
      tenant_id: "tenant-1",
      label: "test",
      usage: "kiosk",
      created_at: 1_700_000_000,
    });
    const sig = crypto.sign(null, Buffer.from(NONCE, "ascii"), privateKey);
    expect(
      await verifyAlarmSignature(env, {
        pubkeyB64: pubRaw.toString("base64url"),
        sigB64: sig.toString("base64url"),
        nonce: NONCE,
        usage: "kiosk",
      }),
    ).toBeNull();
  });
});

describe("buildAlarmSignedMessage (Refs #571、ippoan/alc-app-s3#249 と合意済みの形)", () => {
  it("bpBonded が undefined なら nonce だけ (古いファーム)", () => {
    expect(buildAlarmSignedMessage(NONCE)).toBe(NONCE);
    expect(buildAlarmSignedMessage(NONCE, undefined)).toBe(NONCE);
  });

  it("true/false は半角パイプ区切りで bp=1 / bp=0", () => {
    expect(buildAlarmSignedMessage(NONCE, true)).toBe(`${NONCE}|bp=1`);
    expect(buildAlarmSignedMessage(NONCE, false)).toBe(`${NONCE}|bp=0`);
  });
});

describe("verifyAlarmSignature のボンド状態 (bp) 署名 (Refs #571)", () => {
  /**
   * `seedSignedKey` と同じ鍵登録だが、署名対象は `buildAlarmSignedMessage(NONCE, bpBonded)`
   * (bpBonded 省略時は seedSignedKey と同じ nonce だけの署名 = 後方互換)。
   */
  function seedSignedKeyWithBp(
    env: Env,
    usage: AlarmKeyUsage,
    bpBonded?: boolean,
  ): { pubkeyB64: string; sigB64: string; fp: string } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const pubDer = publicKey.export({ format: "der", type: "spki" });
    const pubRaw = pubDer.subarray(pubDer.length - 32);
    const fp = crypto.createHash("sha256").update(pubRaw).digest("hex").slice(0, 16);
    kv(env)._data[`alarmkey:${fp}`] = JSON.stringify({
      pubkey: pubRaw.toString("base64url"),
      tenant_id: "tenant-1",
      label: "test",
      usage,
      created_at: 1_700_000_000,
    });
    const message = buildAlarmSignedMessage(NONCE, bpBonded);
    const sig = crypto.sign(null, Buffer.from(message, "ascii"), privateKey);
    return { pubkeyB64: pubRaw.toString("base64url"), sigB64: sig.toString("base64url"), fp };
  }

  it("後方互換: nonce だけの署名 (bpBonded 未指定) は今までどおり通る", async () => {
    const env = createMockEnv();
    const { pubkeyB64, sigB64, fp } = seedSignedKeyWithBp(env, "kiosk");
    const verified = await verifyAlarmSignature(env, { pubkeyB64, sigB64, nonce: NONCE, usage: "kiosk" });
    expect(verified?.fingerprint).toBe(fp);
  });

  it.each<[boolean, string]>([
    [true, "bp=1"],
    [false, "bp=0"],
  ])("新形式: nonce|%s への署名を bpBonded=%s で検証できる", async (bpBonded) => {
    const env = createMockEnv();
    const { pubkeyB64, sigB64, fp } = seedSignedKeyWithBp(env, "kiosk", bpBonded);
    const verified = await verifyAlarmSignature(env, {
      pubkeyB64,
      sigB64,
      nonce: NONCE,
      usage: "kiosk",
      bpBonded,
    });
    expect(verified?.fingerprint).toBe(fp);
  });

  it("bpBonded の値が署名対象と食い違えば null (bp=1 の署名を bp=0 として検証)", async () => {
    const env = createMockEnv();
    const { pubkeyB64, sigB64 } = seedSignedKeyWithBp(env, "kiosk", true);
    expect(
      await verifyAlarmSignature(env, { pubkeyB64, sigB64, nonce: NONCE, usage: "kiosk", bpBonded: false }),
    ).toBeNull();
  });

  it("bp 付きの署名を bpBonded 未指定 (nonce だけ) で検証しても null", async () => {
    const env = createMockEnv();
    const { pubkeyB64, sigB64 } = seedSignedKeyWithBp(env, "kiosk", true);
    expect(
      await verifyAlarmSignature(env, { pubkeyB64, sigB64, nonce: NONCE, usage: "kiosk" }),
    ).toBeNull();
  });

  it("nonce だけの署名を bpBonded 付きで検証しても null", async () => {
    const env = createMockEnv();
    const { pubkeyB64, sigB64 } = seedSignedKeyWithBp(env, "kiosk");
    expect(
      await verifyAlarmSignature(env, { pubkeyB64, sigB64, nonce: NONCE, usage: "kiosk", bpBonded: true }),
    ).toBeNull();
  });
});
