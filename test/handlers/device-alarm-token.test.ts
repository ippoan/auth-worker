/**
 * GET /device/alarm-nonce, POST /device/alarm-token (Refs #551) — 警告デバイスの署名で
 * 短命の端末 JWT (device-kiosk) を返す口。出した JWT が `/device-data-proxy` の kiosk
 * 許可表を通り、`/device/claim-ticket` では弾かれるところまでをここで固定する。
 */
import { describe, it, expect, vi, afterAll } from "vitest";
import crypto from "node:crypto";

// OIDC mint は別ユニットでテスト済み。proxy を通す確認では forward 先だけ見る。
vi.mock("../../src/lib/oidc", () => ({
  mintGoogleIdToken: vi.fn(async () => "fake-oidc-token"),
}));

import {
  handleDeviceAlarmNonce,
  handleDeviceAlarmToken,
  ALARM_TOKEN_TTL_SEC,
  roleForUsage,
} from "../../src/handlers/device-alarm-token";
import { handleDeviceDataProxy } from "../../src/handlers/device-data-proxy";
import { handleDeviceClaimTicket } from "../../src/handlers/device-claim-ticket";
import {
  DEVICE_JWT_AUDIENCE,
  DEVICE_ROLE_KIOSK,
  DEVICE_ROLE_TENKO_MANAGER,
  DEVICE_ROLE_BP_STATION,
} from "../../src/lib/device";
import { decodeJwtPayload } from "../../src/lib/jwt";
import { createMockEnv, createMockKV, type MockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const AUTH_ORIGIN = "https://auth.test.example";
const ALLOWED_ORIGINS =
  "https://app1.test.example,https://app2.test.example,https://auth.test.example";
const REDIRECT_URI = "https://app1.test.example/page";
const TENANT_ID = "tenant-alarm-kiosk-1";

const originalFetch = globalThis.fetch;
afterAll(() => {
  globalThis.fetch = originalFetch;
});

interface Keypair {
  pubRaw: Uint8Array;
  privateKey: crypto.KeyObject;
}

function generateKeypair(): Keypair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubDer = publicKey.export({ format: "der", type: "spki" });
  const pubRaw = new Uint8Array(pubDer.subarray(pubDer.length - 32));
  return { pubRaw, privateKey };
}

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function fingerprintHex(raw: Uint8Array): string {
  return crypto.createHash("sha256").update(raw).digest("hex").slice(0, 16);
}

/** firmware と同じ契約: 署名対象は nonce (小文字hex32文字) の **ASCII バイト**。 */
function signNonceAscii(privateKey: crypto.KeyObject, nonce: string): string {
  return b64url(new Uint8Array(crypto.sign(null, Buffer.from(nonce, "ascii"), privateKey)));
}

/**
 * 血圧計のボンド状態込みの署名 (Refs #571)。`bpBonded` 省略時は `signNonceAscii` と
 * 同じ (nonce だけの署名、古いファーム互換)。
 */
function signAlarmMessageAscii(
  privateKey: crypto.KeyObject,
  nonce: string,
  bpBonded?: boolean,
): string {
  const message = bpBonded === undefined ? nonce : `${nonce}|bp=${bpBonded ? "1" : "0"}`;
  return b64url(new Uint8Array(crypto.sign(null, Buffer.from(message, "ascii"), privateKey)));
}

/** usage の既定はこの口の用途 (kiosk)。null で usage を持たない record にする。 */
function alarmKeySeed(
  pubRaw: Uint8Array,
  opts: { revoked?: boolean; usage?: string | null } = {},
): { fp: string; kv: Record<string, string> } {
  const fp = fingerprintHex(pubRaw);
  const record = {
    pubkey: b64url(pubRaw),
    tenant_id: TENANT_ID,
    label: "テスト警告灯",
    ...(opts.usage === null ? {} : { usage: opts.usage ?? "kiosk" }),
    created_at: 1_700_000_000,
    ...(opts.revoked ? { revoked_at: 1_700_000_500 } : {}),
  };
  return { fp, kv: { [`alarmkey:${fp}`]: JSON.stringify(record) } };
}

function makeEnv(kvSeed: Record<string, string> = {}, overrides: Partial<Env> = {}): Env {
  return createMockEnv({
    AUTH_CONFIG: createMockKV({ "origins:prod": ALLOWED_ORIGINS, ...kvSeed }),
    MCP_OAUTH_KV: createMockKV(),
    ALC_API_PROXY_SA_KEY: "{}", // resolveSecret が非空を返せばよい (oidc は mock)
    ...overrides,
  });
}

function nonceRequest(): Request {
  return new Request(`${AUTH_ORIGIN}/device/alarm-nonce`);
}

function tokenRequest(body: unknown, rawBody?: string): Request {
  return new Request(`${AUTH_ORIGIN}/device/alarm-token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: rawBody ?? JSON.stringify(body),
  });
}

async function issueKioskNonce(env: Env): Promise<string> {
  const res = await handleDeviceAlarmNonce(nonceRequest(), env);
  expect(res.status).toBe(200);
  const { nonce } = (await res.json()) as { nonce: string; expires_in: number };
  return nonce;
}

/** alarm-nonce → firmware 署名 → alarm-token の body を組み立てる。 */
async function signedBody(
  env: Env,
  keypair: Keypair,
): Promise<{ nonce: string; pubkey: string; sig: string }> {
  const nonce = await issueKioskNonce(env);
  return { nonce, pubkey: b64url(keypair.pubRaw), sig: signNonceAscii(keypair.privateKey, nonce) };
}

/** `signedBody` のボンド状態込み版 (Refs #571)。`bp_bonded` を body に含めて返す。 */
async function signedBodyWithBp(
  env: Env,
  keypair: Keypair,
  bpBonded: boolean,
): Promise<{ nonce: string; pubkey: string; sig: string; bp_bonded: boolean }> {
  const nonce = await issueKioskNonce(env);
  return {
    nonce,
    pubkey: b64url(keypair.pubRaw),
    sig: signAlarmMessageAscii(keypair.privateKey, nonce, bpBonded),
    bp_bonded: bpBonded,
  };
}

async function expectInvalid(res: Response): Promise<void> {
  expect(res.status).toBe(401);
  expect(await res.json()).toEqual({ error: "invalid_alarm_token" });
}

/**
 * rate limit / exp の KV key は時刻から作るので、Date を固定して回す。
 * (同じ describe に他のテストがあるので、hook ではなく it の中の try/finally で囲む)
 */
async function withFixedDate<T>(ms: number, fn: () => Promise<T>): Promise<T> {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(ms);
  try {
    return await fn();
  } finally {
    vi.useRealTimers();
  }
}

function currentMinuteMs(): number {
  return Math.floor(Date.now() / 60_000) * 60_000;
}

async function mintKioskToken(env: Env, keypair: Keypair): Promise<string> {
  const res = await handleDeviceAlarmToken(tokenRequest(await signedBody(env, keypair)), env);
  expect(res.status).toBe(200);
  return ((await res.json()) as { access_token: string }).access_token;
}

describe("GET /device/alarm-nonce", () => {
  it("purpose=kiosk の nonce を redirect_uri 無しで積み、CORS + no-store で返す", async () => {
    const env = makeEnv();
    const res = await handleDeviceAlarmNonce(nonceRequest(), env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    const body = (await res.json()) as { nonce: string; expires_in: number };
    expect(body.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(body.expires_in).toBe(60);
    const stored = JSON.parse(
      (env.AUTH_CONFIG as unknown as MockKV)._data[`devnonce:${body.nonce}`]!,
    ) as Record<string, unknown>;
    expect(stored.purpose).toBe("kiosk");
    expect(stored).not.toHaveProperty("redirect_uri");
  });

  it("同じ IP から 30 回/分を超えると 429", async () => {
    await withFixedDate(currentMinuteMs(), async () => {
      const env = makeEnv();
      for (let i = 0; i < 30; i++) {
        const res = await handleDeviceAlarmNonce(nonceRequest(), env);
        expect(res.status, `attempt ${i + 1}`).toBe(200);
      }
      const res = await handleDeviceAlarmNonce(nonceRequest(), env);
      expect(res.status).toBe(429);
      expect(await res.json()).toEqual({ error: "rate_limited" });
    });
  });
});

describe("POST /device/alarm-token", () => {
  it("登録済み・未失効の鍵の署名で 200、/device/token と同じ形で端末 JWT を返す", async () => {
    const fixedMs = currentMinuteMs() + 5_000;
    await withFixedDate(fixedMs, async () => {
      const keypair = generateKeypair();
      const { fp, kv } = alarmKeySeed(keypair.pubRaw);
      const env = makeEnv(kv);
      const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
      try {
        const res = await handleDeviceAlarmToken(tokenRequest(await signedBody(env, keypair)), env);
        expect(res.status).toBe(200);
        expect(res.headers.get("Cache-Control")).toBe("no-store");
        expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
        const body = (await res.json()) as Record<string, unknown>;
        expect(Object.keys(body).sort()).toEqual(
          ["access_token", "expires_in", "tenant_id", "token_type"].sort(),
        );
        expect(body.token_type).toBe("Bearer");
        expect(body.expires_in).toBe(900);
        expect(ALARM_TOKEN_TTL_SEC).toBe(900);
        expect(body.tenant_id).toBe(TENANT_ID);

        const token = body.access_token as string;
        const payload = decodeJwtPayload(token)!;
        const nowSec = Math.floor(fixedMs / 1000);
        expect(payload.aud).toBe(DEVICE_JWT_AUDIENCE);
        expect(payload.aud).toBe("device");
        expect(payload.role).toBe(DEVICE_ROLE_KIOSK);
        expect(payload.role).toBe("device-kiosk");
        expect(payload.tenant_id).toBe(TENANT_ID);
        expect(payload.sub).toBe(`alarm:${fp}`);
        expect(payload.iat).toBe(nowSec);
        expect(payload.exp).toBe(nowSec + 900);

        // 監査: fingerprint とテナントまで。token は出さない。
        const lines = logSpy.mock.calls.map((c) => String(c[0]));
        const audit = lines.filter((l) => l.includes("device_alarm_token_success"));
        expect(audit).toHaveLength(1);
        expect(JSON.parse(audit[0]!)).toEqual({
          event: "device_alarm_token_success",
          fingerprint: fp,
          tenantId: TENANT_ID,
        });
        expect(lines.some((l) => l.includes(token))).toBe(false);
      } finally {
        logSpy.mockRestore();
      }
    });
  });

  it("未登録の鍵は 401", async () => {
    const registered = generateKeypair();
    const unregistered = generateKeypair();
    const env = makeEnv(alarmKeySeed(registered.pubRaw).kv);
    await expectInvalid(
      await handleDeviceAlarmToken(tokenRequest(await signedBody(env, unregistered)), env),
    );
  });

  it("失効した鍵は 401", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw, { revoked: true }).kv);
    await expectInvalid(
      await handleDeviceAlarmToken(tokenRequest(await signedBody(env, keypair)), env),
    );
  });

  it("用途 admin-login で登録した鍵は 401 (用途違い)", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw, { usage: "admin-login" }).kv);
    await expectInvalid(
      await handleDeviceAlarmToken(tokenRequest(await signedBody(env, keypair)), env),
    );
  });

  it("usage を持たない鍵の record は 401 (fail-closed)", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw, { usage: null }).kv);
    await expectInvalid(
      await handleDeviceAlarmToken(tokenRequest(await signedBody(env, keypair)), env),
    );
  });

  it("nonce の再利用は 401 (single-use)", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
    const body = await signedBody(env, keypair);
    expect((await handleDeviceAlarmToken(tokenRequest(body), env)).status).toBe(200);
    await expectInvalid(await handleDeviceAlarmToken(tokenRequest(body), env));
  });

  it("purpose の無い nonce record は 401 (fail-closed)", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
    const nonce = "a".repeat(32);
    (env.AUTH_CONFIG as unknown as MockKV)._data[`devnonce:${nonce}`] = JSON.stringify({
      exp: Math.floor(Date.now() / 1000) + 60,
    });
    await expectInvalid(
      await handleDeviceAlarmToken(
        tokenRequest({
          nonce,
          pubkey: b64url(keypair.pubRaw),
          sig: signNonceAscii(keypair.privateKey, nonce),
        }),
        env,
      ),
    );
  });

  it("署名不一致 (改ざん) は 401", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
    const body = await signedBody(env, keypair);
    const tampered = Buffer.from(body.sig, "base64url");
    tampered[0] = tampered[0]! ^ 0xff;
    await expectInvalid(
      await handleDeviceAlarmToken(
        tokenRequest({ ...body, sig: tampered.toString("base64url") }),
        env,
      ),
    );
  });

  it("期限切れの nonce は 401", async () => {
    const t0 = currentMinuteMs();
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
    const body = await withFixedDate(t0, () => signedBody(env, keypair));
    await withFixedDate(t0 + 61_000, async () => {
      await expectInvalid(await handleDeviceAlarmToken(tokenRequest(body), env));
    });
  });

  it.each([
    ["body が空", undefined, ""],
    ["body が JSON でない", undefined, "{not json"],
    ["body が null", null, undefined],
    ["フィールドが欠けている", { nonce: "a".repeat(32) }, undefined],
    ["フィールドが文字列でない", { nonce: 1, pubkey: 2, sig: 3 }, undefined],
  ])("%s は 401", async (_label, body, raw) => {
    const env = makeEnv();
    await expectInvalid(await handleDeviceAlarmToken(tokenRequest(body, raw), env));
  });

  it("鍵ごとに 10 回/分を超えると 429", async () => {
    await withFixedDate(currentMinuteMs(), async () => {
      const keypair = generateKeypair();
      const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
      for (let i = 0; i < 10; i++) {
        const res = await handleDeviceAlarmToken(tokenRequest(await signedBody(env, keypair)), env);
        expect(res.status, `attempt ${i + 1}`).toBe(200);
      }
      const res = await handleDeviceAlarmToken(tokenRequest(await signedBody(env, keypair)), env);
      expect(res.status).toBe(429);
      expect(await res.json()).toEqual({ error: "rate_limited" });

      // 別の鍵の枠は消費していない。
      const other = generateKeypair();
      (env.AUTH_CONFIG as unknown as MockKV)._data[`alarmkey:${fingerprintHex(other.pubRaw)}`] =
        alarmKeySeed(other.pubRaw).kv[`alarmkey:${fingerprintHex(other.pubRaw)}`]!;
      const otherRes = await handleDeviceAlarmToken(tokenRequest(await signedBody(env, other)), env);
      expect(otherRes.status).toBe(200);
    });
  });

  it("署名が通らない試行は鍵ごとの枠を消費しない", async () => {
    await withFixedDate(currentMinuteMs(), async () => {
      const keypair = generateKeypair();
      const attacker = generateKeypair();
      const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
      for (let i = 0; i < 12; i++) {
        const nonce = await issueKioskNonce(env);
        // 他人の公開鍵を名乗り、自分の鍵で署名する。
        const res = await handleDeviceAlarmToken(
          tokenRequest({
            nonce,
            pubkey: b64url(keypair.pubRaw),
            sig: signNonceAscii(attacker.privateKey, nonce),
          }),
          env,
        );
        expect(res.status, `attempt ${i + 1}`).toBe(401);
      }
      const res = await handleDeviceAlarmToken(tokenRequest(await signedBody(env, keypair)), env);
      expect(res.status).toBe(200);
    });
  });

  it("同じ IP から 30 回/分を超えると 429 (body を読む前)", async () => {
    await withFixedDate(currentMinuteMs(), async () => {
      const env = makeEnv();
      for (let i = 0; i < 30; i++) {
        const res = await handleDeviceAlarmToken(tokenRequest({}), env);
        expect(res.status, `attempt ${i + 1}`).toBe(401);
      }
      const res = await handleDeviceAlarmToken(tokenRequest({}), env);
      expect(res.status).toBe(429);
    });
  });

  it("JWT_SECRET 未設定は 503", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv, { JWT_SECRET: undefined });
    const res = await handleDeviceAlarmToken(tokenRequest(await signedBody(env, keypair)), env);
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "server_error" });
  });
});

describe("POST /device/alarm-token のボンド状態 (bp、Refs #571)", () => {
  it("後方互換: 古いファーム (nonce だけの署名、bp_bonded 無し) は今までどおり 200 で、JWT に bp_bonded claim が無い", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
    const res = await handleDeviceAlarmToken(tokenRequest(await signedBody(env, keypair)), env);
    expect(res.status).toBe(200);
    const { access_token } = (await res.json()) as { access_token: string };
    const payload = decodeJwtPayload(access_token)!;
    expect(payload).not.toHaveProperty("bp_bonded");
  });

  it.each([true, false])(
    "新形式: nonce|bp=%s への署名は 200 で、JWT の bp_bonded claim に %s がそのまま載る",
    async (bpBonded) => {
      const keypair = generateKeypair();
      const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
      const res = await handleDeviceAlarmToken(
        tokenRequest(await signedBodyWithBp(env, keypair, bpBonded)),
        env,
      );
      expect(res.status).toBe(200);
      const { access_token } = (await res.json()) as { access_token: string };
      const payload = decodeJwtPayload(access_token)!;
      expect(payload.bp_bonded).toBe(bpBonded);
    },
  );

  it("bp_bonded=false と「claim 無し (不明)」は区別される", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);

    const falseRes = await handleDeviceAlarmToken(
      tokenRequest(await signedBodyWithBp(env, keypair, false)),
      env,
    );
    const falsePayload = decodeJwtPayload(
      ((await falseRes.json()) as { access_token: string }).access_token,
    )!;
    expect("bp_bonded" in falsePayload).toBe(true);
    expect(falsePayload.bp_bonded).toBe(false);

    const unknownRes = await handleDeviceAlarmToken(tokenRequest(await signedBody(env, keypair)), env);
    const unknownPayload = decodeJwtPayload(
      ((await unknownRes.json()) as { access_token: string }).access_token,
    )!;
    expect("bp_bonded" in unknownPayload).toBe(false);
  });

  it("bp_bonded の値と署名対象が食い違えば (改ざん) 401", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
    const body = await signedBodyWithBp(env, keypair, true);
    // 署名は bp=1 のままだが、body の bp_bonded だけ false に書き換える。
    await expectInvalid(
      await handleDeviceAlarmToken(tokenRequest({ ...body, bp_bonded: false }), env),
    );
  });

  it("bp_bonded が boolean でなければ 401", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
    const body = await signedBody(env, keypair);
    await expectInvalid(
      await handleDeviceAlarmToken(tokenRequest({ ...body, bp_bonded: "true" }), env),
    );
  });
});

describe("出した端末 JWT の届く範囲", () => {
  it("/device-data-proxy の kiosk 許可表の 1 本を通り、X-Tenant-ID は鍵のテナント", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
    const token = await mintKioskToken(env, keypair);

    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await handleDeviceDataProxy(
      new Request(`${AUTH_ORIGIN}/device-data-proxy/api/tenko/dashboard`, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
      }),
      env,
    );
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [target, init] = fetchMock.mock.calls[0]!;
    expect(String(target)).toBe("https://alc-api.test.example/api/tenko/dashboard");
    expect((init!.headers as Record<string, string>)["X-Tenant-ID"]).toBe(TENANT_ID);
  });

  it("/device-data-proxy の kiosk 許可表に無い経路は 403", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
    const token = await mintKioskToken(env, keypair);
    const res = await handleDeviceDataProxy(
      new Request(`${AUTH_ORIGIN}/device-data-proxy/api/files`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      }),
      env,
    );
    expect(res.status).toBe(403);
  });

  it("/device/claim-ticket は弾かれる", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
    const token = await mintKioskToken(env, keypair);
    const res = await handleDeviceClaimTicket(
      new Request(`${AUTH_ORIGIN}/device/claim-ticket`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      }),
      env,
    );
    expect(res.status).toBe(403);
  });
});

// Refs ippoan/alc-app#353: role は対応表ではなく `device-<usage>` の計算で出す。
// 定数の値 (DEVICE_ROLE_*) と一致することをテストで固定する — 一致しなくなったら
// ここが落ちる。
describe("roleForUsage (Refs ippoan/alc-app#353)", () => {
  it.each<[string, string]>([
    ["kiosk", DEVICE_ROLE_KIOSK],
    ["tenko-manager", DEVICE_ROLE_TENKO_MANAGER],
    ["bp-station", DEVICE_ROLE_BP_STATION],
  ])("roleForUsage(%s) === %s", (usage, expected) => {
    expect(roleForUsage(usage as Parameters<typeof roleForUsage>[0])).toBe(expected);
  });
});

/**
 * 運行管理者席の用途 (`tenko-manager`、Refs ippoan/alc-app#337)。
 *
 * ここで固定したいのは 2 つ:
 *   - その用途の鍵 + その用途の nonce のときだけ `device-tenko-manager` が出る
 *   - **キオスクの鍵からは絶対に出ない** (鍵の用途違い / nonce の purpose 違いの両方)
 */
describe("POST /device/alarm-token の用途 (usage → role、Refs ippoan/alc-app#337)", () => {
  /** 指定した用途の nonce を取る (usage 省略時は既定 = kiosk)。 */
  async function issueNonce(env: Env, usage?: string): Promise<string> {
    const url = usage
      ? `${AUTH_ORIGIN}/device/alarm-nonce?usage=${encodeURIComponent(usage)}`
      : `${AUTH_ORIGIN}/device/alarm-nonce`;
    const res = await handleDeviceAlarmNonce(new Request(url), env);
    expect(res.status).toBe(200);
    return ((await res.json()) as { nonce: string }).nonce;
  }

  /** nonce の用途と body の用途を別々に指定できる token request を組み立てる。 */
  async function tokenBody(
    env: Env,
    keypair: Keypair,
    opts: { nonceUsage?: string; bodyUsage?: string },
  ): Promise<Record<string, unknown>> {
    const nonce = await issueNonce(env, opts.nonceUsage);
    return {
      nonce,
      pubkey: b64url(keypair.pubRaw),
      sig: signNonceAscii(keypair.privateKey, nonce),
      ...(opts.bodyUsage === undefined ? {} : { usage: opts.bodyUsage }),
    };
  }

  describe("GET /device/alarm-nonce の usage", () => {
    it("?usage=tenko-manager は purpose=tenko-manager の nonce を積む", async () => {
      const env = makeEnv();
      const nonce = await issueNonce(env, "tenko-manager");
      const stored = JSON.parse(
        (env.AUTH_CONFIG as unknown as MockKV)._data[`devnonce:${nonce}`]!,
      ) as Record<string, unknown>;
      expect(stored.purpose).toBe("tenko-manager");
    });

    it("usage 省略 / 空文字は既定の purpose=kiosk (既存ファームとの後方互換)", async () => {
      const env = makeEnv();
      for (const usage of [undefined, ""]) {
        const nonce = await issueNonce(env, usage);
        const stored = JSON.parse(
          (env.AUTH_CONFIG as unknown as MockKV)._data[`devnonce:${nonce}`]!,
        ) as Record<string, unknown>;
        expect(stored.purpose, String(usage)).toBe("kiosk");
      }
    });

    it.each(["admin-login", "manager", "KIOSK", "login"])(
      "表に無い usage=%s は 400 で nonce を積まない",
      async (usage) => {
        const env = makeEnv();
        const res = await handleDeviceAlarmNonce(
          new Request(`${AUTH_ORIGIN}/device/alarm-nonce?usage=${encodeURIComponent(usage)}`),
          env,
        );
        expect(res.status).toBe(400);
        expect(await res.json()).toEqual({ error: "invalid_usage" });
        const keys = Object.keys((env.AUTH_CONFIG as unknown as MockKV)._data).filter((k) =>
          k.startsWith("devnonce:"),
        );
        expect(keys).toEqual([]);
      },
    );
  });

  it("用途 tenko-manager の鍵 + その用途の nonce で role=device-tenko-manager が出る", async () => {
    const keypair = generateKeypair();
    const { fp, kv } = alarmKeySeed(keypair.pubRaw, { usage: "tenko-manager" });
    const env = makeEnv(kv);
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      const res = await handleDeviceAlarmToken(
        tokenRequest(
          await tokenBody(env, keypair, {
            nonceUsage: "tenko-manager",
            bodyUsage: "tenko-manager",
          }),
        ),
        env,
      );
      expect(res.status).toBe(200);
      const { access_token, tenant_id } = (await res.json()) as {
        access_token: string;
        tenant_id: string;
      };
      expect(tenant_id).toBe(TENANT_ID);
      const payload = decodeJwtPayload(access_token)!;
      expect(payload.role).toBe(DEVICE_ROLE_TENKO_MANAGER);
      expect(payload.role).toBe("device-tenko-manager");
      expect(payload.aud).toBe(DEVICE_JWT_AUDIENCE);
      expect(payload.sub).toBe(`alarm:${fp}`);
      expect(payload.tenant_id).toBe(TENANT_ID);
      // 値は log に出さない (既存方針)。
      expect(logSpy.mock.calls.map((c) => String(c[0])).some((l) => l.includes(access_token))).toBe(
        false,
      );
    } finally {
      logSpy.mockRestore();
    }
  });

  it("★ キオスクの鍵では運行管理者の role は出ない (鍵の用途違いで 401)", async () => {
    const keypair = generateKeypair();
    // 用途 kiosk で登録された鍵 (= CoreS3 の運行者端末の鍵)。
    const env = makeEnv(alarmKeySeed(keypair.pubRaw, { usage: "kiosk" }).kv);
    await expectInvalid(
      await handleDeviceAlarmToken(
        tokenRequest(
          await tokenBody(env, keypair, {
            nonceUsage: "tenko-manager",
            bodyUsage: "tenko-manager",
          }),
        ),
        env,
      ),
    );
  });

  it("★ 運行管理者の鍵で usage を省略しても kiosk の role は出ない (401)", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw, { usage: "tenko-manager" }).kv);
    await expectInvalid(
      await handleDeviceAlarmToken(
        tokenRequest(await tokenBody(env, keypair, {})),
        env,
      ),
    );
  });

  it("★ 運行者端末向けに出した nonce への署名は運行管理者の JWT に使えない (purpose 違いで 401)", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw, { usage: "tenko-manager" }).kv);
    await expectInvalid(
      await handleDeviceAlarmToken(
        tokenRequest(await tokenBody(env, keypair, { bodyUsage: "tenko-manager" })),
        env,
      ),
    );
  });

  it("★ 運行管理者向けに出した nonce への署名はキオスクの JWT に使えない (逆向きも 401)", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw, { usage: "kiosk" }).kv);
    await expectInvalid(
      await handleDeviceAlarmToken(
        tokenRequest(await tokenBody(env, keypair, { nonceUsage: "tenko-manager" })),
        env,
      ),
    );
  });

  it.each(["admin-login", "manager", "TENKO-MANAGER", "login", 1, ["tenko-manager"], {}])(
    "この口に無い usage=%s は 401",
    async (usage) => {
      const keypair = generateKeypair();
      const env = makeEnv(alarmKeySeed(keypair.pubRaw, { usage: "tenko-manager" }).kv);
      const nonce = await issueNonce(env, "tenko-manager");
      await expectInvalid(
        await handleDeviceAlarmToken(
          tokenRequest({
            nonce,
            pubkey: b64url(keypair.pubRaw),
            sig: signNonceAscii(keypair.privateKey, nonce),
            usage,
          }),
          env,
        ),
      );
    },
  );

  it("鍵ごとの rate limit の枠は用途ごとに別 (kiosk の枠を使い切っても運行管理者は通る)", async () => {
    await withFixedDate(currentMinuteMs(), async () => {
      const kioskKey = generateKeypair();
      const managerKey = generateKeypair();
      const env = makeEnv({
        ...alarmKeySeed(kioskKey.pubRaw, { usage: "kiosk" }).kv,
        ...alarmKeySeed(managerKey.pubRaw, { usage: "tenko-manager" }).kv,
      });
      for (let i = 0; i < 10; i++) {
        const res = await handleDeviceAlarmToken(
          tokenRequest(await signedBody(env, kioskKey)),
          env,
        );
        expect(res.status, `kiosk attempt ${i + 1}`).toBe(200);
      }
      expect((await handleDeviceAlarmToken(tokenRequest(await signedBody(env, kioskKey)), env)).status).toBe(
        429,
      );

      const res = await handleDeviceAlarmToken(
        tokenRequest(
          await tokenBody(env, managerKey, {
            nonceUsage: "tenko-manager",
            bodyUsage: "tenko-manager",
          }),
        ),
        env,
      );
      expect(res.status).toBe(200);
    });
  });

  it("出した JWT は /device-data-proxy の予定の口を通り、kiosk 専用の口では 403", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw, { usage: "tenko-manager" }).kv);
    const res = await handleDeviceAlarmToken(
      tokenRequest(
        await tokenBody(env, keypair, { nonceUsage: "tenko-manager", bodyUsage: "tenko-manager" }),
      ),
      env,
    );
    expect(res.status).toBe(200);
    const { access_token } = (await res.json()) as { access_token: string };

    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const ok = await handleDeviceDataProxy(
      new Request(`${AUTH_ORIGIN}/device-data-proxy/api/tenko/schedules`, {
        method: "GET",
        headers: { Authorization: `Bearer ${access_token}` },
      }),
      env,
    );
    expect(ok.status).toBe(200);
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBe(TENANT_ID);

    const denied = await handleDeviceDataProxy(
      new Request(`${AUTH_ORIGIN}/device-data-proxy/api/tenko/dashboard`, {
        method: "GET",
        headers: { Authorization: `Bearer ${access_token}` },
      }),
      env,
    );
    expect(denied.status).toBe(403);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("キオスクの鍵で出した JWT の role は今までどおり device-kiosk (退行検知)", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw, { usage: "kiosk" }).kv);
    const token = await mintKioskToken(env, keypair);
    expect(decodeJwtPayload(token)!.role).toBe(DEVICE_ROLE_KIOSK);
  });

  it("用途 bp-station の鍵 + その用途の nonce で role=device-bp-station が出る", async () => {
    const keypair = generateKeypair();
    const { fp, kv } = alarmKeySeed(keypair.pubRaw, { usage: "bp-station" });
    const env = makeEnv(kv);
    const res = await handleDeviceAlarmToken(
      tokenRequest(
        await tokenBody(env, keypair, { nonceUsage: "bp-station", bodyUsage: "bp-station" }),
      ),
      env,
    );
    expect(res.status).toBe(200);
    const { access_token, tenant_id } = (await res.json()) as {
      access_token: string;
      tenant_id: string;
    };
    expect(tenant_id).toBe(TENANT_ID);
    const payload = decodeJwtPayload(access_token)!;
    expect(payload.role).toBe(DEVICE_ROLE_BP_STATION);
    expect(payload.role).toBe("device-bp-station");
    expect(payload.aud).toBe(DEVICE_JWT_AUDIENCE);
    expect(payload.sub).toBe(`alarm:${fp}`);
    expect(payload.tenant_id).toBe(TENANT_ID);
  });

  it("★ 血圧測定台の鍵で usage を省略すると kiosk とは用途が食い違うため 401", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw, { usage: "bp-station" }).kv);
    await expectInvalid(
      await handleDeviceAlarmToken(tokenRequest(await tokenBody(env, keypair, {})), env),
    );
  });

  it("★ キオスクの鍵で usage=bp-station を名乗っても 401 (鍵の用途違い)", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw, { usage: "kiosk" }).kv);
    await expectInvalid(
      await handleDeviceAlarmToken(
        tokenRequest(
          await tokenBody(env, keypair, { nonceUsage: "bp-station", bodyUsage: "bp-station" }),
        ),
        env,
      ),
    );
  });

  it("出した JWT は /device-data-proxy の測定台の口を通り、kiosk 専用の口では 403", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw, { usage: "bp-station" }).kv);
    const res = await handleDeviceAlarmToken(
      tokenRequest(
        await tokenBody(env, keypair, { nonceUsage: "bp-station", bodyUsage: "bp-station" }),
      ),
      env,
    );
    expect(res.status).toBe(200);
    const { access_token } = (await res.json()) as { access_token: string };

    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const ok = await handleDeviceDataProxy(
      new Request(`${AUTH_ORIGIN}/device-data-proxy/api/measurements/start`, {
        method: "POST",
        headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
        body: "{}",
      }),
      env,
    );
    expect(ok.status).toBe(200);
    const h = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Record<string, string>;
    expect(h["X-Tenant-ID"]).toBe(TENANT_ID);

    const denied = await handleDeviceDataProxy(
      new Request(`${AUTH_ORIGIN}/device-data-proxy/api/tenko/dashboard`, {
        method: "GET",
        headers: { Authorization: `Bearer ${access_token}` },
      }),
      env,
    );
    expect(denied.status).toBe(403);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
