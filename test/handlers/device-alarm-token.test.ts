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
} from "../../src/handlers/device-alarm-token";
import { handleDeviceNonce, handleDeviceLogin } from "../../src/handlers/device-login";
import { handleDeviceDataProxy } from "../../src/handlers/device-data-proxy";
import { handleDeviceClaimTicket } from "../../src/handlers/device-claim-ticket";
import { DEVICE_JWT_AUDIENCE, DEVICE_ROLE_KIOSK } from "../../src/lib/device";
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

  it("login 用 (device-nonce) の nonce への署名は 401", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
    const nonceRes = await handleDeviceNonce(
      new Request(`${AUTH_ORIGIN}/auth/device-nonce?redirect_uri=${encodeURIComponent(REDIRECT_URI)}`),
      env,
    );
    const { nonce } = (await nonceRes.json()) as { nonce: string };
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

describe("device-login 側: nonce の purpose", () => {
  it("kiosk 用 (alarm-nonce) の nonce への署名で device-login は 401", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
    const nonce = await issueKioskNonce(env);
    const url = new URL(`${AUTH_ORIGIN}/auth/device-login`);
    url.searchParams.set("pubkey", b64url(keypair.pubRaw));
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("sig", signNonceAscii(keypair.privateKey, nonce));
    url.searchParams.set("redirect_uri", REDIRECT_URI);
    const res = await handleDeviceLogin(new Request(url.toString()), env);
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_device_login" });
  });

  it("purpose=login の nonce でも、redirect_uri が allowlist から外れていれば 401", async () => {
    const keypair = generateKeypair();
    const env = makeEnv(alarmKeySeed(keypair.pubRaw).kv);
    const noLongerAllowed = "https://not-allowed.example/page";
    const nonce = "c".repeat(32);
    // 発行後に allowlist が変わった状況を模して KV へ直接書く。
    (env.AUTH_CONFIG as unknown as MockKV)._data[`devnonce:${nonce}`] = JSON.stringify({
      purpose: "login",
      redirect_uri: noLongerAllowed,
      exp: Math.floor(Date.now() / 1000) + 60,
    });
    const url = new URL(`${AUTH_ORIGIN}/auth/device-login`);
    url.searchParams.set("pubkey", b64url(keypair.pubRaw));
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("sig", signNonceAscii(keypair.privateKey, nonce));
    url.searchParams.set("redirect_uri", noLongerAllowed);
    const res = await handleDeviceLogin(new Request(url.toString()), env);
    expect(res.status).toBe(401);
  });
});
