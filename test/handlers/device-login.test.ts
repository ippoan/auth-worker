import { describe, it, expect, vi } from "vitest";
import crypto from "node:crypto";
import { handleDeviceNonce, handleDeviceLogin } from "../../src/handlers/device-login";
import { createMockEnv, createMockKV } from "../helpers/mock-env";
import { decodeJwtPayload } from "../../src/lib/jwt";
import type { Env } from "../../src/index";

const AUTH_ORIGIN = "https://auth.test.example";
const WORKERS_DEV_AUTH_ORIGIN = "https://auth-staging.m-tama-ramu.workers.dev";
const ALLOWED_ORIGINS =
  "https://app1.test.example,https://app2.test.example,https://auth.test.example";
const REDIRECT_URI = "https://app1.test.example/page";
const REDIRECT_URI_2 = "https://app2.test.example/page";
const TENANT_ID = "tenant-device-1";
const LABEL = "テスト警告灯";

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
function signNonceAscii(privateKey: crypto.KeyObject, nonce: string): Uint8Array {
  return new Uint8Array(crypto.sign(null, Buffer.from(nonce, "ascii"), privateKey));
}

/**
 * `alarmkey:<fp>` に登録する record と、そのための KV seed entry を組み立てる。
 * usage の既定はこの口の用途 (admin-login)。null で usage を持たない record にする。
 */
function alarmKeySeed(
  pubRaw: Uint8Array,
  opts: { tenantId?: string; label?: string; revoked?: boolean; usage?: string | null } = {},
): { fp: string; kv: Record<string, string> } {
  const fp = fingerprintHex(pubRaw);
  const record = {
    pubkey: b64url(pubRaw),
    tenant_id: opts.tenantId ?? TENANT_ID,
    label: opts.label ?? LABEL,
    ...(opts.usage === null ? {} : { usage: opts.usage ?? "admin-login" }),
    created_at: 1_700_000_000,
    ...(opts.revoked ? { revoked_at: 1_700_000_500 } : {}),
  };
  return { fp, kv: { [`alarmkey:${fp}`]: JSON.stringify(record) } };
}

function makeEnv(kvSeed: Record<string, string> = {}, overrides: Partial<Env> = {}): Env {
  return createMockEnv({
    AUTH_CONFIG: createMockKV({ "origins:prod": ALLOWED_ORIGINS, ...kvSeed }),
    ...overrides,
  });
}

function nonceRequest(redirectUri: string, host: string = AUTH_ORIGIN): Request {
  const url = new URL(`${host}/auth/device-nonce`);
  if (redirectUri) url.searchParams.set("redirect_uri", redirectUri);
  return new Request(url.toString());
}

function loginRequest(
  params: { pubkey?: string; nonce?: string; sig?: string; redirect_uri?: string },
  host: string = AUTH_ORIGIN,
): Request {
  const url = new URL(`${host}/auth/device-login`);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) url.searchParams.set(k, v);
  }
  return new Request(url.toString());
}

/** device-nonce → firmware 署名 → device-login、を 1 回分まとめて実行する。 */
async function issueNonceAndSign(
  env: Env,
  keypair: Keypair,
  redirectUri: string,
  host: string = AUTH_ORIGIN,
): Promise<{ nonce: string; sig: string }> {
  const nonceRes = await handleDeviceNonce(nonceRequest(redirectUri, host), env);
  expect(nonceRes.status).toBe(200);
  const { nonce } = (await nonceRes.json()) as { nonce: string; expires_in: number };
  const sig = b64url(signNonceAscii(keypair.privateKey, nonce));
  return { nonce, sig };
}

describe("GET /auth/device-nonce", () => {
  it("issues a nonce and stores redirect_uri in KV (TTL 60)", async () => {
    const env = makeEnv();
    const kv = env.AUTH_CONFIG as unknown as { _data: Record<string, string>; _ttls: Record<string, number> };
    const res = await handleDeviceNonce(nonceRequest(REDIRECT_URI), env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    const body = (await res.json()) as { nonce: string; expires_in: number };
    expect(body.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(body.expires_in).toBe(60);
    const stored = JSON.parse(kv._data[`devnonce:${body.nonce}`]!) as { redirect_uri: string };
    expect(stored.redirect_uri).toBe(REDIRECT_URI);
    expect(kv._ttls[`devnonce:${body.nonce}`]).toBe(60);
  });

  it("400 when redirect_uri is missing", async () => {
    const res = await handleDeviceNonce(nonceRequest(""), makeEnv());
    expect(res.status).toBe(400);
  });

  it("400 when redirect_uri is not in the allowlist", async () => {
    const res = await handleDeviceNonce(nonceRequest("https://evil.example/hack"), makeEnv());
    expect(res.status).toBe(400);
  });

  it("429 after 30 requests/min from the same IP", async () => {
    // rate limit の KV key は分バケット (Math.floor(now/60_000)) なので、実時計のまま
    // 31 回叩くと途中で分が変わったときだけ flaky になる。Date を分の頭に固定する。
    // (同じ describe に他のテストがあるので、hook ではなく it の中の try/finally で囲む)
    const fixedMinute = Math.floor(Date.now() / 60_000) * 60_000;
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(fixedMinute);
    try {
      const env = makeEnv({}, { MCP_OAUTH_KV: createMockKV() });
      for (let i = 0; i < 30; i++) {
        const res = await handleDeviceNonce(nonceRequest(REDIRECT_URI), env);
        expect(res.status, `attempt ${i + 1}`).toBe(200);
      }
      const res = await handleDeviceNonce(nonceRequest(REDIRECT_URI), env);
      expect(res.status).toBe(429);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("GET /auth/device-login", () => {
  it("mints an admin session and redirects with cookie only (shared cookie domain)", async () => {
    const keypair = generateKeypair();
    const { fp, kv } = alarmKeySeed(keypair.pubRaw);
    const env = makeEnv(kv);

    const { nonce, sig } = await issueNonceAndSign(env, keypair, REDIRECT_URI);
    const res = await handleDeviceLogin(
      loginRequest({ pubkey: b64url(keypair.pubRaw), nonce, sig, redirect_uri: REDIRECT_URI }),
      env,
    );

    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe(REDIRECT_URI); // クリーン、fragment 無し
    const setCookie = res.headers.get("Set-Cookie")!;
    expect(setCookie).toContain("logi_auth_token=eyJ");
    expect(setCookie).toContain("Max-Age=3600"); // JWT の exp に合わせる (Google の 86400 とは違う)

    const cookieToken = setCookie.match(/logi_auth_token=([^;]+)/)![1]!;
    const payload = decodeJwtPayload(cookieToken)!;
    expect(payload.sub).toBe(`alarm:${fp}`);
    expect(payload.email).toBe("");
    expect(payload.name).toBe(`警告デバイス ${LABEL}`);
    expect(payload.tenant_id).toBe(TENANT_ID);
    expect(payload.role).toBe("admin");
    expect(payload.token_kind).toBe("device-key");
  });

  it("falls back to URL fragment when cookie domain is a public suffix (workers.dev)", async () => {
    const keypair = generateKeypair();
    const { kv } = alarmKeySeed(keypair.pubRaw);
    const env = makeEnv(kv);

    const { nonce, sig } = await issueNonceAndSign(
      env,
      keypair,
      REDIRECT_URI,
      WORKERS_DEV_AUTH_ORIGIN,
    );
    const res = await handleDeviceLogin(
      loginRequest(
        { pubkey: b64url(keypair.pubRaw), nonce, sig, redirect_uri: REDIRECT_URI },
        WORKERS_DEV_AUTH_ORIGIN,
      ),
      env,
    );

    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    expect(location).toContain(REDIRECT_URI);
    expect(location).toContain("#token=");
    expect(location).toContain(`org_id=${TENANT_ID}`);
    expect(location).toContain("lw_callback=1");
  });

  it("fragment fallback keeps an existing lw_callback query param as-is (doesn't double-set it)", async () => {
    const keypair = generateKeypair();
    const { kv } = alarmKeySeed(keypair.pubRaw);
    const env = makeEnv(kv);
    const redirectWithCallback = `${REDIRECT_URI}?lw_callback=1`;

    const { nonce, sig } = await issueNonceAndSign(
      env,
      keypair,
      redirectWithCallback,
      WORKERS_DEV_AUTH_ORIGIN,
    );
    const res = await handleDeviceLogin(
      loginRequest(
        { pubkey: b64url(keypair.pubRaw), nonce, sig, redirect_uri: redirectWithCallback },
        WORKERS_DEV_AUTH_ORIGIN,
      ),
      env,
    );
    expect(res.status).toBe(302);
    const location = res.headers.get("Location")!;
    // 既存の lw_callback=1 を保った上での 1 個だけ (二重付与しない)。
    expect(location.match(/lw_callback=1/g)?.length).toBe(1);
  });

  it("401 when the nonce is reused (single-use)", async () => {
    const keypair = generateKeypair();
    const { kv } = alarmKeySeed(keypair.pubRaw);
    const env = makeEnv(kv);

    const { nonce, sig } = await issueNonceAndSign(env, keypair, REDIRECT_URI);
    const params = { pubkey: b64url(keypair.pubRaw), nonce, sig, redirect_uri: REDIRECT_URI };
    const first = await handleDeviceLogin(loginRequest(params), env);
    expect(first.status).toBe(302);

    const second = await handleDeviceLogin(loginRequest(params), env);
    expect(second.status).toBe(401);
    expect(await second.json()).toEqual({ error: "invalid_device_login" });
  });

  it("401 when redirect_uri doesn't match the one used at nonce issuance", async () => {
    const keypair = generateKeypair();
    const { kv } = alarmKeySeed(keypair.pubRaw);
    const env = makeEnv(kv);

    const { nonce, sig } = await issueNonceAndSign(env, keypair, REDIRECT_URI);
    const res = await handleDeviceLogin(
      loginRequest({ pubkey: b64url(keypair.pubRaw), nonce, sig, redirect_uri: REDIRECT_URI_2 }),
      env,
    );
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_device_login" });
  });

  it("401 when the signature doesn't verify (tampered)", async () => {
    const keypair = generateKeypair();
    const { kv } = alarmKeySeed(keypair.pubRaw);
    const env = makeEnv(kv);

    const { nonce, sig } = await issueNonceAndSign(env, keypair, REDIRECT_URI);
    const tampered = Buffer.from(sig, "base64url");
    tampered[0] = tampered[0]! ^ 0xff;
    const res = await handleDeviceLogin(
      loginRequest({
        pubkey: b64url(keypair.pubRaw),
        nonce,
        sig: tampered.toString("base64url"),
        redirect_uri: REDIRECT_URI,
      }),
      env,
    );
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_device_login" });
  });

  it("401 for an unregistered pubkey", async () => {
    const registered = generateKeypair();
    const unregistered = generateKeypair();
    const { kv } = alarmKeySeed(registered.pubRaw);
    const env = makeEnv(kv);

    const { nonce, sig } = await issueNonceAndSign(env, unregistered, REDIRECT_URI);
    const res = await handleDeviceLogin(
      loginRequest({ pubkey: b64url(unregistered.pubRaw), nonce, sig, redirect_uri: REDIRECT_URI }),
      env,
    );
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_device_login" });
  });

  it("401 for a revoked pubkey", async () => {
    const keypair = generateKeypair();
    const { kv } = alarmKeySeed(keypair.pubRaw, { revoked: true });
    const env = makeEnv(kv);

    const { nonce, sig } = await issueNonceAndSign(env, keypair, REDIRECT_URI);
    const res = await handleDeviceLogin(
      loginRequest({ pubkey: b64url(keypair.pubRaw), nonce, sig, redirect_uri: REDIRECT_URI }),
      env,
    );
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_device_login" });
  });

  it("401 for a key registered for the kiosk usage (用途違い)", async () => {
    const keypair = generateKeypair();
    const { kv } = alarmKeySeed(keypair.pubRaw, { usage: "kiosk" });
    const env = makeEnv(kv);

    const { nonce, sig } = await issueNonceAndSign(env, keypair, REDIRECT_URI);
    const res = await handleDeviceLogin(
      loginRequest({ pubkey: b64url(keypair.pubRaw), nonce, sig, redirect_uri: REDIRECT_URI }),
      env,
    );
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_device_login" });
  });

  it("401 for a key record without usage (fail-closed)", async () => {
    const keypair = generateKeypair();
    const { kv } = alarmKeySeed(keypair.pubRaw, { usage: null });
    const env = makeEnv(kv);

    const { nonce, sig } = await issueNonceAndSign(env, keypair, REDIRECT_URI);
    const res = await handleDeviceLogin(
      loginRequest({ pubkey: b64url(keypair.pubRaw), nonce, sig, redirect_uri: REDIRECT_URI }),
      env,
    );
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_device_login" });
  });

  it("401 when required query params are missing", async () => {
    const res = await handleDeviceLogin(loginRequest({ redirect_uri: REDIRECT_URI }), makeEnv());
    expect(res.status).toBe(401);
  });

  it("429 after 10 logins/min for the same fingerprint, distinct 401 body from failure cases", async () => {
    // rate limit の KV key は分バケット (Math.floor(now/60_000)) なので、実時計のまま
    // 11 回叩くと途中で分が変わったときだけ flaky になる。Date を分の頭に固定する。
    // (同じ describe に他のテストがあるので、hook ではなく it の中の try/finally で囲む)
    const fixedMinute = Math.floor(Date.now() / 60_000) * 60_000;
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(fixedMinute);
    try {
      const keypair = generateKeypair();
      const { kv } = alarmKeySeed(keypair.pubRaw);
      const env = makeEnv(kv, { MCP_OAUTH_KV: createMockKV() });

      for (let i = 0; i < 10; i++) {
        const { nonce, sig } = await issueNonceAndSign(env, keypair, REDIRECT_URI);
        const res = await handleDeviceLogin(
          loginRequest({ pubkey: b64url(keypair.pubRaw), nonce, sig, redirect_uri: REDIRECT_URI }),
          env,
        );
        expect(res.status, `attempt ${i + 1}`).toBe(302);
      }

      const { nonce, sig } = await issueNonceAndSign(env, keypair, REDIRECT_URI);
      const res = await handleDeviceLogin(
        loginRequest({ pubkey: b64url(keypair.pubRaw), nonce, sig, redirect_uri: REDIRECT_URI }),
        env,
      );
      expect(res.status).toBe(429);
      expect(await res.json()).toEqual({ error: "rate_limited" });
    } finally {
      vi.useRealTimers();
    }
  });

  it("403 when APP_TENANT_ACL denies the tenant for this app (finishLogin's per-app ACL layer)", async () => {
    const keypair = generateKeypair();
    const { kv } = alarmKeySeed(keypair.pubRaw);
    const env = makeEnv(kv, {
      APP_TENANT_ACL: JSON.stringify({
        apps: { [new URL(REDIRECT_URI).origin]: ["some-other-tenant"] },
      }),
    });

    const { nonce, sig } = await issueNonceAndSign(env, keypair, REDIRECT_URI);
    const res = await handleDeviceLogin(
      loginRequest({ pubkey: b64url(keypair.pubRaw), nonce, sig, redirect_uri: REDIRECT_URI }),
      env,
    );
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("アクセスできません");
  });

  it("401 when all query params are omitted (redirect_uri included)", async () => {
    const res = await handleDeviceLogin(loginRequest({}), makeEnv());
    expect(res.status).toBe(401);
  });

  it("401 when the stored nonce record is not valid JSON", async () => {
    const env = makeEnv();
    const kv = env.AUTH_CONFIG as unknown as { _data: Record<string, string> };
    const nonce = "a".repeat(32);
    kv._data[`devnonce:${nonce}`] = "{not json";
    const res = await handleDeviceLogin(
      loginRequest({ pubkey: "x", nonce, sig: "y", redirect_uri: REDIRECT_URI }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("401 when the stored nonce record has the wrong shape", async () => {
    const env = makeEnv();
    const kv = env.AUTH_CONFIG as unknown as { _data: Record<string, string> };
    const nonce = "b".repeat(32);
    kv._data[`devnonce:${nonce}`] = JSON.stringify({ redirect_uri: 123, exp: "soon" });
    const res = await handleDeviceLogin(
      loginRequest({ pubkey: "x", nonce, sig: "y", redirect_uri: REDIRECT_URI }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("401 when the nonce's redirect_uri is no longer in the allowlist (defense in depth, issue text's item g)", async () => {
    const keypair = generateKeypair();
    const { kv } = alarmKeySeed(keypair.pubRaw);
    const env = makeEnv(kv);
    const noLongerAllowed = "https://not-allowed.example/page";
    const nonce = "c".repeat(32);
    // handleDeviceNonce 自体はこの redirect_uri を許可しないので、KV へ直接
    // (発行後に allowlist が変わった状況を模す) 書き込む。
    const kvStore = env.AUTH_CONFIG as unknown as { _data: Record<string, string> };
    kvStore._data[`devnonce:${nonce}`] = JSON.stringify({
      redirect_uri: noLongerAllowed,
      exp: Math.floor(Date.now() / 1000) + 60,
    });
    const sig = b64url(signNonceAscii(keypair.privateKey, nonce));
    const res = await handleDeviceLogin(
      loginRequest({ pubkey: b64url(keypair.pubRaw), nonce, sig, redirect_uri: noLongerAllowed }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("401 when pubkey/sig are not valid base64url (decode throws)", async () => {
    const env = makeEnv();
    const { nonce } = await issueNonceAndSign(env, generateKeypair(), REDIRECT_URI);
    const res = await handleDeviceLogin(
      loginRequest({
        pubkey: "!!!not valid base64!!!",
        nonce,
        sig: "y",
        redirect_uri: REDIRECT_URI,
      }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("401 when the decoded pubkey/sig have the wrong byte length", async () => {
    const env = makeEnv();
    const { nonce } = await issueNonceAndSign(env, generateKeypair(), REDIRECT_URI);
    const res = await handleDeviceLogin(
      loginRequest({
        pubkey: b64url(new Uint8Array(10)), // valid base64url, wrong length
        nonce,
        sig: b64url(new Uint8Array(64)),
        redirect_uri: REDIRECT_URI,
      }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("401 when the registered alarmkey record's stored pubkey is corrupt", async () => {
    const keypair = generateKeypair();
    const fp = fingerprintHex(keypair.pubRaw);
    const env = makeEnv({
      [`alarmkey:${fp}`]: JSON.stringify({
        pubkey: "!!!corrupt!!!",
        tenant_id: TENANT_ID,
        label: LABEL,
        usage: "admin-login",
        created_at: 1,
      }),
    });
    const { nonce, sig } = await issueNonceAndSign(env, keypair, REDIRECT_URI);
    const res = await handleDeviceLogin(
      loginRequest({ pubkey: b64url(keypair.pubRaw), nonce, sig, redirect_uri: REDIRECT_URI }),
      env,
    );
    expect(res.status).toBe(401);
  });

  it("503 when JWT_SECRET is not configured", async () => {
    const keypair = generateKeypair();
    const { kv } = alarmKeySeed(keypair.pubRaw);
    const env = makeEnv(kv, { JWT_SECRET: undefined });
    const { nonce, sig } = await issueNonceAndSign(env, keypair, REDIRECT_URI);
    const res = await handleDeviceLogin(
      loginRequest({ pubkey: b64url(keypair.pubRaw), nonce, sig, redirect_uri: REDIRECT_URI }),
      env,
    );
    expect(res.status).toBe(503);
  });

  it("403 when the tenant is not in TENANT_ACL for an ohishi-exp redirect target (ACL is enforced via finishLogin)", async () => {
    const keypair = generateKeypair();
    const { kv } = alarmKeySeed(keypair.pubRaw, { tenantId: "some-other-tenant" });
    const dtakoRedirect = "https://dtako-admin.example/page";
    const env = makeEnv({
      ...kv,
      "origins:prod": `${ALLOWED_ORIGINS},${new URL(dtakoRedirect).origin}`,
      "app-orgs": JSON.stringify({ "dtako-admin": "ohishi-exp" }),
    });
    (env as unknown as Record<string, unknown>).TENANT_ACL = JSON.stringify({
      "ohishi-exp": ["allowed-tenant"],
    });

    const { nonce, sig } = await issueNonceAndSign(env, keypair, dtakoRedirect);
    const res = await handleDeviceLogin(
      loginRequest({ pubkey: b64url(keypair.pubRaw), nonce, sig, redirect_uri: dtakoRedirect }),
      env,
    );
    // email が空文字なので USER_ACL / bypass_emails は効かず、tenant allowlist だけで
    // fail-closed に判定される (issue #522 の意図どおり)。
    expect(res.status).toBe(403);
  });
});
