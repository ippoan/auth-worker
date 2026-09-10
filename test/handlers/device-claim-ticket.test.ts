/**
 * POST /device/claim-ticket (Refs #519) — CoreS3 (device-hub JWT) が取る
 * 「端末登録の一回券」。券が既存の `POST /device/pair/token` でそのまま
 * device-kiosk credential に化けるところまでを 1 本で通す。
 */
import { describe, it, expect } from "vitest";
import { handleDeviceClaimTicket, CLAIM_TICKET_TTL_SECONDS } from "../../src/handlers/device-claim-ticket";
import { handleDevicePairToken } from "../../src/handlers/device-pair";
import {
  createDeviceCredential,
  revokeDeviceCredential,
  mintDeviceJwt,
  DEVICE_ROLE_HUB,
  DEVICE_ROLE_KIOSK,
  type DeviceRecord,
} from "../../src/lib/device";
import { createMockKV } from "../helpers/mock-env";
import { signTestJwt } from "../helpers/test-jwt";
import type { Env } from "../../src/index";

const SECRET = "device-claim-ticket-test-secret";
const WORKER_ENV = "staging";
const ISSUER = "https://auth.ippoan.org";
const TENANT = "tenant-1";
// handler は実 Date.now を使うため、mint する JWT も実時刻基準にして期限内に保つ。
const NOW = Math.floor(Date.now() / 1000);

function makeEnv(overrides: Record<string, unknown> = {}): Env {
  return {
    AUTH_CONFIG: createMockKV(),
    JWT_SECRET: SECRET,
    WORKER_ENV,
    ...overrides,
  } as unknown as Env;
}

function claimReq(headers: Record<string, string> = {}): Request {
  return new Request(`${ISSUER}/device/claim-ticket`, { method: "POST", headers });
}

/** hub credential を KV に作り、その device JWT を返す。 */
async function seedHub(env: Env, role: string = DEVICE_ROLE_HUB): Promise<{ token: string; deviceId: string }> {
  const created = await createDeviceCredential(env, TENANT, "hub", NOW, role);
  const token = await mintDeviceJwt({ JWT_SECRET: SECRET, WORKER_ENV }, created.record, NOW);
  return { token, deviceId: created.record.device_id };
}

function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

async function claimTicket(env: Env, token: string): Promise<Response> {
  return handleDeviceClaimTicket(claimReq(bearer(token)), env);
}

describe("handleDeviceClaimTicket", () => {
  it("issues a ticket the existing pair/token redeem turns into a kiosk credential", async () => {
    const env = makeEnv();
    const { token } = await seedHub(env);

    const res = await claimTicket(env, token);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = (await res.json()) as { ticket: string; expires_in: number };
    expect(typeof body.ticket).toBe("string");
    expect(body.ticket.length).toBeGreaterThan(0);
    expect(body.expires_in).toBe(CLAIM_TICKET_TTL_SECONDS);
    expect(CLAIM_TICKET_TTL_SECONDS).toBe(300);

    // ブラウザ側 (認証不要) が券を引き換える。
    const redeem = await handleDevicePairToken(
      new Request(`${ISSUER}/device/pair/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_code: body.ticket }),
      }),
      env,
    );
    expect(redeem.status).toBe(200);
    const cred = (await redeem.json()) as Record<string, string>;
    expect(cred.status).toBe("approved");
    expect(cred.device_id).toBeTruthy();
    expect(cred.device_secret).toBeTruthy();
    expect(cred.tenant_id).toBe(TENANT); // tenant は hub の JWT 由来 (client からは詐称不能)
    expect(cred.label).toMatch(/^kiosk via /);

    // 発行された credential は device-kiosk。
    const kv = env.AUTH_CONFIG as unknown as { _data: Record<string, string> };
    const record = JSON.parse(kv._data[`device:${cred.device_id}`]!) as DeviceRecord;
    expect(record.role).toBe(DEVICE_ROLE_KIOSK);
    expect(record.tenant_id).toBe(TENANT);
  });

  it("burns the ticket after one redeem (2 回目は consumed)", async () => {
    const env = makeEnv();
    const { token } = await seedHub(env);
    const body = (await (await claimTicket(env, token)).json()) as { ticket: string };

    const redeemOnce = () =>
      handleDevicePairToken(
        new Request(`${ISSUER}/device/pair/token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ device_code: body.ticket }),
        }),
        env,
      );

    expect((await redeemOnce()).status).toBe(200);
    const second = await redeemOnce();
    expect(second.status).toBe(410);
    expect(((await second.json()) as { status: string }).status).toBe("consumed");
  });

  it("keeps the ticket short-lived (300s、pairing 既定の 600 ではなく)", async () => {
    const env = makeEnv();
    const { token } = await seedHub(env);
    const body = (await (await claimTicket(env, token)).json()) as { ticket: string };
    const kv = env.AUTH_CONFIG as unknown as { _ttls: Record<string, number> };
    expect(kv._ttls[`devpair:dc:${body.ticket}`]).toBeLessThanOrEqual(CLAIM_TICKET_TTL_SECONDS);
  });

  it("rejects a JWT whose role is not device-hub (403)", async () => {
    const env = makeEnv();
    const { token } = await seedHub(env, DEVICE_ROLE_KIOSK);
    const res = await claimTicket(env, token);
    expect(res.status).toBe(403);
  });

  it("rejects a browser JWT (aud 無し) signed with the same secret (401)", async () => {
    const env = makeEnv();
    const token = await signTestJwt(
      { sub: "user-1", tenant_id: TENANT, role: DEVICE_ROLE_HUB, env: WORKER_ENV },
      SECRET,
    );
    const res = await claimTicket(env, token);
    expect(res.status).toBe(401);
  });

  it("rejects an expired device JWT (401)", async () => {
    const env = makeEnv();
    const created = await createDeviceCredential(env, TENANT, "hub", NOW, DEVICE_ROLE_HUB);
    const token = await mintDeviceJwt({ JWT_SECRET: SECRET, WORKER_ENV }, created.record, NOW - 7200, 60);
    const res = await claimTicket(env, token);
    expect(res.status).toBe(401);
  });

  it("rejects a missing Authorization header (401)", async () => {
    const res = await handleDeviceClaimTicket(claimReq(), makeEnv());
    expect(res.status).toBe(401);
  });

  it("rejects a revoked hub credential even while its JWT is still valid (403)", async () => {
    const env = makeEnv();
    const { token, deviceId } = await seedHub(env);
    expect(await revokeDeviceCredential(env, deviceId)).toBe(true);
    const res = await claimTicket(env, token);
    expect(res.status).toBe(403);
  });

  it("rejects a JWT whose device record is gone (403)", async () => {
    const env = makeEnv();
    const { token, deviceId } = await seedHub(env);
    await env.AUTH_CONFIG.delete(`device:${deviceId}`);
    const res = await claimTicket(env, token);
    expect(res.status).toBe(403);
  });

  it("caps issuance per hub: the 6th ticket in the window is 429", async () => {
    const env = makeEnv();
    const { token, deviceId } = await seedHub(env);
    for (let i = 0; i < 5; i++) {
      expect((await claimTicket(env, token)).status).toBe(200);
    }
    const res = await claimTicket(env, token);
    expect(res.status).toBe(429);

    const kv = env.AUTH_CONFIG as unknown as { _data: Record<string, string>; _ttls: Record<string, number> };
    expect(kv._data[`hubticket:${deviceId}`]).toBe("5"); // 拒否では窓を延ばさない
    expect(kv._ttls[`hubticket:${deviceId}`]).toBe(600);
  });

  it("counts per hub, so another hub is unaffected by a capped one", async () => {
    const env = makeEnv();
    const first = await seedHub(env);
    const second = await seedHub(env);
    for (let i = 0; i < 5; i++) await claimTicket(env, first.token);
    expect((await claimTicket(env, first.token)).status).toBe(429);
    expect((await claimTicket(env, second.token)).status).toBe(200);
  });

  it("treats a corrupt counter as a fresh window", async () => {
    const env = makeEnv();
    const { token, deviceId } = await seedHub(env);
    await env.AUTH_CONFIG.put(`hubticket:${deviceId}`, "not-a-number");
    expect((await claimTicket(env, token)).status).toBe(200);
    const kv = env.AUTH_CONFIG as unknown as { _data: Record<string, string> };
    expect(kv._data[`hubticket:${deviceId}`]).toBe("1");
  });

  it("returns 503 when the KV binding is missing", async () => {
    const env = makeEnv({ AUTH_CONFIG: undefined });
    const res = await handleDeviceClaimTicket(claimReq(bearer("whatever")), env);
    expect(res.status).toBe(503);
  });

  it("returns 503 when JWT_SECRET is not configured", async () => {
    const env = makeEnv({ JWT_SECRET: undefined });
    const res = await handleDeviceClaimTicket(claimReq(bearer("whatever")), env);
    expect(res.status).toBe(503);
  });
});
