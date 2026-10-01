import { describe, it, expect } from "vitest";
import { handleInternalDeviceLabels } from "../../src/handlers/internal-device-labels";
import { handleInternalHubDevices } from "../../src/handlers/internal-hub-devices";
import {
  createDeviceCredential,
  revokeDeviceCredential,
  DEVICE_ROLE_HUB,
  DEVICE_ROLE_KIOSK,
} from "../../src/lib/device";
import { createMockEnv, createMockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ORIGIN = "https://auth.test.example";
const SECRET = "test-internal-shared-secret-32chr";
const NOW = Math.floor(Date.now() / 1000);

function makeEnv(overrides: Partial<Env> = {}): Env {
  return createMockEnv({ INTERNAL_SHARED_SECRET: SECRET, AUTH_CONFIG: createMockKV(), ...overrides });
}

function req(auth?: string | null, query = "?tenant_id=tenant-a", path = "device-labels"): Request {
  const headers: Record<string, string> = {};
  if (auth !== null && auth !== undefined) headers.Authorization = auth;
  return new Request(`${ORIGIN}/internal/${path}${query}`, { method: "GET", headers });
}

describe("GET /internal/device-labels — 認可 (/internal/hub-devices と同じ拒否)", () => {
  it.each([
    ["secret 無し", undefined],
    ["secret 違い", "wrong-secret"],
  ])("%s → 401 で登録簿の中身を返さない", async (_n, auth) => {
    const env = makeEnv();
    await createDeviceCredential(env, "tenant-a", "secret-label-xyz", NOW, DEVICE_ROLE_KIOSK);
    const res = await handleInternalDeviceLabels(req(auth), env);
    const hub = await handleInternalHubDevices(req(auth, "", "hub-devices"), env);
    expect(res.status).toBe(401);
    const text = await res.text();
    expect(text).toBe(await hub.text());
    expect(text).toBe(JSON.stringify({ error: "unauthorized" }));
    expect(text).not.toContain("secret-label-xyz");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("INTERNAL_SHARED_SECRET* が未 bind → 503 (hub-devices と同じ)", async () => {
    const env = makeEnv({ INTERNAL_SHARED_SECRET: undefined });
    const res = await handleInternalDeviceLabels(req(SECRET), env);
    const hub = await handleInternalHubDevices(req(SECRET, "", "hub-devices"), env);
    expect(res.status).toBe(503);
    expect(await res.text()).toBe(await hub.text());
  });
});

describe("GET /internal/device-labels — 応答", () => {
  it("そのテナントの未失効の端末だけ。別テナント・失効は返らない", async () => {
    const env = makeEnv();
    const a1 = await createDeviceCredential(env, "tenant-a", "hub-a", NOW, DEVICE_ROLE_HUB);
    const a2 = await createDeviceCredential(env, "tenant-a", "kiosk-a", NOW + 1, DEVICE_ROLE_KIOSK, undefined, true);
    const gone = await createDeviceCredential(env, "tenant-a", "revoked-a", NOW + 2, DEVICE_ROLE_KIOSK);
    await createDeviceCredential(env, "tenant-b", "other-b", NOW, DEVICE_ROLE_KIOSK);
    await revokeDeviceCredential(env, gone.device_id);

    const res = await handleInternalDeviceLabels(req(SECRET), env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = (await res.json()) as { devices: Array<Record<string, unknown>> };
    expect(body.devices).toEqual([
      { device_id: a2.device_id, label: "kiosk-a" },
      { device_id: a1.device_id, label: "hub-a" },
    ]);
    for (const d of body.devices) expect(Object.keys(d).sort()).toEqual(["device_id", "label"]);
    expect(Object.keys(body)).toEqual(["devices"]);
  });

  it("label が無い record は label: null", async () => {
    const env = makeEnv();
    const c = await createDeviceCredential(env, "tenant-a", "x", NOW, DEVICE_ROLE_KIOSK);
    const raw = JSON.parse((await env.AUTH_CONFIG.get(`device:${c.device_id}`)) as string);
    delete raw.label;
    await env.AUTH_CONFIG.put(`device:${c.device_id}`, JSON.stringify(raw));
    const body = (await (await handleInternalDeviceLabels(req(SECRET), env)).json()) as {
      devices: unknown[];
    };
    expect(body.devices).toEqual([{ device_id: c.device_id, label: null }]);
  });

  it("端末が 0 台のテナント → { devices: [] }", async () => {
    const env = makeEnv();
    const res = await handleInternalDeviceLabels(req(SECRET, "?tenant_id=tenant-empty"), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ devices: [] });
  });

  it.each(["", "?tenant_id=", "?other=1"])("tenant_id 無し/空 (%s) → 400", async (q) => {
    const res = await handleInternalDeviceLabels(req(SECRET, q), makeEnv());
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "tenant_id_required" });
  });
});
