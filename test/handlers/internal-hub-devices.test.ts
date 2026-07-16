import { describe, it, expect } from "vitest";
import { handleInternalHubDevices } from "../../src/handlers/internal-hub-devices";
import { createDeviceCredential, DEVICE_ROLE_HUB, DEVICE_ROLE_KIOSK } from "../../src/lib/device";
import { createMockEnv, createMockKV } from "../helpers/mock-env";
import type { Env } from "../../src/index";

const ORIGIN = "https://auth.test.example";
const TEST_INTERNAL_SECRET = "test-internal-shared-secret-32chr";
const NOW = Math.floor(Date.now() / 1000);

function makeEnv(overrides: Partial<Env> = {}): Env {
  return createMockEnv({
    INTERNAL_SHARED_SECRET: TEST_INTERNAL_SECRET,
    ...overrides,
  });
}

function req(auth?: string | null): Request {
  const headers: Record<string, string> = {};
  if (auth !== null && auth !== undefined) headers.Authorization = auth;
  return new Request(`${ORIGIN}/internal/hub-devices`, { method: "GET", headers });
}

describe("GET /internal/hub-devices — env guard", () => {
  it("returns 503 when no INTERNAL_SHARED_SECRET* binding present", async () => {
    const env = makeEnv({ INTERNAL_SHARED_SECRET: undefined });
    const res = await handleInternalHubDevices(req(TEST_INTERNAL_SECRET), env);
    expect(res.status).toBe(503);
    expect((await res.json()) as { error: string }).toEqual({ error: "server_error" });
  });
});

describe("GET /internal/hub-devices — authentication", () => {
  it("returns 401 when Authorization header is missing", async () => {
    const env = makeEnv();
    const res = await handleInternalHubDevices(req(), env);
    expect(res.status).toBe(401);
  });

  it("returns 401 when the shared secret doesn't match", async () => {
    const env = makeEnv();
    const res = await handleInternalHubDevices(req("wrong-secret"), env);
    expect(res.status).toBe(401);
  });

  it("accepts the correct shared secret", async () => {
    const env = makeEnv({ AUTH_CONFIG: createMockKV() });
    const res = await handleInternalHubDevices(req(TEST_INTERNAL_SECRET), env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });
});

describe("GET /internal/hub-devices — response", () => {
  it("returns hub devices only, without secret_hash/label", async () => {
    const kv = createMockKV();
    const env = makeEnv({ AUTH_CONFIG: kv });
    const hub = await createDeviceCredential(env, "tenant-a", "cores3-1", NOW, DEVICE_ROLE_HUB);
    await createDeviceCredential(env, "tenant-a", "kiosk-1", NOW, DEVICE_ROLE_KIOSK);

    const res = await handleInternalHubDevices(req(TEST_INTERNAL_SECRET), env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { devices: Array<{ tenant_id: string; device_id: string }> };
    expect(body.devices).toEqual([{ tenant_id: "tenant-a", device_id: hub.device_id }]);
  });

  it("returns an empty list when no devices are registered", async () => {
    const env = makeEnv({ AUTH_CONFIG: createMockKV() });
    const res = await handleInternalHubDevices(req(TEST_INTERNAL_SECRET), env);
    const body = (await res.json()) as { devices: unknown[] };
    expect(body.devices).toEqual([]);
  });
});
