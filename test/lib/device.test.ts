import { describe, it, expect, vi, afterEach } from "vitest";
import {
  createDeviceCredential,
  getDeviceRecord,
  revokeDeviceCredential,
  verifyDeviceCredential,
  mintDeviceJwt,
  normalizeDeviceRole,
  sha256Hex,
  DEVICE_ROLE,
  DEVICE_ROLE_KIOSK,
  DEVICE_ROLE_DTAKO_INGEST,
  DEVICE_ROLE_HUB,
  DEVICE_ROLE_PRINT,
  DEVICE_JWT_TTL_SECONDS,
  listAllHubDeviceRecords,
  type DeviceRecord,
} from "../../src/lib/device";
import { verifyJwt } from "../../src/lib/jwt";
import { createMockKV } from "../helpers/mock-env";

const SECRET = "test-jwt-secret-shared-with-alc-api";
// verifyJwt は exp > 現在時刻を要求するので、mint の exp が未来になるよう実時刻基準にする。
const NOW = Math.floor(Date.now() / 1000);

afterEach(() => {
  vi.restoreAllMocks();
});

describe("sha256Hex", () => {
  it("returns 64-char hex and is deterministic", async () => {
    const h = await sha256Hex("hello");
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(await sha256Hex("hello")).toBe(h);
    expect(await sha256Hex("world")).not.toBe(h);
  });
});

describe("normalizeDeviceRole", () => {
  it("passes allowlisted roles through", () => {
    expect(normalizeDeviceRole(DEVICE_ROLE)).toBe(DEVICE_ROLE);
    expect(normalizeDeviceRole(DEVICE_ROLE_KIOSK)).toBe(DEVICE_ROLE_KIOSK);
    expect(normalizeDeviceRole(DEVICE_ROLE_DTAKO_INGEST)).toBe(DEVICE_ROLE_DTAKO_INGEST);
    expect(normalizeDeviceRole(DEVICE_ROLE_HUB)).toBe(DEVICE_ROLE_HUB);
    expect(normalizeDeviceRole(DEVICE_ROLE_PRINT)).toBe(DEVICE_ROLE_PRINT);
  });

  it("falls back to the default role for unknown strings", () => {
    expect(normalizeDeviceRole("admin")).toBe(DEVICE_ROLE);
    expect(normalizeDeviceRole("")).toBe(DEVICE_ROLE);
  });

  it("falls back to the default role for non-string input", () => {
    expect(normalizeDeviceRole(undefined)).toBe(DEVICE_ROLE);
    expect(normalizeDeviceRole(123)).toBe(DEVICE_ROLE);
  });
});

describe("createDeviceCredential", () => {
  it("issues id+secret, stores hash-only record (no plaintext secret)", async () => {
    const kv = createMockKV();
    const env = { AUTH_CONFIG: kv };
    const cred = await createDeviceCredential(env, "tenant-1", "ohishi-data", NOW);

    expect(cred.device_id).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(cred.device_secret).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(cred.record.tenant_id).toBe("tenant-1");
    expect(cred.record.label).toBe("ohishi-data");
    expect(cred.record.created_at).toBe(NOW);
    expect(cred.record.revoked).toBe(false);
    expect(cred.record.role).toBe(DEVICE_ROLE); // role 省略 → 既定
    expect(cred.record.secret_hash).toBe(await sha256Hex(cred.device_secret));

    // KV stored value never contains the plaintext secret.
    const stored = await kv.get("device:" + cred.device_id);
    expect(stored).not.toBeNull();
    expect(stored).not.toContain(cred.device_secret);
    expect(JSON.parse(stored!).secret_hash).toBe(cred.record.secret_hash);
  });

  it("generates distinct ids/secrets across calls", async () => {
    const env = { AUTH_CONFIG: createMockKV() };
    const a = await createDeviceCredential(env, "t", "l", NOW);
    const b = await createDeviceCredential(env, "t", "l", NOW);
    expect(a.device_id).not.toBe(b.device_id);
    expect(a.device_secret).not.toBe(b.device_secret);
  });

  it("stores an allowlisted role and normalizes unknown ones", async () => {
    const env = { AUTH_CONFIG: createMockKV() };
    const kiosk = await createDeviceCredential(env, "t", "l", NOW, DEVICE_ROLE_KIOSK);
    expect(kiosk.record.role).toBe(DEVICE_ROLE_KIOSK);
    const hub = await createDeviceCredential(env, "t", "l", NOW, DEVICE_ROLE_HUB);
    expect(hub.record.role).toBe(DEVICE_ROLE_HUB); // CoreS3 ハブ (#363)
    const print = await createDeviceCredential(env, "t", "l", NOW, DEVICE_ROLE_PRINT);
    expect(print.record.role).toBe(DEVICE_ROLE_PRINT); // AtomS3 印刷ブリッジ (alc-app-s3#38)
    const bad = await createDeviceCredential(env, "t", "l", NOW, "admin");
    expect(bad.record.role).toBe(DEVICE_ROLE); // 未知 role は既定に倒す
  });
});

describe("getDeviceRecord", () => {
  it("returns the record when present", async () => {
    const env = { AUTH_CONFIG: createMockKV() };
    const cred = await createDeviceCredential(env, "t", "l", NOW);
    const rec = await getDeviceRecord(env, cred.device_id);
    expect(rec?.device_id).toBe(cred.device_id);
  });

  it("returns null when missing", async () => {
    const env = { AUTH_CONFIG: createMockKV() };
    expect(await getDeviceRecord(env, "nope")).toBeNull();
  });

  it("returns null on corrupt JSON", async () => {
    const kv = createMockKV({ "device:bad": "{not json" });
    expect(await getDeviceRecord({ AUTH_CONFIG: kv }, "bad")).toBeNull();
  });
});

describe("verifyDeviceCredential", () => {
  it("returns the record for a valid id+secret", async () => {
    const env = { AUTH_CONFIG: createMockKV() };
    const cred = await createDeviceCredential(env, "tenant-1", "l", NOW);
    const rec = await verifyDeviceCredential(env, cred.device_id, cred.device_secret);
    expect(rec?.tenant_id).toBe("tenant-1");
  });

  it("returns null for a wrong secret (same-length hash mismatch)", async () => {
    const env = { AUTH_CONFIG: createMockKV() };
    const cred = await createDeviceCredential(env, "t", "l", NOW);
    expect(await verifyDeviceCredential(env, cred.device_id, "wrong-secret")).toBeNull();
  });

  it("returns null for a missing device", async () => {
    const env = { AUTH_CONFIG: createMockKV() };
    expect(await verifyDeviceCredential(env, "missing", "x")).toBeNull();
  });

  it("returns null for a revoked device", async () => {
    const env = { AUTH_CONFIG: createMockKV() };
    const cred = await createDeviceCredential(env, "t", "l", NOW);
    await revokeDeviceCredential(env, cred.device_id);
    expect(await verifyDeviceCredential(env, cred.device_id, cred.device_secret)).toBeNull();
  });

  it("returns null when stored hash has a different length (length-mismatch guard)", async () => {
    // 壊れた / 旧式の secret_hash (短い) を直接置いて length 不一致 branch を踏む。
    const record: DeviceRecord = {
      device_id: "len",
      tenant_id: "t",
      secret_hash: "deadbeef", // 8 chars != sha256 の 64 chars
      label: "l",
      created_at: NOW,
      revoked: false,
    };
    const kv = createMockKV({ "device:len": JSON.stringify(record) });
    expect(await verifyDeviceCredential({ AUTH_CONFIG: kv }, "len", "anything")).toBeNull();
  });
});

describe("revokeDeviceCredential", () => {
  it("revokes an existing device and persists revoked=true", async () => {
    const env = { AUTH_CONFIG: createMockKV() };
    const cred = await createDeviceCredential(env, "t", "l", NOW);
    expect(await revokeDeviceCredential(env, cred.device_id)).toBe(true);
    expect((await getDeviceRecord(env, cred.device_id))?.revoked).toBe(true);
  });

  it("returns false for a missing device", async () => {
    const env = { AUTH_CONFIG: createMockKV() };
    expect(await revokeDeviceCredential(env, "missing")).toBe(false);
  });
});

describe("mintDeviceJwt", () => {
  const record: DeviceRecord = {
    device_id: "dev-1",
    tenant_id: "tenant-9",
    secret_hash: "x",
    label: "l",
    created_at: NOW,
    revoked: false,
  };

  it("mints an HS256 JWT that verifyJwt accepts, with minimal-role claims", async () => {
    const token = await mintDeviceJwt({ JWT_SECRET: SECRET, WORKER_ENV: "staging" }, record, NOW);
    const payload = await verifyJwt(token, SECRET, "staging");
    expect(payload).not.toBeNull();
    expect(payload!.sub).toBe("dev-1");
    expect(payload!.tenant_id).toBe("tenant-9");
    expect(payload!.role).toBe(DEVICE_ROLE);
    expect(payload!.env).toBe("staging");
    expect(payload!.iat).toBe(NOW);
    expect(payload!.exp).toBe(NOW + DEVICE_JWT_TTL_SECONDS);
  });

  it("carries the record's role when set (kiosk)", async () => {
    const kioskRecord: DeviceRecord = { ...record, role: DEVICE_ROLE_KIOSK };
    const token = await mintDeviceJwt({ JWT_SECRET: SECRET, WORKER_ENV: "staging" }, kioskRecord, NOW);
    const payload = await verifyJwt(token, SECRET, "staging");
    expect(payload!.role).toBe(DEVICE_ROLE_KIOSK);
  });

  it("carries the record's role when set (print、cf-alc-recorder が introspect で読む)", async () => {
    const printRecord: DeviceRecord = { ...record, role: DEVICE_ROLE_PRINT };
    const token = await mintDeviceJwt({ JWT_SECRET: SECRET, WORKER_ENV: "staging" }, printRecord, NOW);
    const payload = await verifyJwt(token, SECRET, "staging");
    expect(payload!.role).toBe(DEVICE_ROLE_PRINT);
  });

  it("carries the record's role when set (hub、cf-alc-recorder が introspect で読む)", async () => {
    const hubRecord: DeviceRecord = { ...record, role: DEVICE_ROLE_HUB };
    const token = await mintDeviceJwt({ JWT_SECRET: SECRET, WORKER_ENV: "staging" }, hubRecord, NOW);
    const payload = await verifyJwt(token, SECRET, "staging");
    expect(payload!.role).toBe(DEVICE_ROLE_HUB);
    expect(payload!.sub).toBe("dev-1"); // recorder は sub を device_id として注入する
  });

  it("honors a custom ttl", async () => {
    const token = await mintDeviceJwt({ JWT_SECRET: SECRET, WORKER_ENV: "prod" }, record, NOW, 60);
    const payload = await verifyJwt(token, SECRET, "prod");
    expect(payload!.exp).toBe(NOW + 60);
  });

  it("is rejected by verifyJwt under a different env (cross-env replay guard)", async () => {
    const token = await mintDeviceJwt({ JWT_SECRET: SECRET, WORKER_ENV: "staging" }, record, NOW);
    expect(await verifyJwt(token, SECRET, "prod")).toBeNull();
  });

  it("throws when JWT_SECRET is not configured", async () => {
    await expect(
      mintDeviceJwt({ JWT_SECRET: undefined, WORKER_ENV: "staging" }, record, NOW),
    ).rejects.toThrow("JWT_SECRET not configured");
  });
});

describe("listAllHubDeviceRecords", () => {
  it("returns an empty array when no devices exist", async () => {
    const env = { AUTH_CONFIG: createMockKV() };
    expect(await listAllHubDeviceRecords(env)).toEqual([]);
  });

  it("returns only hub devices, across tenants, as {tenant_id, device_id}", async () => {
    const env = { AUTH_CONFIG: createMockKV() };
    const hub1 = await createDeviceCredential(env, "tenant-a", "cores3-1", NOW, DEVICE_ROLE_HUB);
    await createDeviceCredential(env, "tenant-a", "kiosk-1", NOW, DEVICE_ROLE_KIOSK); // hub 以外は除外
    const hub2 = await createDeviceCredential(env, "tenant-b", "cores3-2", NOW, DEVICE_ROLE_HUB);
    await createDeviceCredential(env, "tenant-b", "unset-role", NOW); // role 未指定 (既定 DEVICE_ROLE) も除外

    const result = await listAllHubDeviceRecords(env);
    expect(result).toHaveLength(2);
    expect(result).toEqual(
      expect.arrayContaining([
        { tenant_id: "tenant-a", device_id: hub1.device_id },
        { tenant_id: "tenant-b", device_id: hub2.device_id },
      ]),
    );
    // secret_hash 等の機微値を含まない最小限の shape であること
    for (const r of result) {
      expect(Object.keys(r).sort()).toEqual(["device_id", "tenant_id"]);
    }
  });

  it("excludes revoked hub devices", async () => {
    const env = { AUTH_CONFIG: createMockKV() };
    const hub = await createDeviceCredential(env, "tenant-a", "cores3-1", NOW, DEVICE_ROLE_HUB);
    await revokeDeviceCredential(env, hub.device_id);
    expect(await listAllHubDeviceRecords(env)).toEqual([]);
  });

  it("skips corrupt KV entries (getDeviceRecord returns null)", async () => {
    const kv = createMockKV({ "device:bad": "{not json" });
    const env = { AUTH_CONFIG: kv };
    const hub = await createDeviceCredential(env, "tenant-a", "cores3-1", NOW, DEVICE_ROLE_HUB);
    const result = await listAllHubDeviceRecords(env);
    expect(result).toEqual([{ tenant_id: "tenant-a", device_id: hub.device_id }]);
  });
});
