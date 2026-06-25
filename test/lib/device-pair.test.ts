import { describe, it, expect } from "vitest";
import {
  startPairing,
  getPairingByUserCode,
  approvePairing,
  redeemPairing,
  PAIRING_TTL_SECONDS,
  PAIRING_POLL_INTERVAL_SECONDS,
} from "../../src/lib/device-pair";
import {
  getDeviceRecord,
  verifyDeviceCredential,
  DEVICE_ROLE,
  DEVICE_ROLE_KIOSK,
} from "../../src/lib/device";
import { createMockKV } from "../helpers/mock-env";

const NOW = 1_700_000_000;
const DC = "devpair:dc:";
const UC = "devpair:uc:";

function env() {
  return { AUTH_CONFIG: createMockKV() };
}

describe("startPairing", () => {
  it("issues device_code + user_code and stores pending state in KV", async () => {
    const e = env();
    const p = await startPairing(e, "ohishi-data", NOW);
    expect(p.device_code).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(p.user_code).toMatch(/^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
    expect(p.expires_in).toBe(PAIRING_TTL_SECONDS);
    expect(p.interval).toBe(PAIRING_POLL_INTERVAL_SECONDS);

    const kv = e.AUTH_CONFIG as unknown as { _data: Record<string, string> };
    const state = JSON.parse(kv._data[DC + p.device_code]!);
    expect(state.status).toBe("pending");
    expect(state.tenant_id).toBe("");
    expect(state.label).toBe("ohishi-data");
    expect(state.role).toBe(DEVICE_ROLE); // role 省略 → 既定
    expect(kv._data[UC + p.user_code]).toBe(p.device_code);
  });

  it("defaults the label when empty", async () => {
    const e = env();
    const p = await startPairing(e, "", NOW);
    const kv = e.AUTH_CONFIG as unknown as { _data: Record<string, string> };
    expect(JSON.parse(kv._data[DC + p.device_code]!).label).toBe("headless device");
  });

  it("stores an allowlisted role (kiosk)", async () => {
    const e = env();
    const p = await startPairing(e, "tablet", NOW, DEVICE_ROLE_KIOSK);
    const kv = e.AUTH_CONFIG as unknown as { _data: Record<string, string> };
    expect(JSON.parse(kv._data[DC + p.device_code]!).role).toBe(DEVICE_ROLE_KIOSK);
  });
});

describe("getPairingByUserCode", () => {
  it("returns pending state for a valid user_code", async () => {
    const e = env();
    const p = await startPairing(e, "l", NOW);
    const st = await getPairingByUserCode(e, p.user_code, NOW);
    expect(st?.device_code).toBe(p.device_code);
  });

  it("null for an unknown user_code", async () => {
    expect(await getPairingByUserCode(env(), "ZZZZ-ZZZZ", NOW)).toBeNull();
  });

  it("null when user_code maps to a missing device_code", async () => {
    const kv = createMockKV({ [UC + "AAAA-AAAA"]: "ghost-dc" });
    expect(await getPairingByUserCode({ AUTH_CONFIG: kv }, "AAAA-AAAA", NOW)).toBeNull();
  });

  it("null on corrupt state JSON", async () => {
    const kv = createMockKV({ [UC + "BBBB-BBBB"]: "dc1", [DC + "dc1"]: "{bad" });
    expect(await getPairingByUserCode({ AUTH_CONFIG: kv }, "BBBB-BBBB", NOW)).toBeNull();
  });

  it("null when expired", async () => {
    const e = env();
    const p = await startPairing(e, "l", NOW);
    expect(await getPairingByUserCode(e, p.user_code, NOW + PAIRING_TTL_SECONDS + 1)).toBeNull();
  });
});

describe("approvePairing", () => {
  it("approves a pending pairing and records tenant_id", async () => {
    const e = env();
    const p = await startPairing(e, "l", NOW);
    expect(await approvePairing(e, p.user_code, "tenant-1", NOW)).toBe("approved");
    const st = await getPairingByUserCode(e, p.user_code, NOW);
    expect(st?.status).toBe("approved");
    expect(st?.tenant_id).toBe("tenant-1");
  });

  it("not_found for an unknown user_code", async () => {
    expect(await approvePairing(env(), "ZZZZ-ZZZZ", "t", NOW)).toBe("not_found");
  });

  it("not_found when device_code is missing", async () => {
    const kv = createMockKV({ [UC + "AAAA-AAAA"]: "ghost" });
    expect(await approvePairing({ AUTH_CONFIG: kv }, "AAAA-AAAA", "t", NOW)).toBe("not_found");
  });

  it("expired past the deadline", async () => {
    const e = env();
    const p = await startPairing(e, "l", NOW);
    expect(await approvePairing(e, p.user_code, "t", NOW + PAIRING_TTL_SECONDS + 1)).toBe("expired");
  });

  it("already when approved twice", async () => {
    const e = env();
    const p = await startPairing(e, "l", NOW);
    await approvePairing(e, p.user_code, "t", NOW);
    expect(await approvePairing(e, p.user_code, "t", NOW)).toBe("already");
  });
});

describe("redeemPairing", () => {
  it("pending before approval", async () => {
    const e = env();
    const p = await startPairing(e, "l", NOW);
    expect(await redeemPairing(e, p.device_code, NOW)).toEqual({ status: "pending" });
  });

  it("expired when state is gone", async () => {
    expect(await redeemPairing(env(), "missing", NOW)).toEqual({ status: "expired" });
  });

  it("expired past the deadline", async () => {
    const e = env();
    const p = await startPairing(e, "l", NOW);
    expect(await redeemPairing(e, p.device_code, NOW + PAIRING_TTL_SECONDS + 1)).toEqual({
      status: "expired",
    });
  });

  it("issues a usable device credential once, then reports consumed", async () => {
    const e = env();
    const p = await startPairing(e, "ohishi-data", NOW);
    await approvePairing(e, p.user_code, "tenant-9", NOW);

    const r = await redeemPairing(e, p.device_code, NOW);
    expect(r.status).toBe("approved");
    if (r.status !== "approved") throw new Error("unreachable");
    expect(r.credential.record.tenant_id).toBe("tenant-9");
    expect(r.credential.record.label).toBe("ohishi-data");

    // 発行された credential は実際に検証できる。
    const rec = await verifyDeviceCredential(
      e,
      r.credential.device_id,
      r.credential.device_secret,
    );
    expect(rec?.tenant_id).toBe("tenant-9");
    expect(await getDeviceRecord(e, r.credential.device_id)).not.toBeNull();

    // 2 回目は consumed (再発行しない)。
    expect(await redeemPairing(e, p.device_code, NOW)).toEqual({ status: "consumed" });
  });

  it("carries the pairing role into the issued credential (kiosk)", async () => {
    const e = env();
    const p = await startPairing(e, "tablet", NOW, DEVICE_ROLE_KIOSK);
    await approvePairing(e, p.user_code, "tenant-k", NOW);
    const r = await redeemPairing(e, p.device_code, NOW);
    if (r.status !== "approved") throw new Error("unreachable");
    expect(r.credential.record.role).toBe(DEVICE_ROLE_KIOSK);
  });
});
