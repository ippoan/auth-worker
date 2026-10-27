import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
vi.mock("../src/lib/alc-internal", () => ({
  resolveActiveDeviceTenant: vi.fn(),
}));

import { DevicePairEntrypoint, RE_PAIR_ROLE } from "../src/device-pair-entrypoint";
import { getDeviceRecord, verifyDeviceCredential } from "../src/lib/device";
import { resolveActiveDeviceTenant } from "../src/lib/alc-internal";
import { createMockKV } from "./helpers/mock-env";
import type { Env } from "../src/index";

const mockResolveTenant = vi.mocked(resolveActiveDeviceTenant);
/** テスト固有のダミーの値 (本番の値ではない)。 */
const TENANT = "88888888-8888-8888-8888-888888888888";
const DEVICE = "0b9f5a52-6a1e-4c1b-9d2a-3f4e5d6c7b8a";
const LABEL = `alc-app:${DEVICE}`;

function makeEnv(): Env {
  return { AUTH_CONFIG: createMockKV(), JWT_SECRET: "device-test-secret", WORKER_ENV: "staging" } as unknown as Env;
}

/** `[[services]] entrypoint = "DevicePairEntrypoint"` 越しの呼び出しを再現する。 */
function rpc(e: Env): DevicePairEntrypoint {
  return new DevicePairEntrypoint({} as unknown as ExecutionContext, e);
}

beforeEach(() => {
  mockResolveTenant.mockReset();
  mockResolveTenant.mockResolvedValue({ ok: true, tenantId: TENANT });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("DevicePairEntrypoint (W6b-b、Refs ippoan/rust-alc-api#680)", () => {
  it("RPC で呼べるメソッドは pairInternal だけ", () => {
    const own = Object.getOwnPropertyNames(DevicePairEntrypoint.prototype).filter((n) => n !== "constructor");
    expect(own).toEqual(["pairInternal"]);
  });

  it("端末の ID から引いた tenant で kiosk の credential を発行し、同じ label の旧 credential を失効する", async () => {
    const e = makeEnv();
    const first = await rpc(e).pairInternal(DEVICE, LABEL);
    expect(first).toEqual({ device_id: expect.any(String), device_secret: expect.any(String) });
    expect(Object.getPrototypeOf(first)).toBe(Object.prototype);
    expect(mockResolveTenant).toHaveBeenCalledWith(e, DEVICE);
    const record = await getDeviceRecord(e, first!.device_id);
    expect(record?.tenant_id).toBe(TENANT);
    expect(record?.role).toBe(RE_PAIR_ROLE);
    expect(record?.label).toBe(LABEL);

    const second = await rpc(e).pairInternal(DEVICE, LABEL);
    expect(second!.device_id).not.toBe(first!.device_id);
    expect(await verifyDeviceCredential(e, first!.device_id, first!.device_secret)).toBeNull();
    expect(await verifyDeviceCredential(e, second!.device_id, second!.device_secret)).not.toBeNull();
  });

  it("tenant が引けない (未登録・無効 / 問い合わせの失敗) なら null で、固定の語だけをログに出す", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    for (const reason of ["not_found", "unavailable"] as const) {
      mockResolveTenant.mockResolvedValueOnce({ ok: false, reason });
      expect(await rpc(makeEnv()).pairInternal(DEVICE, LABEL)).toBeNull();
    }
    expect(log.mock.calls.map((c) => JSON.parse(String(c[0])))).toEqual([
      { event: "device_pair_rpc_denied", reason: "not_found" },
      { event: "device_pair_rpc_denied", reason: "upstream" },
    ]);
    for (const call of log.mock.calls) expect(String(call[0])).not.toContain(DEVICE);
  });

  it("発行で例外が出ても throw せず null (例外の種類だけをログに出す)", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    mockResolveTenant.mockRejectedValueOnce(new TypeError("boom"));
    expect(await rpc(makeEnv()).pairInternal(DEVICE, LABEL)).toBeNull();
    expect(JSON.parse(String(log.mock.calls[0]![0]))).toEqual({ event: "device_pair_rpc_failed", error: "TypeError" });
  });

  it("引数が文字列でない・空なら呼ばずに null", async () => {
    const e = makeEnv();
    for (const [id, label] of [
      ["", LABEL],
      [DEVICE, ""],
      [1, LABEL],
      [DEVICE, null],
    ] as const) {
      expect(await rpc(e).pairInternal(id as unknown as string, label as unknown as string)).toBeNull();
    }
    expect(mockResolveTenant).not.toHaveBeenCalled();
  });
});
