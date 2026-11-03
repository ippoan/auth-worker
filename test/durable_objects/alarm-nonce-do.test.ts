import { describe, it, expect, vi, afterEach } from "vitest";

import { createMockAlarmNonceDO, createMockEnv } from "../helpers/mock-env";
import { alarmNonceStore, bumpAlarmRate } from "../../src/lib/alarm-nonce";

const T0 = Date.UTC(2026, 10, 3, 4, 0, 0);

afterEach(() => vi.useRealTimers());

describe("AlarmNonceDO", () => {
  it("bumpRate は分ごとに数え、上限で止め、次の分で数え直す", async () => {
    const ns = createMockAlarmNonceDO();
    const d = ns._do;
    expect(await d.bumpRate("ip:a", 2, T0)).toBe(true);
    expect(await d.bumpRate("ip:a", 2, T0 + 1000)).toBe(true);
    expect(await d.bumpRate("ip:a", 2, T0 + 2000)).toBe(false);
    // 別の key は別に数える
    expect(await d.bumpRate("ip:b", 2, T0)).toBe(true);
    // 次の分
    expect(await d.bumpRate("ip:a", 2, T0 + 60_000)).toBe(true);
    expect(ns._data["rate:ip:a"]).toEqual({ minute: Math.floor((T0 + 60_000) / 60_000), n: 1 });
  });

  it("put した値は take で 1 回だけ取れる", async () => {
    const ns = createMockAlarmNonceDO();
    await ns._do.put("devnonce:x", "v", T0);
    expect(await ns._do.take("devnonce:x")).toBe("v");
    expect(await ns._do.take("devnonce:x")).toBeNull();
  });

  it("書き込みで掃除の alarm を 1 回だけ立てる", async () => {
    const ns = createMockAlarmNonceDO();
    await ns._do.put("devnonce:x", "v", T0);
    expect(ns._alarm.at).toBe(T0 + 5 * 60_000);
    await ns._do.bumpRate("ip:a", 1, T0 + 1000);
    expect(ns._alarm.at).toBe(T0 + 5 * 60_000);
  });

  it("alarm は期限切れの nonce・読めない値・過ぎた分の回数を消し、残りがあれば次を立てる", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    const nowSec = Math.floor(T0 / 1000);
    const minute = Math.floor(T0 / 60_000);
    const ns = createMockAlarmNonceDO();
    Object.assign(ns._data, {
      "devnonce:live": JSON.stringify({ purpose: "kiosk", exp: nowSec + 30 }),
      "devnonce:old": JSON.stringify({ purpose: "kiosk", exp: nowSec }),
      "devnonce:noexp": JSON.stringify({ purpose: "kiosk" }),
      "devnonce:broken": "{",
      "devnonce:notstring": 1,
      "rate:now": { minute, n: 1 },
      "rate:past": { minute: minute - 1, n: 5 },
    });
    await ns._do.alarm();
    expect(Object.keys(ns._data).sort()).toEqual(["devnonce:live", "rate:now"]);
    expect(ns._alarm.at).toBe(T0 + 5 * 60_000);
  });

  it("alarm で消すものが無ければ消さずに次を立てる", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    const ns = createMockAlarmNonceDO();
    ns._data["rate:now"] = { minute: Math.floor(T0 / 60_000), n: 1 };
    await ns._do.alarm();
    expect(Object.keys(ns._data)).toEqual(["rate:now"]);
    expect(ns._alarm.at).toBe(T0 + 5 * 60_000);
  });

  it("alarm で空になったら次の alarm は立てない", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    const ns = createMockAlarmNonceDO();
    ns._data["rate:past"] = { minute: Math.floor(T0 / 60_000) - 1, n: 1 };
    await ns._do.alarm();
    expect(ns._data).toEqual({});
    expect(ns._alarm.at).toBeNull();
  });
});

describe("alarmNonceStore / bumpAlarmRate", () => {
  it("全体で 1 つの DO を apac-ne の hint で引く", async () => {
    const ns = createMockAlarmNonceDO();
    const env = createMockEnv({ ALARM_NONCE_DO: ns });
    alarmNonceStore(env);
    expect(await bumpAlarmRate(env, "ip:a", 1)).toBe(true);
    expect(await bumpAlarmRate(env, "ip:a", 1)).toBe(false);
    expect(ns._hints).toEqual(["apac-ne", "apac-ne", "apac-ne"]);
  });
});
