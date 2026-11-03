/**
 * `/device/alarm-nonce`・`/device/alarm-token` の nonce と回数制限を持つ Durable Object
 * (`lib/alarm-nonce.ts` の `alarmNonceStore` が全体で 1 つを日本寄り (`apac-ne`) に置く)。
 *
 * 以前は KV (`AUTH_CONFIG` の `devnonce:` と `MCP_OAUTH_KV` の回数) に置いていたが、KV の書き込みは
 * 中央の保存場所まで行くので、要求が SIN などに着くと nonce の口が 10 秒を超えて画面の上限で
 * 切れていた (運行管理者席の Failed to fetch)。KV は置き場所をアジアに指定できない。
 * DO なら書いた直後に読めるので、発行した拠点と消費する拠点が違っても nonce が見える。
 *
 * 期限の切れた nonce と過ぎた分の回数は alarm でまとめて消す。
 */
import { DurableObject } from "cloudflare:workers";

/** 回数の key の頭。値は `{ minute, n }` (分ごとの窓)。 */
const RATE_PREFIX = "rate:";
/** 期限切れを掃除する間隔 */
const SWEEP_INTERVAL_MS = 5 * 60_000;

interface RateEntry {
  minute: number;
  n: number;
}

export class AlarmNonceDO extends DurableObject {
  private get storage(): DurableObjectStorage {
    return (this.ctx as DurableObjectState).storage;
  }

  /**
   * `key` の今の分の回数を 1 足す。`limitPerMinute` に達していれば足さずに false。
   * 1 つの DO の中で直列に走るので、KV と違って同時の要求で数え漏れない。
   */
  async bumpRate(key: string, limitPerMinute: number, nowMs: number): Promise<boolean> {
    const minute = Math.floor(nowMs / 60_000);
    const storageKey = RATE_PREFIX + key;
    const cur = await this.storage.get<RateEntry>(storageKey);
    const n = cur && cur.minute === minute ? cur.n : 0;
    if (n >= limitPerMinute) return false;
    await this.storage.put(storageKey, { minute, n: n + 1 });
    await this.ensureSweep(nowMs);
    return true;
  }

  /** `key` に値を置く (nonce の record。期限は値の `exp` で見る)。 */
  async put(key: string, value: string, nowMs: number): Promise<void> {
    await this.storage.put(key, value);
    await this.ensureSweep(nowMs);
  }

  /** `key` の値を取り出して消す (1 回きり)。無ければ null。 */
  async take(key: string): Promise<string | null> {
    const value = await this.storage.get<string>(key);
    if (value === undefined) return null;
    await this.storage.delete(key);
    return value;
  }

  /** 期限の切れた nonce と、過ぎた分の回数を消す。 */
  async alarm(): Promise<void> {
    const nowMs = Date.now();
    const minute = Math.floor(nowMs / 60_000);
    const nowSec = Math.floor(nowMs / 1000);
    const stale: string[] = [];
    for (const [key, value] of await this.storage.list()) {
      if (key.startsWith(RATE_PREFIX)) {
        if ((value as RateEntry).minute < minute) stale.push(key);
      } else if (isExpired(value, nowSec)) {
        stale.push(key);
      }
    }
    if (stale.length > 0) await this.storage.delete(stale);
    if ((await this.storage.list({ limit: 1 })).size > 0) {
      await this.storage.setAlarm(nowMs + SWEEP_INTERVAL_MS);
    }
  }

  private async ensureSweep(nowMs: number): Promise<void> {
    if ((await this.storage.getAlarm()) === null) {
      await this.storage.setAlarm(nowMs + SWEEP_INTERVAL_MS);
    }
  }
}

/** nonce の record (JSON の `exp`、unix 秒) が期限切れか。読めない値も消す側に倒す。 */
function isExpired(value: unknown, nowSec: number): boolean {
  if (typeof value !== "string") return true;
  try {
    const exp = (JSON.parse(value) as { exp?: unknown }).exp;
    return typeof exp !== "number" || exp <= nowSec;
  } catch {
    return true;
  }
}
