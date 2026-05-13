/**
 * MCP OAuth Provider — KV (`MCP_OAUTH_KV`) アクセス層。
 *
 * Phase 1 では Device Authorization Endpoint が `putDeviceCode` を使う。
 * `getDeviceCode` (Phase 3) と `getDeviceCodeByUserCode` (Phase 2) は
 * 同じ data shape を読み出すための互換 stub として先に置いておく。
 *
 * Key 設計:
 *   - `device_code:{code}` → JSON DeviceCodeRecord (TTL 900s)
 *   - `user_code:{code}`   → device_code (string, 逆引き用, TTL 900s)
 */

import type { Env } from "../index";

export interface DeviceCodeRecord {
  device_code: string;
  user_code: string;        // formatted "XXXX-XXXX"
  client_id: string;
  scope: string;            // space-separated; empty string when not provided
  status: "pending" | "approved" | "denied"; // Phase 2 で update
  created_at: number;       // ms epoch
  expires_at: number;       // ms epoch (created_at + 900_000)
}

/** RFC 8628 §3.2 expires_in。issue #93 仕様 = 15 min。 */
export const DEVICE_CODE_TTL_SEC = 900;

export async function putDeviceCode(
  env: Env,
  rec: DeviceCodeRecord,
): Promise<void> {
  if (!env.MCP_OAUTH_KV) throw new Error("MCP_OAUTH_KV not bound");
  const json = JSON.stringify(rec);
  await Promise.all([
    env.MCP_OAUTH_KV.put(`device_code:${rec.device_code}`, json, {
      expirationTtl: DEVICE_CODE_TTL_SEC,
    }),
    // 逆引き: user_code → device_code (Phase 2 で `/device/verify` が使う)
    env.MCP_OAUTH_KV.put(`user_code:${rec.user_code}`, rec.device_code, {
      expirationTtl: DEVICE_CODE_TTL_SEC,
    }),
  ]);
}

/** Phase 3 で token endpoint が使う。Phase 1 では未参照だが test 対象。 */
export async function getDeviceCode(
  env: Env,
  device_code: string,
): Promise<DeviceCodeRecord | null> {
  if (!env.MCP_OAUTH_KV) return null;
  const json = await env.MCP_OAUTH_KV.get(`device_code:${device_code}`);
  if (!json) return null;
  try {
    return JSON.parse(json) as DeviceCodeRecord;
  } catch {
    return null;
  }
}

/** Phase 2 で `/device/verify` が user_code を入力された時に使う。 */
export async function getDeviceCodeByUserCode(
  env: Env,
  user_code: string,
): Promise<string | null> {
  if (!env.MCP_OAUTH_KV) return null;
  return env.MCP_OAUTH_KV.get(`user_code:${user_code}`);
}
