/**
 * headless device pairing (RFC 8628 風) — smb-watch 等の **ブラウザを持たない box** が
 * device credential を発行してもらうためのフロー (Phase 2.5 / ohishi-exp/smb-watch#1)。
 *
 *   1. box: startPairing → device_code (秘密・box 保持) + user_code (短い・operator 提示) を得て
 *      verification URL + user_code を端末に表示する。
 *   2. operator: スマホ等のブラウザで verification URL を開き (auth-worker で Google ログイン =
 *      tenant 確定)、user_code を承認する → approvePairing。
 *   3. box: redeemPairing(device_code) を interval 間隔で poll。approved になったら
 *      `createDeviceCredential` (lib/device.ts) で credential を発行して 1 回だけ返す。
 *
 * device_code は秘密 (poll 用、box だけが持つ)。user_code は短く人間が承認 UI で扱う。
 * pending state は KV に短命 (既定 10 分) で置き、TTL で自動消滅する。
 */

import { base64Encode } from "./lineworks-crypto";
import {
  createDeviceCredential,
  type DeviceKvEnv,
  type NewDeviceCredential,
} from "./device";

const DC_PREFIX = "devpair:dc:"; // device_code → PairState(JSON)
const UC_PREFIX = "devpair:uc:"; // user_code  → device_code

/** 既定の pairing 有効期限 (秒)。 */
export const PAIRING_TTL_SECONDS = 600;
/** box が推奨される poll 間隔 (秒)。 */
export const PAIRING_POLL_INTERVAL_SECONDS = 5;

/** user_code に使う非曖昧な英数字 (0/O, 1/I 等を除外)。 */
const USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export type PairingStatus = "pending" | "approved" | "consumed";

/** KV に置く pairing の状態。 */
export interface PairState {
  device_code: string;
  user_code: string;
  /** approve 時に operator のセッションから確定する tenant。pending では空。 */
  tenant_id: string;
  /** box が運用識別用に渡すラベル (例: hostname)。 */
  label: string;
  status: PairingStatus;
  created_at: number;
  /** unix 秒。これを過ぎたら expired 扱い (KV TTL でも消える)。 */
  expires_at: number;
}

/** startPairing の返り値 (box が表示する)。 */
export interface NewPairing {
  device_code: string;
  user_code: string;
  expires_in: number;
  interval: number;
}

function base64UrlBytes(bytes: Uint8Array): string {
  return base64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomDeviceCode(): string {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return base64UrlBytes(buf);
}

/** 8 文字の user_code を生成し `XXXX-XXXX` 形式で返す。 */
function randomUserCode(): string {
  const buf = new Uint8Array(8);
  crypto.getRandomValues(buf);
  let s = "";
  for (let i = 0; i < buf.length; i++) {
    s += USER_CODE_ALPHABET[buf[i]! % USER_CODE_ALPHABET.length];
  }
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}

/** pairing を開始し、KV に pending state を置く。 */
export async function startPairing(
  env: DeviceKvEnv,
  label: string,
  now: number,
  ttlSeconds: number = PAIRING_TTL_SECONDS,
): Promise<NewPairing> {
  const device_code = randomDeviceCode();
  const user_code = randomUserCode();
  const state: PairState = {
    device_code,
    user_code,
    tenant_id: "",
    label: label || "headless device",
    status: "pending",
    created_at: now,
    expires_at: now + ttlSeconds,
  };
  await env.AUTH_CONFIG.put(DC_PREFIX + device_code, JSON.stringify(state), {
    expirationTtl: ttlSeconds,
  });
  await env.AUTH_CONFIG.put(UC_PREFIX + user_code, device_code, {
    expirationTtl: ttlSeconds,
  });
  return {
    device_code,
    user_code,
    expires_in: ttlSeconds,
    interval: PAIRING_POLL_INTERVAL_SECONDS,
  };
}

async function readState(env: DeviceKvEnv, deviceCode: string): Promise<PairState | null> {
  const raw = await env.AUTH_CONFIG.get(DC_PREFIX + deviceCode);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as PairState;
  } catch {
    return null;
  }
}

/** approve 画面が user_code から pending state を引く。不在/期限切れは null。 */
export async function getPairingByUserCode(
  env: DeviceKvEnv,
  userCode: string,
  now: number,
): Promise<PairState | null> {
  const deviceCode = await env.AUTH_CONFIG.get(UC_PREFIX + userCode);
  if (!deviceCode) return null;
  const state = await readState(env, deviceCode);
  if (!state) return null;
  if (state.expires_at <= now) return null;
  return state;
}

export type ApproveResult = "approved" | "not_found" | "expired" | "already";

/** operator が user_code を承認する。pending かつ未期限のときだけ tenant を確定し approved に。 */
export async function approvePairing(
  env: DeviceKvEnv,
  userCode: string,
  tenantId: string,
  now: number,
): Promise<ApproveResult> {
  const deviceCode = await env.AUTH_CONFIG.get(UC_PREFIX + userCode);
  if (!deviceCode) return "not_found";
  const state = await readState(env, deviceCode);
  if (!state) return "not_found";
  if (state.expires_at <= now) return "expired";
  if (state.status !== "pending") return "already";
  state.status = "approved";
  state.tenant_id = tenantId;
  const remaining = Math.max(1, state.expires_at - now);
  await env.AUTH_CONFIG.put(DC_PREFIX + deviceCode, JSON.stringify(state), {
    expirationTtl: remaining,
  });
  return "approved";
}

export type RedeemResult =
  | { status: "pending" }
  | { status: "expired" }
  | { status: "consumed" }
  | { status: "approved"; credential: NewDeviceCredential };

/**
 * box が device_code で poll する。approved になっていれば device credential を発行して
 * 1 回だけ返し (status→consumed)、以後は consumed を返す。pending/期限切れも報告する。
 */
export async function redeemPairing(
  env: DeviceKvEnv,
  deviceCode: string,
  now: number,
): Promise<RedeemResult> {
  const state = await readState(env, deviceCode);
  if (!state || state.expires_at <= now) return { status: "expired" };
  if (state.status === "pending") return { status: "pending" };
  if (state.status === "consumed") return { status: "consumed" };

  // status === "approved": credential を発行して consumed に倒す。
  const credential = await createDeviceCredential(env, state.tenant_id, state.label, now);
  state.status = "consumed";
  const remaining = Math.max(1, state.expires_at - now);
  await env.AUTH_CONFIG.put(DC_PREFIX + deviceCode, JSON.stringify(state), {
    expirationTtl: remaining,
  });
  return { status: "approved", credential };
}
