/**
 * 無人デバイス (smb-watch 等) 向けの device credential + device JWT 発行 (Phase 2)。
 *
 * 設計 (ohishi-exp/smb-watch#1 Phase 2 / 案B):
 *   - pairing (browser・Google ログインで tenant 確定) で **長命 device credential**
 *     (device_id + device_secret) を 1 個発行し KV に保管する。secret は平文保存せず
 *     sha-256 ハッシュのみ持つ。revocable。
 *   - runtime (無人 box) は device credential を `/device/token` に提示し、**短命
 *     device JWT** を mint してもらう。JWT は `JWT_SECRET` (rust-alc-api と HS256 共有)
 *     で署名し、`/auth/introspect` が検証する通常の auth-worker JWT と同型。
 *   - device JWT の role は最小権限 (`DEVICE_ROLE`)。盗難時の blast radius を限定する。
 *
 * 署名様式は `internal-jwt.ts` の `signHs256` に合わせる (header {alg:HS256,typ:JWT}、
 * base64url、JWT_SECRET)。round-trip は `jwt.ts::verifyJwt` で検証できる。
 */

import { base64Encode } from "./lineworks-crypto";
import { resolveSecret, type SecretBinding } from "./secret";

const TEXT_ENCODER = new TextEncoder();

/** KV key prefix。`device:<device_id>` に DeviceRecord(JSON) を格納する。 */
const KV_PREFIX = "device:";

/** device JWT の既定 TTL (1h)。box は run のたびに mint する。 */
export const DEVICE_JWT_TTL_SECONDS = 3600;

/**
 * device JWT の既定 role。carins ファイル upload 専用の最小権限。
 * admin / 他 API を含めない (= 盗難時も「1 tenant の車検証 upload」に限定)。
 */
export const DEVICE_ROLE = "device-uploader";

/**
 * alc-app キオスク端末用 role。kiosk が叩く最小 route (measurements / tenko /
 * timecard 等) のみを許可する想定で、consumer (rust-alc-api) 側が route 許可を判定する。
 * carins upload (`device-uploader`) とは blast radius を用途別に分離する (Refs rust-alc-api#434)。
 */
export const DEVICE_ROLE_KIOSK = "device-kiosk";

/**
 * Kagoya VPS 上の無人 dtako データ投入系サービス (browser-render-rust の
 * dtakolog cron / dtako-scraper の CSV アップロード) 共用 role。同一 VPS・同一
 * 運用チーム・同一機能ドメイン (dtako データの rust-alc-api への ingest) なので、
 * サービスごとに role を分けず 1 role に統一する (2026-07-01、dtako-scraper#14
 * 対応時に device-dtako-upload 単独 role 新設案から方針転換)。
 *
 * 許可 path は `device-data-proxy.ts` の `ROLE_PATH_ALLOWLIST` 側で管理
 * (`/api/dtako-logs/bulk` + `/api/upload`)。device credential (device_id/
 * device_secret) 自体はサービス・テナントごとに個別発行するため、rotate/revoke
 * の粒度は role 統一後も維持される (role は「できること」、credential は
 * 「誰が」の軸で直交する)。
 */
export const DEVICE_ROLE_DTAKO_INGEST = "device-dtako-ingest";

/** pairing / credential 発行で受理する device role の allowlist。 */
export const DEVICE_ROLES: ReadonlySet<string> = new Set([
  DEVICE_ROLE,
  DEVICE_ROLE_KIOSK,
  DEVICE_ROLE_DTAKO_INGEST,
]);

/**
 * 受け取った role 文字列を allowlist で検証して返す。未知 / 空は既定 (`DEVICE_ROLE`)。
 * device JWT の role は blast radius を決めるので、外部入力をそのまま信用せず必ず通す。
 */
export function normalizeDeviceRole(raw: unknown): string {
  return typeof raw === "string" && DEVICE_ROLES.has(raw) ? raw : DEVICE_ROLE;
}

/** KV に保管する device レコード。平文 secret は持たない。 */
export interface DeviceRecord {
  device_id: string;
  tenant_id: string;
  /** sha-256(device_secret) の hex。検証は hash 同士の定数時間比較で行う。 */
  secret_hash: string;
  /** 運用識別用ラベル (例: "ohishi-data smb-watch")。 */
  label: string;
  /**
   * device JWT に載せる role (blast radius)。旧レコードには無いので
   * `mintDeviceJwt` は `?? DEVICE_ROLE` で後方互換に倒す。
   */
  role?: string;
  /** 発行時刻 (unix 秒)。 */
  created_at: number;
  /** revoke 済みフラグ。true なら検証は常に失敗する。 */
  revoked: boolean;
}

/** KV binding だけを要求する env サブセット。 */
export interface DeviceKvEnv {
  AUTH_CONFIG: KVNamespace;
}

/** JWT 署名に要る env サブセット (`internal-jwt.ts` と同じ)。 */
export interface DeviceJwtEnv {
  JWT_SECRET: SecretBinding;
  WORKER_ENV: string;
}

/** pairing 発行結果。`device_secret` は平文で、この 1 回だけ呼び出し側に返る。 */
export interface NewDeviceCredential {
  device_id: string;
  device_secret: string;
  record: DeviceRecord;
}

/** crypto.getRandomValues ベースの base64url ランダムトークン。 */
function randomToken(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return base64UrlEncode(buf);
}

/** sha-256 を hex 文字列で返す。 */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", TEXT_ENCODER.encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * 新規 device credential を発行し KV に保管する。
 * 返り値の `device_secret` は平文で、発行時の 1 回だけ取得できる (KV には hash のみ)。
 */
export async function createDeviceCredential(
  env: DeviceKvEnv,
  tenantId: string,
  label: string,
  now: number,
  role: string = DEVICE_ROLE,
): Promise<NewDeviceCredential> {
  const device_id = randomToken(16);
  const device_secret = randomToken(32);
  const record: DeviceRecord = {
    device_id,
    tenant_id: tenantId,
    secret_hash: await sha256Hex(device_secret),
    label,
    role: normalizeDeviceRole(role),
    created_at: now,
    revoked: false,
  };
  await env.AUTH_CONFIG.put(KV_PREFIX + device_id, JSON.stringify(record));
  return { device_id, device_secret, record };
}

/** device レコードを KV から読む。不在 / JSON 破損は null。 */
export async function getDeviceRecord(
  env: DeviceKvEnv,
  deviceId: string,
): Promise<DeviceRecord | null> {
  const raw = await env.AUTH_CONFIG.get(KV_PREFIX + deviceId);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as DeviceRecord;
  } catch {
    return null;
  }
}

/** device を revoke する。存在して revoke できたら true、不在なら false。 */
export async function revokeDeviceCredential(
  env: DeviceKvEnv,
  deviceId: string,
): Promise<boolean> {
  const record = await getDeviceRecord(env, deviceId);
  if (!record) return false;
  record.revoked = true;
  await env.AUTH_CONFIG.put(KV_PREFIX + deviceId, JSON.stringify(record));
  return true;
}

/** 長さ一致前提の定数時間比較 (hash は固定長 hex なので長さ差は即 false で良い)。 */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * device_id + device_secret を検証し、有効なら DeviceRecord を返す。
 * 不在 / revoke 済み / secret 不一致はいずれも null (情報リークを避け区別しない)。
 */
export async function verifyDeviceCredential(
  env: DeviceKvEnv,
  deviceId: string,
  deviceSecret: string,
): Promise<DeviceRecord | null> {
  const record = await getDeviceRecord(env, deviceId);
  if (!record || record.revoked) return null;
  const hash = await sha256Hex(deviceSecret);
  if (!constantTimeEqual(hash, record.secret_hash)) return null;
  return record;
}

/** device JWT の claims。introspect が読む tenant_id / role / env / exp を持つ。 */
export interface DeviceJwtClaims {
  sub: string;
  tenant_id: string;
  role: string;
  env: string;
  iat: number;
  exp: number;
  [key: string]: unknown;
}

/**
 * device JWT を mint する (HS256 / JWT_SECRET)。`/auth/introspect` が
 * verifyJwt(JWT_SECRET, WORKER_ENV) + tenant_id + ACL で検証する。
 * `JWT_SECRET` 未設定なら throw (caller が 500 を返す前提)。
 */
export async function mintDeviceJwt(
  env: DeviceJwtEnv,
  record: DeviceRecord,
  now: number,
  ttlSeconds: number = DEVICE_JWT_TTL_SECONDS,
): Promise<string> {
  const secret = await resolveSecret(env.JWT_SECRET);
  if (!secret) {
    throw new Error("JWT_SECRET not configured");
  }
  const claims: DeviceJwtClaims = {
    sub: record.device_id,
    tenant_id: record.tenant_id,
    role: record.role ?? DEVICE_ROLE,
    env: env.WORKER_ENV,
    iat: now,
    exp: now + ttlSeconds,
  };
  return signHs256(claims, secret);
}

async function signHs256(payload: Record<string, unknown>, secret: string): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const headerSegment = base64UrlEncodeJson(header);
  const payloadSegment = base64UrlEncodeJson(payload);
  const signingInput = `${headerSegment}.${payloadSegment}`;
  const key = await crypto.subtle.importKey(
    "raw",
    TEXT_ENCODER.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, TEXT_ENCODER.encode(signingInput));
  return `${signingInput}.${base64UrlEncode(new Uint8Array(sig))}`;
}

function base64UrlEncodeJson(obj: unknown): string {
  return base64UrlEncode(TEXT_ENCODER.encode(JSON.stringify(obj)));
}

function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
