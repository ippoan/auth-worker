/**
 * 警告デバイス (VoiceS3R) の nonce 発行・消費と署名検証。
 *
 * `/auth/device-login` (#522、管理者 session を出す) と `/device/alarm-token`
 * (#551、短命の端末 JWT を出す) が同じ手順で VoiceS3R を確かめるので、ここに 1 本で置く。
 *
 * 契約 (device-login.ts 冒頭と同じ。変えるときは firmware / alc-app と合意する):
 *   - nonce = 小文字 hex 32 文字。署名対象は **その ASCII 32 バイト**
 *   - pubkey / sig は base64url の raw bytes (32 B / 64 B)。decode は `alarm-key.ts` の正本
 *
 * 血圧計のボンド状態込みの署名 (Refs #571、`ippoan/alc-app-s3#249` と合意済みの形。
 * 変える時は両側で揃えること):
 *   - `<nonce>|bp=1` ボンドされている / `<nonce>|bp=0` ボンドされていない /
 *     `<nonce>` だけ (古いファーム、ボンド状態は「不明」)。区切りは半角パイプ 1 文字、
 *     `bp=` の後は `1`/`0` のみ、空白なし。組み立ては `buildAlarmSignedMessage`。
 *
 * nonce の record は `purpose` を持つ。消費時は purpose の一致を要求し、purpose の
 * 無い record は拒否する (fail-closed)。ログイン用に発行した nonce への署名を端末 JWT に
 * (またはその逆に) 使い回させないため。
 *
 * 鍵の record も用途 (`usage`) を持つ。署名検証時は呼び出し側 (口) の用途との一致を
 * 要求し、usage の無い record は拒否する (nonce の purpose と同じ fail-closed)。
 */
import type { Env } from "../index";
import {
  decodeBase64Url,
  fingerprintFromRawPubkey,
  getAlarmKeyRecord,
  type AlarmKeyRecord,
  type AlarmKeyUsage,
} from "../handlers/alarm-key";
import { verifyEd25519 } from "./ed25519";

/**
 * nonce を何に使うか。`login` = device-login、`kiosk` / `tenko-manager` / `bp-station` =
 * alarm-token (同じ口だが用途ごとに purpose を分ける — 運行者端末の nonce への署名で
 * 運行管理者の JWT を取らせないため。Refs ippoan/alc-app#337)。
 */
export type AlarmNoncePurpose = "login" | "kiosk" | "tenko-manager" | "bp-station";

/** 受理する purpose の正本。 */
const ALARM_NONCE_PURPOSES: ReadonlyArray<AlarmNoncePurpose> = [
  "login",
  "kiosk",
  "tenko-manager",
  "bp-station",
];

/** nonce の TTL (秒)。両エンドポイントの `expires_in` と一致させる。 */
export const ALARM_NONCE_TTL_SEC = 60;

const NONCE_KV_PREFIX = "devnonce:";

export interface AlarmNonceRecord {
  purpose: AlarmNoncePurpose;
  /** device-login (purpose=login) の nonce だけが持つ。消費側で完全一致を見る。 */
  redirect_uri?: string;
  /** 失効時刻 (unix 秒)。KV の TTL に加えて消費時にも見る。 */
  exp: number;
}

/** 署名検証を通った鍵。 */
export interface VerifiedAlarmKey {
  fingerprint: string;
  record: AlarmKeyRecord;
}

/**
 * 署名対象の ASCII 文字列を組み立てる (Refs #571、`ippoan/alc-app-s3#249` と 1 文字も
 * 違わずに揃えた形):
 *   - `bpBonded` が `undefined` (古いファームは値を送らない) → `<nonce>` だけ
 *     (ボンド状態は「不明」として扱う。後方互換)
 *   - `true` → `<nonce>|bp=1` / `false` → `<nonce>|bp=0`
 */
export function buildAlarmSignedMessage(nonce: string, bpBonded?: boolean): string {
  if (bpBonded === undefined) return nonce;
  return `${nonce}|bp=${bpBonded ? "1" : "0"}`;
}

/** 小文字 hex 32 文字の nonce (16 random bytes)。 */
function generateNonceHex(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function isPurpose(value: unknown): value is AlarmNoncePurpose {
  return (
    typeof value === "string" && (ALARM_NONCE_PURPOSES as ReadonlyArray<string>).includes(value)
  );
}

function parseAlarmNonceRecord(raw: string | null): AlarmNonceRecord | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<AlarmNonceRecord>;
    if (!isPurpose(parsed.purpose) || typeof parsed.exp !== "number") return null;
    const record: AlarmNonceRecord = { purpose: parsed.purpose, exp: parsed.exp };
    if (typeof parsed.redirect_uri === "string") record.redirect_uri = parsed.redirect_uri;
    return record;
  } catch {
    return null;
  }
}

/** nonce を発行し、`devnonce:<nonce>` (TTL 60s) に purpose と一緒に積む。 */
export async function issueAlarmNonce(
  env: Env,
  opts: { purpose: AlarmNoncePurpose; redirectUri?: string },
): Promise<string> {
  const nonce = generateNonceHex();
  const now = Math.floor(Date.now() / 1000);
  const record: AlarmNonceRecord = { purpose: opts.purpose, exp: now + ALARM_NONCE_TTL_SEC };
  if (opts.redirectUri !== undefined) record.redirect_uri = opts.redirectUri;
  await env.AUTH_CONFIG.put(NONCE_KV_PREFIX + nonce, JSON.stringify(record), {
    expirationTtl: ALARM_NONCE_TTL_SEC,
  });
  return nonce;
}

/**
 * nonce を消費する (single-use — 読んだ時点で KV から消す)。record が無い・壊れている・
 * purpose が無い / 違う・期限切れのどれでも null。
 */
export async function consumeAlarmNonce(
  env: Env,
  nonce: string,
  purpose: AlarmNoncePurpose,
): Promise<AlarmNonceRecord | null> {
  const key = NONCE_KV_PREFIX + nonce;
  const record = parseAlarmNonceRecord(await env.AUTH_CONFIG.get(key));
  await env.AUTH_CONFIG.delete(key);
  if (!record || record.purpose !== purpose) return null;
  if (record.exp <= Math.floor(Date.now() / 1000)) return null;
  return record;
}

/**
 * nonce への署名を、登録済みの公開鍵 (`alarmkey:<fp>`) で検証する。pubkey / sig の
 * decode 失敗・長さ違い・未登録・失効・用途違い (usage の無い record を含む)・
 * 保管済み公開鍵の破損・署名不一致のどれでも null (呼び出し側は理由を区別せず固定の
 * 401 を返す)。
 */
export async function verifyAlarmSignature(
  env: Env,
  input: { pubkeyB64: string; sigB64: string; nonce: string; usage: AlarmKeyUsage; bpBonded?: boolean },
): Promise<VerifiedAlarmKey | null> {
  let pubkeyRaw: Uint8Array;
  let sig: Uint8Array;
  try {
    pubkeyRaw = decodeBase64Url(input.pubkeyB64);
    sig = decodeBase64Url(input.sigB64);
  } catch {
    return null;
  }
  if (pubkeyRaw.length !== 32 || sig.length !== 64) return null;

  const fingerprint = await fingerprintFromRawPubkey(pubkeyRaw);
  const record = await getAlarmKeyRecord(env, fingerprint);
  if (!record || record.revoked_at !== undefined) return null;
  // 用途は口ごとに 1 つ。usage の無い record (undefined) もここで落ちる。
  if (record.usage !== input.usage) return null;

  // 入力の pubkey は fingerprint を引く鍵にだけ使い、署名検証は必ず record 側の
  // pubkey (登録時の正本) で行う。
  let recordPubkeyRaw: Uint8Array;
  try {
    recordPubkeyRaw = decodeBase64Url(record.pubkey);
  } catch {
    return null;
  }

  // 署名対象は nonce (+ ボンド状態) の ASCII バイト (hex→raw にデコードした 16 バイトでは
  // ない)。bpBonded が undefined なら nonce だけ (古いファーム、今までどおり素通し)。
  const message = new TextEncoder().encode(buildAlarmSignedMessage(input.nonce, input.bpBonded));
  const ok = await verifyEd25519(recordPubkeyRaw, sig, message);
  return ok ? { fingerprint, record } : null;
}
