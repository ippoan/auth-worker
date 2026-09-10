/**
 * 警告デバイス (VoiceS3R, ippoan/alc-app-s3#205) の公開鍵登録・一覧・失効
 * (ippoan/auth-worker#521)。
 *
 * VoiceS3R は ed25519 の鍵対を機体内で作り、**公開鍵だけ**を USB 経由でここに
 * 登録する (秘密鍵は機体から一切出ない)。登録された公開鍵は「管理者が
 * VoiceS3R を USB で繋いでいる」ことを示す 2 要素目の認証に使う — ログイン
 * (nonce 署名 / device-login) は次の issue (この record の形を渡す)。
 *
 *   POST /device/setup/alarm-key         — {pubkey, label} → 登録
 *   GET  /device/setup/alarm-keys        — operator の tenant の一覧
 *   POST /device/setup/alarm-key/revoke  — {fingerprint} → 失効 (削除しない)
 *
 * KV (AUTH_CONFIG):
 *   `alarmkey:<fingerprint>`   → AlarmKeyRecord
 *   `alarmkeys:<tenant_id>`    → fingerprint の配列 (JSON)。一覧を KV の
 *                                prefix 走査にしないためのテナント索引
 *
 * fingerprint = 公開鍵 (raw 32 B) の SHA-256 の先頭 16 hex (小文字)。
 *
 * **object 認可**: 3 本すべてで「record の tenant_id = session の tenant」を
 * 検査する (`deviceCommandRequest` の `managedDeviceKind` のような共通 3 段目
 * helper が無いため、ここでは handler 内に明示する)。
 */

import type { Env } from "../index";
import { adminRequest } from "./device-setup";

function jsonNoStore(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

/** KV に保管する警告デバイス公開鍵レコード。 */
export interface AlarmKeyRecord {
  /** base64url エンコードした ed25519 公開鍵 (raw 32 B)。 */
  pubkey: string;
  tenant_id: string;
  label: string;
  created_at: number;
  /** 失効時刻 (unix 秒)。未設定 = 有効。 */
  revoked_at?: number;
}

const RECORD_PREFIX = "alarmkey:";
const TENANT_INDEX_PREFIX = "alarmkeys:";

function recordKey(fingerprint: string): string {
  return RECORD_PREFIX + fingerprint;
}

function tenantIndexKey(tenantId: string): string {
  return TENANT_INDEX_PREFIX + tenantId;
}

/** base64url (パディング無し可) → raw bytes。不正な文字列は例外を投げる。 */
function decodeBase64Url(b64url: string): Uint8Array {
  const padded = b64url.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(b64url.length / 4) * 4, "=");
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256HexBytes(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** 公開鍵の base64url 文字列を検証し、fingerprint (先頭 16 hex) を返す。不正なら null。 */
async function validatePubkeyAndFingerprint(pubkey: unknown): Promise<string | null> {
  if (typeof pubkey !== "string" || !pubkey) return null;
  let raw: Uint8Array;
  try {
    raw = decodeBase64Url(pubkey);
  } catch {
    return null;
  }
  if (raw.length !== 32) return null;
  const hex = await sha256HexBytes(raw);
  return hex.slice(0, 16);
}

function isValidLabel(label: unknown): label is string {
  return typeof label === "string" && label.length >= 1 && label.length <= 64;
}

async function readJsonBody(request: Request): Promise<Record<string, unknown>> {
  try {
    const v = await request.json();
    if (v && typeof v === "object") return v as Record<string, unknown>;
  } catch {
    // 空 body は各 handler の検証で弾く
  }
  return {};
}

async function getAlarmKeyRecord(env: Env, fingerprint: string): Promise<AlarmKeyRecord | null> {
  const raw = await env.AUTH_CONFIG.get(recordKey(fingerprint));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as AlarmKeyRecord;
  } catch {
    return null;
  }
}

async function readTenantIndex(env: Env, tenantId: string): Promise<string[]> {
  const raw = await env.AUTH_CONFIG.get(tenantIndexKey(tenantId));
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as string[]) : [];
  } catch {
    return [];
  }
}

/**
 * POST /device/setup/alarm-key — {pubkey, label} を検証し、operator の
 * session tenant で record を作って登録する。
 */
export async function handleAlarmKeyRegister(request: Request, env: Env): Promise<Response> {
  const pre = await adminRequest(request, env);
  if (pre instanceof Response) return pre;

  const body = await readJsonBody(request);
  const fingerprint = await validatePubkeyAndFingerprint(body.pubkey);
  if (!fingerprint) {
    return jsonNoStore({ error: "invalid pubkey (base64url of 32 raw bytes required)" }, 400);
  }
  if (!isValidLabel(body.label)) {
    return jsonNoStore({ error: "label は 1〜64 文字で必要です" }, 400);
  }
  const label = body.label as string;

  const existing = await getAlarmKeyRecord(env, fingerprint);
  if (existing) {
    return jsonNoStore({ error: "already registered" }, 409);
  }

  const now = Math.floor(Date.now() / 1000);
  const record: AlarmKeyRecord = {
    pubkey: body.pubkey as string,
    tenant_id: pre.session.tenantId,
    label,
    created_at: now,
  };
  await env.AUTH_CONFIG.put(recordKey(fingerprint), JSON.stringify(record));

  // read-modify-write (KV に原子性は無い)。同時登録が index への追記を
  // 取りこぼす可能性はあるが、record 自体は fingerprint key に確実に書けており、
  // 実害は「一覧に一瞬出遅れる」程度に留まるため許容する。
  const index = await readTenantIndex(env, pre.session.tenantId);
  if (!index.includes(fingerprint)) {
    index.push(fingerprint);
    await env.AUTH_CONFIG.put(tenantIndexKey(pre.session.tenantId), JSON.stringify(index));
  }

  return jsonNoStore({ fingerprint });
}

/** GET /device/setup/alarm-keys — operator の tenant に登録済みの警告デバイス鍵一覧。 */
export async function handleAlarmKeyList(request: Request, env: Env): Promise<Response> {
  const pre = await adminRequest(request, env);
  if (pre instanceof Response) return pre;

  const fingerprints = await readTenantIndex(env, pre.session.tenantId);
  const keys: Array<{ fingerprint: string; label: string; created_at: number; revoked_at?: number }> =
    [];
  for (const fingerprint of fingerprints) {
    const record = await getAlarmKeyRecord(env, fingerprint);
    // 他 tenant の鍵は索引が指していても混入させない (二重の tenant 検査)。
    if (!record || record.tenant_id !== pre.session.tenantId) continue;
    keys.push({
      fingerprint,
      label: record.label,
      created_at: record.created_at,
      ...(record.revoked_at !== undefined ? { revoked_at: record.revoked_at } : {}),
    });
  }
  return jsonNoStore({ keys });
}

/**
 * POST /device/setup/alarm-key/revoke — {fingerprint} を失効させる (削除しない)。
 * record が無い場合と他 tenant の record の場合は同じ応答 (存在を漏らさない)。
 */
export async function handleAlarmKeyRevoke(request: Request, env: Env): Promise<Response> {
  const pre = await adminRequest(request, env);
  if (pre instanceof Response) return pre;

  const body = await readJsonBody(request);
  const fingerprint = typeof body.fingerprint === "string" ? body.fingerprint : "";
  if (!fingerprint) return jsonNoStore({ error: "fingerprint が必要です" }, 400);

  const record = await getAlarmKeyRecord(env, fingerprint);
  // 存在しない場合と、存在するが他 tenant の場合を同じ応答文言・status にする
  // (record の有無や所有 tenant を漏らさないため)。
  if (!record || record.tenant_id !== pre.session.tenantId) {
    return jsonNoStore({ error: "not_found" }, 403);
  }

  if (record.revoked_at === undefined) {
    record.revoked_at = Math.floor(Date.now() / 1000);
    await env.AUTH_CONFIG.put(recordKey(fingerprint), JSON.stringify(record));
  }

  return jsonNoStore({ fingerprint, revoked_at: record.revoked_at });
}
