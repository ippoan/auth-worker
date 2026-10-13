/**
 * 機械用の資格情報 (machine credential) — 複合機・PC のように「人のログインができない送り手」が
 * HTTP Basic で名乗るための username / password (Refs ohishi-exp/rust-leave-worker#1)。
 *
 * 最初の用途は休暇申請書の PDF の受け取り (`purpose = "leave-scan"`)。複合機は WebDAV の PUT に
 * Basic しか付けられないので、受け口 (nuxt-leave) は Basic をそのまま auth-worker の RPC
 * (`MachineCredentialEntrypoint.issueTicket`) に渡し、**会社 (tenant) を決めるのは auth-worker だけ**にする。
 *
 * ★ **device credential (`device:` prefix、`lib/device.ts`) とは置き場を分けている**:
 *   - device record に role を足すと `/device/token` で device JWT が mint できてしまう
 *   - device 一覧 (`device:` の全走査) に混ざる
 * ここの資格情報は JWT を一切出さない。出すのは用途を固定したチケット (`lib/machine-ticket.ts`) だけ。
 *
 * ★ **`AUTH_CONFIG` は prod と staging で同じ namespace** なので、key に環境名 (`MACHINE_CRED_ENV`) を入れて
 * 分ける。staging で発行した資格情報は prod では照合できない。`MACHINE_CRED_ENV` が無い・不正なら
 * 全関数が失敗側の値 (null / false / 空配列) を返す (throw しない)。
 *
 * KV:
 *   - `mcred:<env>:<username>` → `MachineCredentialRecord` (JSON)。password は sha256 hex だけ
 *   - `mcred-tenant:<env>:<tenant_id>:<username>` → `"1"` (tenant ごとの一覧の索引)
 */
import { constantTimeEqual, sha256Hex } from "./device";
import { parseBasicAuth } from "./errors";

/** 資格情報の用途の allowlist (ここ 1 か所に定義する)。用途を足すときはここに足す。 */
export const MACHINE_CRED_PURPOSES = ["leave-scan"] as const;
export type MachineCredPurpose = (typeof MACHINE_CRED_PURPOSES)[number];

/** label の最大長 (管理画面の表示用の名前)。 */
export const MACHINE_CRED_LABEL_MAX = 64;

const KV_PREFIX = "mcred:";
const TENANT_INDEX_PREFIX = "mcred-tenant:";
/** username = `mc_` + 16 hex。照合の前にこの形でなければ KV を引かない。 */
const USERNAME_RE = /^mc_[0-9a-f]{16}$/;
/** key に埋めるので `:` などを含む値は受けない。 */
const ENV_RE = /^[a-z0-9-]+$/;

export interface MachineCredEnv {
  AUTH_CONFIG: KVNamespace;
  /** 環境名 (top-level `"prod"` / `[env.staging.vars]` `"staging"`)。 */
  MACHINE_CRED_ENV?: string;
}

export interface MachineCredentialRecord {
  username: string;
  tenant_id: string;
  purpose: MachineCredPurpose;
  label: string;
  /** password の sha256 hex。平文は保存しない。 */
  secret_hash: string;
  /** ISO 8601 */
  created_at: string;
  revoked: boolean;
}

/** 一覧で返す形 (password も hash も返さない)。 */
export interface MachineCredentialSummary {
  username: string;
  purpose: MachineCredPurpose;
  label: string;
  created_at: string;
  revoked: boolean;
}

export function isMachineCredPurpose(value: unknown): value is MachineCredPurpose {
  return (MACHINE_CRED_PURPOSES as readonly unknown[]).includes(value);
}

/** `MACHINE_CRED_ENV` を key に使える形で返す。未設定・不正は null (= 呼び手は失敗側へ倒す)。 */
export function machineCredEnvName(env: { MACHINE_CRED_ENV?: string }): string | null {
  const v = env.MACHINE_CRED_ENV;
  return typeof v === "string" && ENV_RE.test(v) ? v : null;
}

function recordKey(envName: string, username: string): string {
  return `${KV_PREFIX}${envName}:${username}`;
}

function tenantIndexPrefix(envName: string, tenantId: string): string {
  return `${TENANT_INDEX_PREFIX}${envName}:${tenantId}:`;
}

function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

function randomBase64Url(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  let s = "";
  for (const b of buf) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function getRecord(
  env: MachineCredEnv,
  envName: string,
  username: string,
): Promise<MachineCredentialRecord | null> {
  if (!USERNAME_RE.test(username)) return null;
  const raw = await env.AUTH_CONFIG.get(recordKey(envName, username));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as MachineCredentialRecord;
  } catch {
    return null;
  }
}

/**
 * 今も有効な (失効していない) 資格情報を返す。チケットの検証 (`lib/machine-ticket.ts`) が
 * 「発行後に失効させた資格情報のチケットを通さない」ために引く。
 */
export async function getActiveMachineCredential(
  env: MachineCredEnv,
  username: string,
): Promise<MachineCredentialRecord | null> {
  const envName = machineCredEnvName(env);
  if (!envName) return null;
  const record = await getRecord(env, envName, username);
  return record && !record.revoked ? record : null;
}

/**
 * 新しい資格情報を発行する。返す password は平文で、**この戻り値の 1 回だけ**取れる (KV には hash だけ)。
 * 環境名が無い・tenant が空・用途が allowlist に無い・label が空か長すぎる → null。
 */
export async function createMachineCredential(
  env: MachineCredEnv,
  tenantId: string,
  purpose: string,
  label: string,
): Promise<{ username: string; password: string } | null> {
  const envName = machineCredEnvName(env);
  if (!envName) return null;
  if (typeof tenantId !== "string" || !tenantId || tenantId.includes(":")) return null;
  if (!isMachineCredPurpose(purpose)) return null;
  const trimmed = typeof label === "string" ? label.trim() : "";
  if (!trimmed || trimmed.length > MACHINE_CRED_LABEL_MAX) return null;

  const username = `mc_${randomHex(8)}`;
  const password = randomBase64Url(32);
  const record: MachineCredentialRecord = {
    username,
    tenant_id: tenantId,
    purpose,
    label: trimmed,
    secret_hash: await sha256Hex(password),
    created_at: new Date().toISOString(),
    revoked: false,
  };
  await env.AUTH_CONFIG.put(recordKey(envName, username), JSON.stringify(record));
  await env.AUTH_CONFIG.put(tenantIndexPrefix(envName, tenantId) + username, "1");
  return { username, password };
}

/**
 * tenant の資格情報の一覧 (失効済みも `revoked: true` で含める)。`purpose` を渡すとその用途だけ。
 * 環境名が無い・tenant が空 → 空配列。
 */
export async function listMachineCredentials(
  env: MachineCredEnv,
  tenantId: string,
  purpose?: string,
): Promise<MachineCredentialSummary[]> {
  const envName = machineCredEnvName(env);
  if (!envName || !tenantId || tenantId.includes(":")) return [];
  const prefix = tenantIndexPrefix(envName, tenantId);
  const out: MachineCredentialSummary[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.AUTH_CONFIG.list({ prefix, cursor });
    for (const { name } of page.keys) {
      const record = await getRecord(env, envName, name.slice(prefix.length));
      // 索引と本体の tenant が食い違うものは出さない (索引だけを信じない)。
      if (!record || record.tenant_id !== tenantId) continue;
      if (purpose !== undefined && record.purpose !== purpose) continue;
      out.push({
        username: record.username,
        purpose: record.purpose,
        label: record.label,
        created_at: record.created_at,
        revoked: record.revoked,
      });
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return out;
}

/**
 * 資格情報を失効させる。**他 tenant のもの・存在しないものは false** (区別しない)。
 * 既に失効済みなら true (冪等)。失効後は `verifyBasic` もチケットの検証も通らない。
 */
export async function revokeMachineCredential(
  env: MachineCredEnv,
  tenantId: string,
  username: string,
): Promise<boolean> {
  const envName = machineCredEnvName(env);
  if (!envName) return false;
  const record = await getRecord(env, envName, username);
  if (!record || record.tenant_id !== tenantId) return false;
  if (!record.revoked) {
    record.revoked = true;
    await env.AUTH_CONFIG.put(recordKey(envName, username), JSON.stringify(record));
  }
  return true;
}

/**
 * `Authorization: Basic ...` を照合する。通れば tenant と username を返す。
 * 不在 / 失効 / 用途の不一致 / password の不一致 / ヘッダの形の不正は**区別せず** null。
 */
export async function verifyBasic(
  env: MachineCredEnv,
  authorization: string,
  purpose: string,
): Promise<{ tenantId: string; username: string } | null> {
  const envName = machineCredEnvName(env);
  if (!envName || !isMachineCredPurpose(purpose)) return null;
  const basic = parseBasicAuth(authorization);
  if (!basic) return null;
  // 不在でも hash は計算する (不在と不一致で処理量を変えない)。
  const hash = await sha256Hex(basic.password);
  const record = await getRecord(env, envName, basic.username);
  if (!record || record.revoked || record.purpose !== purpose) return null;
  if (!constantTimeEqual(hash, record.secret_hash)) return null;
  return { tenantId: record.tenant_id, username: record.username };
}
