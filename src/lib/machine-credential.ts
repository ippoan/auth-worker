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
 * ★ **資格情報は DB の表 `alc_api.machine_credentials` (tenants へ FK + ON DELETE CASCADE) に在り、
 * 読み書きは alc-auth-worker (Service Binding `ALC_AUTH`) の内部口だけで行う** — 会社が消えれば資格情報も消える。
 * 環境の分離は binding の行き先 (prod / staging で別の worker・別の DB) で決まる。
 * username / password の生成と password の sha256 hex はここ (TS 側) で行い、alc-auth-worker には hash だけ送る。
 *
 * ★ **fail-closed**: `ALC_AUTH` か `INTERNAL_SHARED_SECRET` が無い・`MACHINE_CRED_ENV` が無い/不正・
 * 応答が 2xx と 404 以外・JSON が壊れている・通信が失敗した → 全関数が失敗側の値 (null / false / 空配列) を返す
 * (throw しない)。404 は本文に関係なく「無い」として扱う。
 *
 * alc-auth-worker の内部口 (全部 `X-Internal-Shared-Secret` が要る。不一致は 404):
 *   - `POST /internal/machine-credentials` {username, tenant_id, purpose, label, secret_hash} → 201
 *   - `GET  /internal/machine-credentials?tenant_id=<uuid>[&purpose=<p>]` → 200 {credentials: [...]}
 *   - `POST /internal/machine-credentials/<username>/revoke` {tenant_id} → 200 {revoked: true} / 404
 *   - `GET  /internal/machine-credentials/<username>` → 200 {tenant_id, purpose, secret_hash, revoked} / 404
 */
import { constantTimeEqual, sha256Hex } from "./device";
import { fetchAlcAuth, type AlcAuthEnv } from "./alc-auth-fetch";
import { parseBasicAuth } from "./errors";

/** 資格情報の用途の allowlist (ここ 1 か所に定義する)。用途を足すときはここに足す。 */
export const MACHINE_CRED_PURPOSES = ["leave-scan"] as const;
export type MachineCredPurpose = (typeof MACHINE_CRED_PURPOSES)[number];

/** label の最大長 (管理画面の表示用の名前)。 */
export const MACHINE_CRED_LABEL_MAX = 64;

/** alc-auth-worker の機械用資格情報の内部口の path。 */
const CREDENTIALS_PATH = "/internal/machine-credentials";

/**
 * 複合機のパスワード欄が短い (Canon iR-ADV で 24 文字程度) ため、パスワードは 24 文字にする。
 * 18 byte = 144 bit。
 */
const MACHINE_CRED_PASSWORD_BYTES = 18;
/** username = `mc_` + 16 hex。照合の前にこの形でなければ alc-auth-worker を引かない。 */
const USERNAME_RE = /^mc_[0-9a-f]{16}$/;
/** 環境名の形 (チケットの HKDF の info と payload の `env` に使う)。 */
const ENV_RE = /^[a-z0-9-]+$/;

/** `ALC_AUTH` か `INTERNAL_SHARED_SECRET` が無ければ全関数が失敗側の値を返す。 */
export interface MachineCredEnv extends AlcAuthEnv {
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

/** `MACHINE_CRED_ENV` を使える形で返す。未設定・不正は null (= 呼び手は失敗側へ倒す)。 */
export function machineCredEnvName(env: { MACHINE_CRED_ENV?: string }): string | null {
  const v = env.MACHINE_CRED_ENV;
  return typeof v === "string" && ENV_RE.test(v) ? v : null;
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

type AlcAuthResult = { status: 404 } | { status: 200; body: Record<string, unknown> };

/**
 * alc-auth-worker の内部口を 1 回叩く。2xx は JSON object の本文と共に `status: 200`、404 は本文を見ずに
 * `status: 404`、それ以外 (binding / secret / 環境名が無い・通信失敗・他の status・壊れた JSON) は null。
 */
async function callAlcAuth(
  env: MachineCredEnv,
  path: string,
  init: { method: "GET" | "POST"; body?: Record<string, unknown> } = { method: "GET" },
): Promise<AlcAuthResult | null> {
  if (!machineCredEnvName(env)) return null;
  let res: Response | null;
  try {
    res = await fetchAlcAuth(env, `${CREDENTIALS_PATH}${path}`, {
      method: init.method,
      body: init.body ? JSON.stringify(init.body) : undefined,
    });
  } catch {
    return null;
  }
  if (!res) return null;
  if (res.status === 404) return { status: 404 };
  if (res.status < 200 || res.status > 299) return null;
  try {
    const body = (await res.json()) as unknown;
    return body && typeof body === "object" && !Array.isArray(body)
      ? { status: 200, body: body as Record<string, unknown> }
      : null;
  } catch {
    return null;
  }
}

type LookupRecord = { tenant_id: string; purpose: string; secret_hash: string; revoked: boolean };

/** 口 4 の引き直しの結果。`unavailable` は「無い」ではなく「確かめられなかった」(再試行すれば変わりうる)。 */
type LookupResult =
  | { status: "found"; record: LookupRecord }
  | { status: "absent" }
  | { status: "unavailable" };

/**
 * 口 4 (`GET /internal/machine-credentials/<username>`) で 1 件引く。
 * 形の不正な username・404 は `absent`。binding / secret / 環境名が無い・通信失敗・2xx/404 以外・
 * 壊れた JSON・形の合わない本文は `unavailable`。
 */
async function lookupDetailed(env: MachineCredEnv, username: string): Promise<LookupResult> {
  if (typeof username !== "string" || !USERNAME_RE.test(username)) return { status: "absent" };
  const r = await callAlcAuth(env, `/${username}`);
  if (!r) return { status: "unavailable" };
  if (r.status === 404) return { status: "absent" };
  const { tenant_id, purpose, secret_hash, revoked } = r.body;
  if (
    typeof tenant_id !== "string" ||
    typeof purpose !== "string" ||
    typeof secret_hash !== "string" ||
    typeof revoked !== "boolean"
  ) {
    return { status: "unavailable" };
  }
  return { status: "found", record: { tenant_id, purpose, secret_hash, revoked } };
}

/** 不在・形の不正・失敗は null (区別しない)。`verifyBasic` 用 (失敗側に倒す)。 */
async function lookup(env: MachineCredEnv, username: string): Promise<LookupRecord | null> {
  const r = await lookupDetailed(env, username);
  return r.status === "found" ? r.record : null;
}

/**
 * `checkActiveMachineCredential` の結果。`inactive` は不在・失効 (確定した「無効」)、
 * `unavailable` は alc-auth-worker に確かめられなかった (一時的な失敗。再試行できる)。
 */
export type ActiveMachineCredentialResult =
  | { status: "active"; credential: MachineCredentialRecord }
  | { status: "inactive" }
  | { status: "unavailable" };

/**
 * 今も有効な (失効していない) 資格情報を引き、「有効 / 無効 / 確かめられなかった」を区別して返す。
 * チケットの検証 (`lib/machine-ticket.ts`) は、一時的な失敗を無効と取り違えて捨てないためにこちらを使う。
 * ★ 口 4 は label / created_at を返さず、hash もここでは使わないので、その 3 つは空文字で返す。
 */
export async function checkActiveMachineCredential(
  env: MachineCredEnv,
  username: string,
): Promise<ActiveMachineCredentialResult> {
  const r = await lookupDetailed(env, username);
  if (r.status === "unavailable") return { status: "unavailable" };
  if (r.status === "absent" || r.record.revoked) return { status: "inactive" };
  return {
    status: "active",
    credential: {
      username,
      tenant_id: r.record.tenant_id,
      purpose: r.record.purpose as MachineCredPurpose,
      label: "",
      secret_hash: "",
      created_at: "",
      revoked: false,
    },
  };
}

/**
 * 今も有効な (失効していない) 資格情報を返す。不在・失効・失敗は null (区別しない。区別が要るなら
 * `checkActiveMachineCredential`)。
 */
export async function getActiveMachineCredential(
  env: MachineCredEnv,
  username: string,
): Promise<MachineCredentialRecord | null> {
  const r = await checkActiveMachineCredential(env, username);
  return r.status === "active" ? r.credential : null;
}

/**
 * 新しい資格情報を発行する。返す password は平文で、**この戻り値の 1 回だけ**取れる
 * (alc-auth-worker には hash だけ送る)。
 * 環境名が無い・tenant が空・用途が allowlist に無い・label が空か長すぎる・会社が無い・
 * username の重複・alc-auth-worker に届かない → null。
 */
export async function createMachineCredential(
  env: MachineCredEnv,
  tenantId: string,
  purpose: string,
  label: string,
): Promise<{ username: string; password: string } | null> {
  if (typeof tenantId !== "string" || !tenantId) return null;
  if (!isMachineCredPurpose(purpose)) return null;
  const trimmed = typeof label === "string" ? label.trim() : "";
  if (!trimmed || trimmed.length > MACHINE_CRED_LABEL_MAX) return null;

  const username = `mc_${randomHex(8)}`;
  const password = randomBase64Url(MACHINE_CRED_PASSWORD_BYTES);
  const r = await callAlcAuth(env, "", {
    method: "POST",
    body: {
      username,
      tenant_id: tenantId,
      purpose,
      label: trimmed,
      secret_hash: await sha256Hex(password),
    },
  });
  return r?.status === 200 ? { username, password } : null;
}

/**
 * tenant の資格情報の一覧 (失効済みも `revoked: true` で含める)。`purpose` を渡すとその用途だけ。
 * 環境名が無い・tenant が空・alc-auth-worker に届かない → 空配列。形の合わない行は出さない。
 */
export async function listMachineCredentials(
  env: MachineCredEnv,
  tenantId: string,
  purpose?: string,
): Promise<MachineCredentialSummary[]> {
  if (typeof tenantId !== "string" || !tenantId) return [];
  const q = new URLSearchParams({ tenant_id: tenantId });
  if (purpose !== undefined) q.set("purpose", purpose);
  const r = await callAlcAuth(env, `?${q.toString()}`);
  if (r?.status !== 200 || !Array.isArray(r.body.credentials)) return [];
  const out: MachineCredentialSummary[] = [];
  for (const item of r.body.credentials as unknown[]) {
    if (!item || typeof item !== "object") continue;
    const c = item as Record<string, unknown>;
    if (
      typeof c.username !== "string" ||
      !isMachineCredPurpose(c.purpose) ||
      typeof c.label !== "string" ||
      typeof c.created_at !== "string" ||
      typeof c.revoked !== "boolean"
    ) {
      continue;
    }
    if (purpose !== undefined && c.purpose !== purpose) continue;
    out.push({
      username: c.username,
      purpose: c.purpose,
      label: c.label,
      created_at: c.created_at,
      revoked: c.revoked,
    });
  }
  return out;
}

/**
 * 資格情報を失効させる。**他 tenant のもの・存在しないものは false** (区別しない。alc-auth-worker が 404)。
 * 既に失効済みなら true (冪等)。失効後は `verifyBasic` もチケットの検証も通らない。
 */
export async function revokeMachineCredential(
  env: MachineCredEnv,
  tenantId: string,
  username: string,
): Promise<boolean> {
  if (typeof tenantId !== "string" || !tenantId) return false;
  if (typeof username !== "string" || !USERNAME_RE.test(username)) return false;
  const r = await callAlcAuth(env, `/${username}/revoke`, {
    method: "POST",
    body: { tenant_id: tenantId },
  });
  return r?.status === 200 && r.body.revoked === true;
}

/**
 * `Authorization: Basic ...` を照合する。通れば tenant と username を返す。
 * 不在 / 失効 / 用途の不一致 / password の不一致 / ヘッダの形の不正 / alc-auth-worker に届かないは
 * **区別せず** null。
 */
export async function verifyBasic(
  env: MachineCredEnv,
  authorization: string,
  purpose: string,
): Promise<{ tenantId: string; username: string } | null> {
  if (!machineCredEnvName(env) || !isMachineCredPurpose(purpose)) return null;
  const basic = parseBasicAuth(authorization);
  if (!basic) return null;
  // 不在でも hash は計算する (不在と不一致で処理量を変えない)。
  const hash = await sha256Hex(basic.password);
  const record = await lookup(env, basic.username);
  if (!record || record.revoked || record.purpose !== purpose) return null;
  if (!constantTimeEqual(hash, record.secret_hash)) return null;
  return { tenantId: record.tenant_id, username: basic.username };
}
