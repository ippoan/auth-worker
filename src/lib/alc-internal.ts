/**
 * rust-alc-api の `/api/internal/auth/*` を叩く internal client (rust-alc-api#434 Phase 2)。
 *
 * 認証 DB 操作 (sso-config 読み / user upsert / refresh-token 保存) は rust が DB owner の
 * まま保持し、auth-worker は `signInternalJWT` (`aud=alc-api-internal`) を付けて internal
 * endpoint 越しに叩く。rust 側は `require_internal_jwt` で検証する。
 *
 * lockdown (`allUsers` 削除) 後は Cloud Run IAM が OIDC を要求するため、`INTERNAL_AUTH_OIDC=1`
 * で `internalAuthToken` が `mintGoogleIdToken(aud=alc-api-internal)` に切替わる (Refs #434)。
 * 移行前 (flag 未設定 or SA key 無し) は従来の HS256 internal-JWT で到達する (非破壊)。
 */
import type { Env } from "../index";
import { signInternalJWT } from "./internal-jwt";
import { resolveSecret, type SecretBinding } from "./secret";
import { mintGoogleIdToken } from "./oidc";

/** rust の `aud=alc-api-internal` (alc-auth-jwt の INTERNAL_AUD と同値)。 */
const INTERNAL_AUD = "alc-api-internal";

/**
 * `internalAuthToken` が必要とする最小 env。worker 本体の `Env` に加えて、
 * Durable Object の narrow な env interface (lineworks-webhook-do の `DOEnv` 等)
 * からも構造的に満たせるようにしておく (Refs ippoan/rust-alc-api#479 — HS256
 * dual-accept 撤去の前提として、全 internal 呼び出し元をこの helper に集約する)。
 */
export interface InternalAuthEnv {
  /** lockdown cutover flag (wrangler.toml vars)。"1" で OIDC mint を試す。 */
  INTERNAL_AUTH_OIDC?: string;
  ALC_API_PROXY_SA_KEY?: SecretBinding;
  JWT_SECRET: SecretBinding;
  WORKER_ENV: string;
}

/**
 * internal-auth 呼び出しの Authorization token を返す。
 *
 * - lockdown cutover 後 (`INTERNAL_AUTH_OIDC=1` + `ALC_API_PROXY_SA_KEY` 設定): Google OIDC
 *   (aud=alc-api-internal) を mint。Cloud Run IAM (`--add-custom-audiences=alc-api-internal`) が
 *   検証し、rust 側は dual-accept で aud を確認する。
 * - それ以外 (移行前): 従来の HS256 internal JWT (`signInternalJWT`)。
 */
export async function internalAuthToken(env: InternalAuthEnv): Promise<string> {
  if (env.INTERNAL_AUTH_OIDC === "1") {
    const saKey = await resolveSecret(env.ALC_API_PROXY_SA_KEY);
    if (saKey) return mintGoogleIdToken(saKey, INTERNAL_AUD);
  }
  return signInternalJWT(env);
}

/** `/api/internal/auth/sso-config` のレスポンス。 */
export interface SsoConfig {
  tenant_id: string;
  client_id: string;
  client_secret_encrypted: string;
  external_org_id: string;
  woff_id: string | null;
}

/** `/api/internal/auth/users/*` のレスポンス (user + tenant slug、token は含まない)。 */
export interface InternalUserWithSlug {
  id: string;
  tenant_id: string;
  email: string;
  name: string;
  role: string;
  google_sub: string | null;
  lineworks_id: string | null;
  line_user_id: string | null;
  slug: string | null;
}

async function internalFetch(env: Env, path: string, init?: RequestInit): Promise<Response> {
  const token = await internalAuthToken(env);
  const headers = new Headers(init?.headers);
  headers.set("Authorization", `Bearer ${token}`);
  if (init?.body !== undefined) headers.set("Content-Type", "application/json");
  return fetch(`${env.ALC_API_ORIGIN}${path}`, { ...init, headers });
}

/** SSO 設定を解決する。未登録は null。 */
export async function resolveSsoConfig(
  env: Env,
  provider: string,
  domain: string,
): Promise<SsoConfig | null> {
  const qs = `provider=${encodeURIComponent(provider)}&domain=${encodeURIComponent(domain)}`;
  const res = await internalFetch(env, `/api/internal/auth/sso-config?${qs}`);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`internal sso-config failed: ${res.status}`);
  return (await res.json()) as SsoConfig;
}

/** `resolveActiveDeviceTenant` の解決結果。 */
export type ResolveDeviceTenantResult =
  | { ok: true; tenantId: string }
  | { ok: false; reason: "not_found" | "unavailable" };

/**
 * device_id から、rust-alc-api に登録済みで有効な端末の tenant を解決する
 * (Refs #544)。`/device/pair-internal` が body の tenant_id を信用せず、この
 * 結果だけを発行 tenant として使うための lookup。
 *
 * 200 かつ JSON の `tenant_id` が空でない string の時だけ `ok`。404 は
 * `not_found`。それ以外 (401・5xx・JSON 不正・tenant_id 欠落・fetch の例外) は
 * すべて `unavailable` — 呼び出し元は fail-closed (発行しない) で扱う。
 */
export async function resolveActiveDeviceTenant(
  env: Env,
  deviceId: string,
): Promise<ResolveDeviceTenantResult> {
  let res: Response;
  try {
    res = await internalFetch(
      env,
      `/api/internal/devices/${encodeURIComponent(deviceId)}/pairing-tenant`,
    );
  } catch {
    return { ok: false, reason: "unavailable" };
  }
  if (res.status === 404) return { ok: false, reason: "not_found" };
  if (res.status !== 200) return { ok: false, reason: "unavailable" };

  let body: unknown;
  try {
    body = await res.json();
  } catch {
    return { ok: false, reason: "unavailable" };
  }
  const tenantId =
    body && typeof body === "object" && typeof (body as Record<string, unknown>).tenant_id === "string"
      ? ((body as Record<string, unknown>).tenant_id as string)
      : "";
  if (!tenantId) return { ok: false, reason: "unavailable" };
  return { ok: true, tenantId };
}

/** `GET /api/internal/rls-check` の応答のうち、auth-worker が外へ出す部分 (Refs #605)。 */
export interface RlsCheckResult {
  ok: boolean;
  migrations: {
    applied: number;
    max_version: number;
    binary_count: number;
    binary_max_version: number;
    matches_binary: boolean;
  };
  runtime_role: {
    current_user: string;
    is_runtime_role: boolean;
    rolsuper: boolean;
    rolbypassrls: boolean;
    rolinherit: boolean;
    member_of_table_owner: boolean;
  };
  connections: Array<{ usename: string; count: number }>;
  owner_role_connected: boolean;
  invariants: {
    violation_count: number;
    /** 検査ごとの題と違反の件数。違反が無くても毎回返る。 */
    checks: Array<{ check_no: number; title: string; violations: number }>;
    violations: Array<{ check_no: number; object: string; detail: string }>;
  };
  /** 観測したカタログの値 (表示用)。backend が取れなかった時・object でない時・
   *  大きすぎる時は null。中身は検査せずそのまま返す。 */
  state: Record<string, unknown> | null;
  /** backend の合否の内訳。`verdicts` を返さない backend (古い版) では null。 */
  verdicts: RlsBackendVerdicts | null;
  /** 履歴との食い違い (食い違った表・関数・view を期待と実物で並べたもの)。扱いは `state` と
   *  同じ — 無い時・object でない時・大きすぎる時は null。中身は検査せずそのまま返す。 */
  drift: Record<string, unknown> | null;
}

/** backend が返す合否の内訳。backend の `ok` はこの 4 つが全部 true のとき true。 */
export interface RlsBackendVerdicts {
  invariants: boolean;
  runtime_role: boolean;
  migrations: boolean;
  drift: boolean;
}

/** `state` / `drift` を JSON にした長さの上限 (`state` の想定は約 20KB)。超えたら null。 */
export const RLS_STATE_MAX_LENGTH = 262144;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** object で、JSON にした長さが上限以内ならそのまま返す。それ以外は null。 */
function passThroughObject(v: unknown): Record<string, unknown> | null {
  return isRecord(v) && JSON.stringify(v).length <= RLS_STATE_MAX_LENGTH ? v : null;
}

/**
 * backend の応答から契約の key だけを名指しで写す。型が 1 つでも違えば null。
 * スプレッドで写さない — backend が key を足しても MCP の tool から出ないようにする。
 *
 * `state` と `drift` だけは入れ子まで写さない (object であることと大きさだけ見る)。形の
 * 正本は alc-migrations の固定の SQL と backend の比較で、形が育つたびにここの写しを直す
 * 二重管理にしないため。合わなくてもその key を null にするだけで全体は null にしない。
 *
 * `verdicts` は無くてよい (古い backend は返さない → `verdicts: null`)。在るなら 4 つとも
 * boolean であること — 欠け・型違いは応答全体を不正として null (内訳を読めないまま
 * 合否だけ返さない)。
 */
function parseRlsCheck(body: unknown): RlsCheckResult | null {
  if (!isRecord(body)) return null;
  const { ok, migrations: m, runtime_role: r, connections, owner_role_connected, invariants: inv } = body;
  if (typeof ok !== "boolean" || typeof owner_role_connected !== "boolean") return null;
  if (!isRecord(m) || !isRecord(r) || !isRecord(inv)) return null;
  if (!Array.isArray(connections) || !Array.isArray(inv.violations)) return null;
  if (!Array.isArray(inv.checks)) return null;

  if (
    typeof m.applied !== "number" ||
    typeof m.max_version !== "number" ||
    typeof m.binary_count !== "number" ||
    typeof m.binary_max_version !== "number" ||
    typeof m.matches_binary !== "boolean"
  ) {
    return null;
  }
  if (
    typeof r.current_user !== "string" ||
    typeof r.is_runtime_role !== "boolean" ||
    typeof r.rolsuper !== "boolean" ||
    typeof r.rolbypassrls !== "boolean" ||
    typeof r.rolinherit !== "boolean" ||
    typeof r.member_of_table_owner !== "boolean"
  ) {
    return null;
  }
  if (typeof inv.violation_count !== "number") return null;

  const conns: RlsCheckResult["connections"] = [];
  for (const c of connections as unknown[]) {
    if (!isRecord(c) || typeof c.usename !== "string" || typeof c.count !== "number") return null;
    conns.push({ usename: c.usename, count: c.count });
  }
  const violations: RlsCheckResult["invariants"]["violations"] = [];
  for (const v of inv.violations as unknown[]) {
    if (
      !isRecord(v) ||
      typeof v.check_no !== "number" ||
      typeof v.object !== "string" ||
      typeof v.detail !== "string"
    ) {
      return null;
    }
    violations.push({ check_no: v.check_no, object: v.object, detail: v.detail });
  }
  const checks: RlsCheckResult["invariants"]["checks"] = [];
  for (const c of inv.checks as unknown[]) {
    if (
      !isRecord(c) ||
      typeof c.check_no !== "number" ||
      typeof c.title !== "string" ||
      typeof c.violations !== "number"
    ) {
      return null;
    }
    checks.push({ check_no: c.check_no, title: c.title, violations: c.violations });
  }
  let verdicts: RlsBackendVerdicts | null = null;
  if (body.verdicts !== undefined) {
    const v = body.verdicts;
    if (
      !isRecord(v) ||
      typeof v.invariants !== "boolean" ||
      typeof v.runtime_role !== "boolean" ||
      typeof v.migrations !== "boolean" ||
      typeof v.drift !== "boolean"
    ) {
      return null;
    }
    verdicts = {
      invariants: v.invariants,
      runtime_role: v.runtime_role,
      migrations: v.migrations,
      drift: v.drift,
    };
  }

  return {
    ok,
    migrations: {
      applied: m.applied,
      max_version: m.max_version,
      binary_count: m.binary_count,
      binary_max_version: m.binary_max_version,
      matches_binary: m.matches_binary,
    },
    runtime_role: {
      current_user: r.current_user,
      is_runtime_role: r.is_runtime_role,
      rolsuper: r.rolsuper,
      rolbypassrls: r.rolbypassrls,
      rolinherit: r.rolinherit,
      member_of_table_owner: r.member_of_table_owner,
    },
    connections: conns,
    owner_role_connected,
    invariants: { violation_count: inv.violation_count, checks, violations },
    state: passThroughObject(body.state),
    verdicts,
    drift: passThroughObject(body.drift),
  };
}

/**
 * backend の固定の検査 (RLS の不変条件・実行用ロールの属性・接続ロール・適用履歴) の
 * 結果を読む (Refs #605)。引数を取らない GET 1 回で、テナントのヘッダも body も付けない。
 *
 * 200 かつ契約どおりの形の時だけ値を返す。それ以外 (fetch の例外・timeout・非 200・
 * JSON 不正・型違い・key 欠け) はすべて null — 呼び出し元は fail-closed で扱う。
 * 例外は `state` と `drift`、それに無くてよい `verdicts` (`parseRlsCheck` 参照)。
 */
export async function fetchRlsCheck(env: Env): Promise<RlsCheckResult | null> {
  let res: Response;
  try {
    res = await internalFetch(env, `/api/internal/rls-check`, {
      method: "GET",
      signal: AbortSignal.timeout(15000),
    });
  } catch {
    return null;
  }
  if (res.status !== 200) return null;

  let body: unknown;
  try {
    body = (await res.json()) as unknown;
  } catch {
    return null;
  }
  return parseRlsCheck(body);
}

/** vein (分割 worker) の DB 接続のロール (Refs #605)。 */
export interface VeinDbRole {
  /** `ALC_VEIN` が bind されているか (本番だけ bind)。 */
  bound: boolean;
  /** bind されていない時・呼べなかった時・形が違った時は null。 */
  current_user: string | null;
  is_runtime_role: boolean | null;
}

/** Service Binding 越しなのでホスト名は使われない。path は固定で、利用者由来の値を入れない。 */
const VEIN_DB_ROLE_URL = "https://alc-vein/internal/db-role";

/**
 * vein がどのロールで DB に繋いでいるかを、Service Binding で 1 回聞く (Refs #605)。
 * vein は backend と別の接続の secret を持ち、所有者ロールで繋いでいると RLS が掛からない。
 *
 * `/api/vein/` の proxy (`forwardViaAlcBinding`) は通さず、binding を直接呼ぶ — vein の口は
 * `/api` の外に在り、proxy の振り分けからは届かない。引数なしの GET で、Authorization・
 * テナントのヘッダ・body を付けない。契約の 2 key だけを名指しで写す。
 *
 * bind されていなければ `bound: false`。bind されているのに値を取れない (fetch の例外・
 * timeout・非 200・JSON 不正・型違い) ときは `bound: true` で値は null — 呼び出し元は
 * fail-closed で扱う。
 */
export async function fetchVeinDbRole(env: Env): Promise<VeinDbRole> {
  const binding = env.ALC_VEIN;
  if (!binding) return { bound: false, current_user: null, is_runtime_role: null };
  try {
    const res = await binding.fetch(VEIN_DB_ROLE_URL, {
      method: "GET",
      signal: AbortSignal.timeout(10000),
    });
    if (res.status === 200) {
      const body = (await res.json()) as unknown;
      if (
        isRecord(body) &&
        typeof body.current_user === "string" &&
        typeof body.is_runtime_role === "boolean"
      ) {
        return { bound: true, current_user: body.current_user, is_runtime_role: body.is_runtime_role };
      }
    }
  } catch {
    // 下の fail-closed の値を返す
  }
  return { bound: true, current_user: null, is_runtime_role: null };
}

/** tool `verify_rls` が返す形。backend の値に、tool が決めた合否と vein のロールを足す。 */
export interface VerifyRlsResult extends Omit<RlsCheckResult, "verdicts"> {
  /** null の項目は「その backend・その環境では判定していない」(古い backend・vein が未 bind)。 */
  verdicts: {
    invariants: boolean | null;
    runtime_role: boolean | null;
    migrations: boolean | null;
    drift: boolean | null;
    vein: boolean | null;
  };
  workers: { vein: VeinDbRole };
}

/**
 * tool の `ok` と `verdicts` を組み立てる (Refs #605)。
 *
 * - `verdicts.vein`: bind されていなければ null (合否に入れない)。bind されていれば
 *   `is_runtime_role === true` のときだけ true (呼べなかった・形が違う = false)。
 * - `ok`: backend の `ok` かつ (backend が内訳を返したなら 4 つとも true) かつ
 *   (`vein` が null か true)。backend の `ok` が false なら true にならない。
 */
export function buildVerifyRlsResult(backend: RlsCheckResult, vein: VeinDbRole): VerifyRlsResult {
  const { ok: backendOk, verdicts: bv, ...rest } = backend;
  const veinVerdict = vein.bound ? vein.is_runtime_role === true : null;
  const backendVerdictsOk =
    bv === null || (bv.invariants && bv.runtime_role && bv.migrations && bv.drift);
  return {
    ok: backendOk && backendVerdictsOk && veinVerdict !== false,
    verdicts: {
      invariants: bv?.invariants ?? null,
      runtime_role: bv?.runtime_role ?? null,
      migrations: bv?.migrations ?? null,
      drift: bv?.drift ?? null,
      vein: veinVerdict,
    },
    workers: { vein: { bound: vein.bound, current_user: vein.current_user, is_runtime_role: vein.is_runtime_role } },
    ...rest,
  };
}

/** lineworks_id で user を find-or-create する。 */
export async function upsertLineworksUser(
  env: Env,
  body: { tenant_id: string; lineworks_id: string; email: string; name: string },
): Promise<InternalUserWithSlug> {
  const res = await internalFetch(env, `/api/internal/auth/users/upsert-lineworks`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`internal upsert-lineworks failed: ${res.status}`);
  return (await res.json()) as InternalUserWithSlug;
}

/** refresh token の hash を保存する (raw は渡さない)。 */
export async function saveRefreshToken(
  env: Env,
  body: { user_id: string; refresh_hash: string; expires_at: string },
): Promise<void> {
  const res = await internalFetch(env, `/api/internal/auth/refresh-token`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`internal refresh-token failed: ${res.status}`);
}

/** line_user_id で user を逆引きする (未登録は null)。 */
export async function findUserByLineId(
  env: Env,
  lineUserId: string,
): Promise<InternalUserWithSlug | null> {
  const qs = `line_user_id=${encodeURIComponent(lineUserId)}`;
  const res = await internalFetch(env, `/api/internal/auth/users/by-line-id?${qs}`);
  if (!res.ok) throw new Error(`internal by-line-id failed: ${res.status}`);
  return (await res.json()) as InternalUserWithSlug | null;
}

/**
 * google_sub で user を find-or-create する (Refs rust-alc-api#479)。
 * tenant 解決 (招待 → email_domain → STAGING_MODE 自動作成) は rust 側。
 * どのテナントにも割当できない場合 rust が 403 を返すので null で表す。
 */
export async function upsertGoogleUser(
  env: Env,
  body: { google_sub: string; email: string; name: string },
): Promise<InternalUserWithSlug | null> {
  const res = await internalFetch(env, `/api/internal/auth/users/upsert-google`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (res.status === 403) return null;
  if (!res.ok) throw new Error(`internal upsert-google failed: ${res.status}`);
  return (await res.json()) as InternalUserWithSlug;
}

/** line_user_id で user を find-or-create する。 */
export async function upsertLineUser(
  env: Env,
  body: { tenant_id: string; line_user_id: string; name: string },
): Promise<InternalUserWithSlug> {
  const res = await internalFetch(env, `/api/internal/auth/users/upsert-line`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`internal upsert-line failed: ${res.status}`);
  return (await res.json()) as InternalUserWithSlug;
}

/** LINE recipient を自動登録する (QR 招待フロー)。 */
export async function registerLineRecipient(
  env: Env,
  body: { tenant_id: string; name: string; line_user_id: string },
): Promise<void> {
  const res = await internalFetch(env, `/api/internal/auth/recipients/register-line`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`internal register-line failed: ${res.status}`);
}

/** notify_recipients から line_user_id で tenant を逆引きする (複数テナント対応)。 */
export async function recipientsByLineId(
  env: Env,
  lineUserId: string,
): Promise<Array<{ tenant_id: string; name: string }>> {
  const qs = `line_user_id=${encodeURIComponent(lineUserId)}`;
  const res = await internalFetch(env, `/api/internal/auth/recipients/by-line-id?${qs}`);
  if (!res.ok) throw new Error(`internal recipients-by-line-id failed: ${res.status}`);
  return (await res.json()) as Array<{ tenant_id: string; name: string }>;
}
