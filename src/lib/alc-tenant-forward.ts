/**
 * Service binding RPC (`InternalEntrypoint` / `SmbIngestEntrypoint` / `KintaiAlcEntrypoint`) から
 * tenant data 経路 (`require_tenant_header`) を叩く共通部分。
 *
 *   path が振り分けの表 (`lib/alc-backend-route.ts`) の `rpc` の行に一致し binding が在れば、domain worker へ
 *   Service Binding で渡す (`X-Tenant-ID` などだけ)。表に無い path / binding 無しは 404。
 *   W9 (Refs ippoan/rust-alc-api#680): Cloud Run (rust-alc-api) への fallback・OIDC mint は撤去した。
 *
 * ★ **path / tenant の検査はここではしない** — 呼び手 (entrypoint) の責務。
 * 「どの path を・どの tenant で」通すかは entrypoint ごとに決まっていて
 * (`FORWARDABLE_PATHS` の allowlist / KV 固定の tenant)、この関数は
 * 渡されたものをそのまま送る。entrypoint を経由せずにこの関数を呼び足さないこと。
 *
 * 失敗は throw せず `{status, body, contentType}` で返す。
 * 値は log / 戻り値に出さない。
 */
import type { Env } from "../index";
import { forwardViaAlcBinding, resolveAlcBinding } from "./alc-backend-route";

/**
 * RPC の戻り値。
 *
 * ★ `Response` をそのまま返さない — RPC 越しの `Response` は寿命の扱いが増えるだけで、
 * この用途 (小さい JSON) には要らない。**素の serializable オブジェクト**にする。
 */
export interface AlcRpcResult {
  status: number;
  body: string;
  contentType: string | null;
}

export function alcRpcError(status: number, error: string): AlcRpcResult {
  return { status, body: JSON.stringify({ error }), contentType: "application/json" };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * AUTH_CONFIG KV の `key` に置いた固定 tenant (UUID 文字列) を引く。
 * 無い・空・UUID でない → `null` (呼び手は転送せずに 503 で返す = fail-closed)。
 * 値はこの repo に入れない。
 */
export async function resolveKvTenant(env: Env, key: string): Promise<string | null> {
  const tenantId = ((await env.AUTH_CONFIG.get(key)) ?? "").trim();
  return UUID_RE.test(tenantId) ? tenantId : null;
}

/**
 * AUTH_CONFIG KV の `key` に置いた tenant の許可リスト (UUID 文字列の JSON 配列) を引く。
 * 無い・空・JSON 配列でない・要素が 0 個 → `null` (呼び手は 503 で返す = fail-closed)。
 * 要素は UUID の形のものだけ残す。値はこの repo に入れない。
 */
export async function resolveKvTenantList(env: Env, key: string): Promise<string[] | null> {
  let parsed: unknown;
  try {
    parsed = JSON.parse((await env.AUTH_CONFIG.get(key)) ?? "");
  } catch {
    return null;
  }
  if (!Array.isArray(parsed)) return null;
  const ids = parsed
    .filter((v): v is string => typeof v === "string")
    .map((v) => v.trim())
    .filter((v) => UUID_RE.test(v));
  return ids.length > 0 ? ids : null;
}

export interface AlcTenantForwardInput {
  /** 転送先に `X-Tenant-ID` として注入する tenant (呼び手が検査済みであること)。 */
  tenantId: string;
  /** 転送先の path (呼び手が検査済みであること)。 */
  path: string;
  method: string;
  /** `?a=1&b=2` (先頭 `?` は有っても無くても良い)。 */
  search?: string;
  body?: string;
  contentType?: string;
  /**
   * 開発の軸 (`X-Device-Dev: 1`) の行を読み書きする。MCP `create_test_record` が試験記録を
   * 読み返すときだけ立てる (Refs ippoan/alc-cam#2)。
   */
  deviceDev?: boolean;
}

export async function forwardAlcTenantRequest(
  env: Env,
  input: AlcTenantForwardInput,
): Promise<AlcRpcResult> {
  const rawSearch = input.search || "";
  const search = !rawSearch || rawSearch.startsWith("?") ? rawSearch : `?${rawSearch}`;
  const headers: Record<string, string> = { "X-Tenant-ID": input.tenantId };
  if (input.contentType) headers["Content-Type"] = input.contentType;
  if (input.deviceDev) headers["X-Device-Dev"] = "1";
  const method = (input.method || "GET").toUpperCase();
  const hasBody = method !== "GET" && method !== "HEAD";
  const body = hasBody ? input.body : undefined;

  // ── domain worker (Service Binding) への振り分け ──────────────────────────
  // path は entrypoint の定数・allowlist のもの (この関数は検査しない。冒頭の注)。
  // 表に無い path / binding 無しは 404 (W9 で Cloud Run fallback を撤去)。
  const binding = resolveAlcBinding(input.path, env, "rpc", method);
  if (!binding) return alcRpcError(404, "not_found");
  const res = await forwardViaAlcBinding(binding, input.path, search, { method, headers, body });
  return { status: res.status, body: await res.text(), contentType: res.headers.get("content-type") };
}
