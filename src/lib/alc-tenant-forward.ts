/**
 * Service binding RPC (`InternalEntrypoint` / `SmbIngestEntrypoint`) から
 * rust-alc-api の tenant data 経路 (`require_tenant_header`) を叩く共通部分。
 *
 *   ① env guard (`ALC_API_PROXY_SA_KEY` / `ALC_API_ORIGIN`)
 *   ② OIDC mint (Cloud Run IAM lockdown 用、aud=service URL)
 *   ③ `Authorization: Bearer <OIDC>` + `X-Tenant-ID` を付けて forward
 *
 * ★ **path / tenant の検査はここではしない** — 呼び手 (entrypoint) の責務。
 * 「どの path を・どの tenant で」通すかは entrypoint ごとに決まっていて
 * (`FORWARDABLE_PATHS` の allowlist / KV 固定の tenant)、この関数は
 * 渡されたものをそのまま送る。entrypoint を経由せずにこの関数を呼び足さないこと。
 *
 * 失敗は throw せず `{status, body, contentType}` で返す。
 * 値 (OIDC / SA key) は log / 戻り値に出さない。
 */
import type { Env } from "../index";
import { resolveSecret } from "./secret";
import { mintGoogleIdToken } from "./oidc";

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

export interface AlcTenantForwardInput {
  /** 転送先に `X-Tenant-ID` として注入する tenant (呼び手が検査済みであること)。 */
  tenantId: string;
  /** rust-alc-api 側の path (呼び手が検査済みであること)。 */
  path: string;
  method: string;
  /** `?a=1&b=2` (先頭 `?` は有っても無くても良い)。 */
  search?: string;
  body?: string;
  contentType?: string;
}

export async function forwardAlcTenantRequest(
  env: Env,
  input: AlcTenantForwardInput,
): Promise<AlcRpcResult> {
  // ── ① env guard ──────────────────────────────────────────────────────────
  const saKey = await resolveSecret(env.ALC_API_PROXY_SA_KEY);
  if (!saKey) return alcRpcError(503, "internal entrypoint not configured");
  const apiOrigin = env.ALC_API_ORIGIN;
  if (!apiOrigin) return alcRpcError(503, "server_error");

  // ── ② OIDC mint (Cloud Run IAM lockdown 用、aud=service URL) ──────────────
  let idToken: string;
  try {
    idToken = await mintGoogleIdToken(saKey, apiOrigin);
  } catch {
    return alcRpcError(502, "upstream auth error"); // 詳細は log のみ
  }

  // ── ③ forward ────────────────────────────────────────────────────────────
  const rawSearch = input.search || "";
  const search = !rawSearch || rawSearch.startsWith("?") ? rawSearch : `?${rawSearch}`;
  const target = `${apiOrigin.replace(/\/$/, "")}${input.path}${search}`;

  const headers: Record<string, string> = {
    Authorization: `Bearer ${idToken}`,
    "X-Tenant-ID": input.tenantId,
  };
  if (input.contentType) headers["Content-Type"] = input.contentType;

  const method = (input.method || "GET").toUpperCase();
  const hasBody = method !== "GET" && method !== "HEAD";

  const res = await fetch(target, {
    method,
    headers,
    body: hasBody ? input.body : undefined,
  });

  return {
    status: res.status,
    body: await res.text(),
    contentType: res.headers.get("content-type"),
  };
}
