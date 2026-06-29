/**
 * auth-worker 自身の handler (join-page / api-access-requests 等) が rust の **データ API**
 * を直接 fetch する時の Authorization / identity header を作るヘルパー。
 *
 * #434 lockdown (`allUsers` 削除) 後、rust (`ALC_API_ORIGIN` = alc-api.ippoan.org の
 * Cloud Run domain mapping) は **Google OIDC ID token** を Cloud Run IAM で要求する。
 * aud は **`ALC_API_ORIGIN`** (= service URL / カスタムドメイン、render.sh の
 * custom-audiences に登録済み)。これは `/alc-proxy` と同じ「aud=service URL」方針で、
 * internal route 用の `aud=alc-api-internal` とは区別する (confused-deputy 防止)。
 *
 * 従来これらの handler は browser JWT を素の `Authorization: Bearer` で rust に転送して
 * いたが、(1) rust は #441 で dumb backend 化し JWT を検証せず `require_tenant_header`
 * の注入 header (`X-Tenant-ID` / `X-User-*`) を読む、(2) lockdown 後は Google OIDC で
 * ないと IAM が弾く、の 2 点で誤り。本ヘルパーで OIDC transport + identity 注入に揃える。
 */
import type { Env } from "../index";
import { verifyJwt } from "./jwt";
import { resolveSecret } from "./secret";
import { mintGoogleIdToken } from "./oidc";

/**
 * rust データ API 用の Google OIDC ID token (aud=ALC_API_ORIGIN) を mint して返す。
 * SA key binding (`ALC_API_PROXY_SA_KEY`) / `ALC_API_ORIGIN` 未設定、または mint 失敗で
 * `null` (= 呼び出し側は OIDC 無しで fetch 継続 = lockdown 前は public allUsers で素通り)。
 * identity 不要な public route (例: `/api/tenants/by-slug`) の transport 用。
 */
export async function alcOidcToken(env: Env): Promise<string | null> {
  const saKey = await resolveSecret(env.ALC_API_PROXY_SA_KEY);
  if (!saKey || !env.ALC_API_ORIGIN) return null;
  try {
    return await mintGoogleIdToken(saKey, env.ALC_API_ORIGIN);
  } catch {
    return null;
  }
}

/**
 * browser JWT を auth-worker がローカル検証し、rust データ API 用の header
 * (OIDC transport + 注入 identity) を返す。`require_tenant_header` が読む
 * `X-Tenant-ID` / `X-User-ID` / `X-User-Email` / `X-User-Role` を注入する。
 * JWT 検証失敗・OIDC mint 失敗時は `null` (呼び出し側は 401/503 を返す)。
 */
export async function alcIdentityHeaders(
  env: Env,
  browserToken: string,
): Promise<Record<string, string> | null> {
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) return null;
  const payload = await verifyJwt(browserToken, jwtSecret, env.WORKER_ENV);
  if (!payload) return null;
  const oidc = await alcOidcToken(env);
  if (!oidc) return null;

  const headers: Record<string, string> = { Authorization: `Bearer ${oidc}` };
  const tenantId =
    (payload.tenant_id as string | undefined) || (payload.org as string | undefined) || "";
  if (tenantId) headers["X-Tenant-ID"] = tenantId;
  const sub = payload.sub as string | undefined;
  if (sub) headers["X-User-ID"] = sub;
  const email = payload.email as string | undefined;
  if (email) headers["X-User-Email"] = email;
  const role = payload.role as string | undefined;
  if (role) headers["X-User-Role"] = role;
  return headers;
}
