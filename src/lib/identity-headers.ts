/**
 * rust-alc-api#434: rust-alc-api は #441 で JWT 検証を撤去した dumb backend に
 * なり、`/api/my-orgs` / `/api/auth/switch-org` は `require_tenant_header`
 * (X-Tenant-ID + X-User-ID/Email/Role を信頼) の後ろにある。これらは auth の
 * 関心事なので client は auth-worker 経由で叩く (auth-worker → rust-alc-api の
 * 一方向 pass-through)。よって auth-worker がこの 2 経路の **前段 proxy** を兼ね、
 * ブラウザ JWT を検証して検証済み identity をヘッダ注入する必要がある。
 * 旧実装は raw `Authorization: Bearer` を素通ししていたが、require_tenant_header
 * は Bearer を読まないため X-Tenant-ID 欠落で 401 になっていた (= 本 helper で解消)。
 *
 * lockdown (`allUsers` 削除) 後は上記に加え、Cloud Run IAM が Google OIDC ID token
 * (aud=ALC_API_ORIGIN) を要求する。`alcOidcToken` で mint し `Authorization` に載せる
 * (`alc-data-fetch.ts` の `alcIdentityHeaders` と同方針)。mint 不可 (SA key 未設定 =
 * lockdown 前) でも X-Tenant-ID 系ヘッダはそのまま返す (fail-open、allUsers が残って
 * いる間は Authorization 無しで素通りする従来動作を維持)。
 */
import type { Env } from "../index";
import { alcOidcToken } from "./alc-data-fetch";
import { verifyJwt } from "./jwt";
import { resolveSecret } from "./secret";

/**
 * ブラウザ JWT を `JWT_SECRET` で検証し、rust-alc-api の `require_tenant_header`
 * 向け identity ヘッダ (`X-Tenant-ID` / `X-User-ID` / `X-User-Email` /
 * `X-User-Role`) + lockdown 後の transport 用 OIDC (`Authorization`) を組み立てて
 * 返す。検証失敗 / 必須 claim 欠落なら `null` (= 呼び出し側で 401)。OIDC mint 失敗時は
 * Authorization を付けずに fail-open する (lockdown 前の非破壊)。
 *
 * `require_tenant_header` は `X-Tenant-ID` (UUID) を必須とし、`X-User-ID` (UUID)
 * + `X-User-Email` + `X-User-Role` が **揃って初めて** AuthUser を復元する。
 * 1 つでも欠けると my_orgs / switch_org が AuthUser を取れず 500/401 になるので、
 * 4 点すべてが JWT から取れない token は invalid 扱い (null) にする。
 *
 * 値 (token / secret) は引数とローカルだけを通り、log / response には出さない。
 */
export async function verifiedIdentityHeaders(
  env: Env,
  token: string,
): Promise<Record<string, string> | null> {
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) return null;

  const payload = await verifyJwt(token, jwtSecret, env.WORKER_ENV);
  if (!payload) return null;

  const tenantId =
    (typeof payload.tenant_id === "string" ? payload.tenant_id : "") ||
    (typeof payload.org === "string" ? payload.org : "");
  const sub = typeof payload.sub === "string" ? payload.sub : "";
  const email = typeof payload.email === "string" ? payload.email : "";
  const role = typeof payload.role === "string" ? payload.role : "";

  if (!tenantId || !sub || !email || !role) return null;

  const oidc = await alcOidcToken(env);
  const headers: Record<string, string> = {
    "X-Tenant-ID": tenantId,
    "X-User-ID": sub,
    "X-User-Email": email,
    "X-User-Role": role,
  };
  if (oidc) headers.Authorization = `Bearer ${oidc}`;
  return headers;
}
