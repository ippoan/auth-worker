/**
 * `/alc-proxy/*` — rust-alc-api 向け data-proxy (rust-alc-api#434 step 3、方式 B)。
 *
 * consumer (alc-app / carins / items …) の CF Worker が **service binding**
 * (`AUTH_WORKER`) でこの route に forward する。auth-worker が:
 *   ① cookie / Bearer の browser JWT を **ローカル検証** (JWT_SECRET 所有) + ACL
 *      (origin × tenant、`X-Alc-Proxy-Origin` ヘッダの consumer origin で判定)
 *   ② `run.invoker` SA key (`ALC_API_PROXY_SA_KEY`、auth-worker のみ bind) で
 *      Google OIDC ID token を mint
 *   ③ `ALC_API_ORIGIN` (= rust-alc-api、Cloud Run IAM lockdown 後) へ
 *      `Authorization: Bearer <OIDC>` + `X-Tenant-ID` / `X-User-ID/Email/Role`
 *      を注入して forward
 * を 1 箇所で行う。SA key + OIDC mint を auth-worker に集約し、方式変更時の
 * 再配線を 1 repo に閉じる。
 *
 * 値 (token / SA key / OIDC) は log / response に出さない。
 */
import type { Env } from "../index";
import { getAuthCookie } from "../lib/cookies";
import { extractToken } from "../lib/errors";
import { verifyJwt } from "../lib/jwt";
import { checkAppTenant, checkOrgAccess } from "../lib/acl";
import { resolveSecret } from "../lib/secret";
import { mintGoogleIdToken } from "../lib/oidc";

const ROUTE_PREFIX = "/alc-proxy";

function jsonError(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export async function handleAlcProxy(request: Request, env: Env): Promise<Response> {
  // ── env guard ────────────────────────────────────────────────────────────
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) return jsonError(503, "server_error");
  const saKey = await resolveSecret(env.ALC_API_PROXY_SA_KEY);
  if (!saKey) return jsonError(503, "alc-proxy not configured"); // SA key binding 未設定
  const apiOrigin = env.ALC_API_ORIGIN;
  if (!apiOrigin) return jsonError(503, "server_error");

  // ── 認証: browser JWT (cookie / Bearer) を auth-worker がローカル検証 ───────
  const token = getAuthCookie(request) ?? extractToken(request) ?? "";
  if (!token) return jsonError(401, "Unauthorized");

  // ACL 用 origin は consumer が `X-Alc-Proxy-Origin` で渡す (= 元アプリ origin)。
  // service binding 越しでは request.url が auth-worker のものになり origin を
  // 失うため。欠落 → ACL 強制不能なので fail-closed。
  const originRaw = request.headers.get("X-Alc-Proxy-Origin") ?? "";
  let origin: string;
  try {
    origin = new URL(originRaw).origin;
  } catch {
    return jsonError(401, "Unauthorized");
  }

  const payload = await verifyJwt(token, jwtSecret, env.WORKER_ENV);
  if (!payload) return jsonError(401, "Unauthorized");
  const tenantId =
    (payload.tenant_id as string | undefined) || (payload.org as string | undefined) || "";
  const email = (payload.email as string | undefined) || "";
  const role = (payload.role as string | undefined) || "";
  const sub = (payload.sub as string | undefined) || "";
  if (!(await checkOrgAccess(env, origin, tenantId, email))) return jsonError(401, "Unauthorized");
  if (!checkAppTenant(env, origin, tenantId, email)) return jsonError(401, "Unauthorized");
  if (!tenantId) return jsonError(401, "Unauthorized");

  // ── OIDC mint (Cloud Run IAM lockdown 用)。aud = rust-alc-api service URL ──
  let idToken: string;
  try {
    idToken = await mintGoogleIdToken(saKey, apiOrigin);
  } catch {
    return jsonError(502, "upstream auth error"); // 詳細は log のみ (ここでは出さない)
  }

  // ── forward: ALC_API_ORIGIN + (/alc-proxy 以降の path) ────────────────────
  const url = new URL(request.url);
  const backendPath = url.pathname.slice(ROUTE_PREFIX.length) || "/";
  const target = `${apiOrigin.replace(/\/$/, "")}${backendPath}${url.search}`;

  const fwdHeaders: Record<string, string> = {
    Authorization: `Bearer ${idToken}`,
    "X-Tenant-ID": tenantId,
  };
  if (sub) fwdHeaders["X-User-ID"] = sub;
  if (email) fwdHeaders["X-User-Email"] = email;
  if (role) fwdHeaders["X-User-Role"] = role;
  const contentType = request.headers.get("content-type");
  if (contentType) fwdHeaders["Content-Type"] = contentType;

  const method = request.method;
  const hasBody = method !== "GET" && method !== "HEAD";
  const body = hasBody ? await request.arrayBuffer() : undefined;

  return fetch(target, { method, headers: fwdHeaders, body });
}

export { ROUTE_PREFIX as ALC_PROXY_PREFIX };
