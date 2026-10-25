/**
 * 会社の管理 (ユーザー・招待・SSO 設定・参加の申請) の画面の API が、alc-auth-worker (`ALC_AUTH`) の内部口を
 * 叩くための部品 (Refs ippoan/rust-alc-api#680)。以前は rust-alc-api (Cloud Run) の `/api/admin/users*`・
 * `/api/admin/sso/configs`・`/api/access-requests*`・`/api/tenants/by-slug` を identity ヘッダ付きで叩き、
 * 管理者かどうかは rust が見ていた。いまは**認可をここ (auth-worker) で行い**、alc-auth-worker には tenant を
 * path で渡す (alc-auth-worker は呼び手を信じる。`/api/users/roles` と同じ型)。
 */
import type { Env } from "../index";
import { fetchAlcAuth } from "./alc-auth-fetch";
import { verifyJwt } from "./jwt";
import { resolveSecret } from "./secret";

export function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export function extractToken(request: Request): string | null {
  const auth = request.headers.get("Authorization");
  return auth?.startsWith("Bearer ") ? auth.slice(7) : null;
}

/** 検証済みの JWT から取った呼び手。tenant と user は claim からだけ取る (body・query の値は使わない)。 */
export interface Caller {
  tenantId: string;
  userId: string;
}

/**
 * Bearer を検証して呼び手を返す。token 無し・署名不正・tenant / sub 無しは 401。
 * `admin` なら role が admin でなければ 403。`write` なら開発用・端末の token は 403
 * (読み取りだけ許す。alc-proxy の #433 と同じ考え方)。
 */
export async function requireCaller(
  request: Request,
  env: Env,
  opts: { admin: boolean; write: boolean },
): Promise<Caller | Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);
  const secret = await resolveSecret(env.JWT_SECRET);
  const claims = secret ? await verifyJwt(token, secret, env.WORKER_ENV) : null;
  if (!claims) return jsonResponse({ error: "Unauthorized" }, 401);
  const tenantId = typeof claims.tenant_id === "string" ? claims.tenant_id : "";
  const userId = typeof claims.sub === "string" ? claims.sub : "";
  if (!tenantId || !userId) return jsonResponse({ error: "Unauthorized" }, 401);
  if (opts.admin && claims.role !== "admin") return jsonResponse({ error: "Forbidden" }, 403);
  const tokenKind = claims.token_kind;
  if (opts.write && (tokenKind === "dev" || tokenKind === "device-key")) {
    return jsonResponse({ error: "Forbidden" }, 403);
  }
  return { tenantId, userId };
}

/** `/internal/tenants/{tenant_id}/...` の path (各段を URL エンコードする)。 */
export function tenantPath(tenantId: string, ...rest: string[]): string {
  return [`/internal/tenants/${encodeURIComponent(tenantId)}`, ...rest.map(encodeURIComponent)].join("/");
}

/** alc-auth-worker の応答 (`body` は 204 なら null)。 */
export interface AdminResult {
  status: number;
  body: unknown;
}

const UPSTREAM_ERROR: AdminResult = { status: 502, body: { error: "upstream_error" } };

/**
 * 内部口を 1 回叩き、状態と本文を返す。binding / secret が無い・通信の例外・本文の空の 404 (共有 secret の不一致)・
 * 5xx・JSON でない本文は 502 `upstream_error`。それ以外 (2xx と、`{error}` 付きの 4xx) はそのまま返す。
 */
export async function callTenantAdmin(
  env: Env,
  path: string,
  init: { method: "GET" | "POST" | "PUT" | "DELETE"; body?: unknown } = { method: "GET" },
): Promise<AdminResult> {
  let res: Response | null;
  try {
    res = await fetchAlcAuth(env, path, {
      method: init.method,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
  } catch {
    return UPSTREAM_ERROR;
  }
  if (!res || res.status >= 500) return UPSTREAM_ERROR;
  if (res.status === 204) return { status: 204, body: null };
  const text = await res.text();
  if (!text) return UPSTREAM_ERROR;
  try {
    return { status: res.status, body: JSON.parse(text) as unknown };
  } catch {
    return UPSTREAM_ERROR;
  }
}

/** 2xx でない結果を `{error}` の応答にする (alc-auth-worker の `{error}` をそのまま返す)。 */
export function errorResponse(r: AdminResult): Response {
  return jsonResponse(r.body, r.status);
}
