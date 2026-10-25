/**
 * 会社のユーザー管理の API (`/admin/users` の画面が呼ぶ)。
 * Client JS → auth-worker → alc-auth-worker の内部口 (`ALC_AUTH`、Refs ippoan/rust-alc-api#680)。
 * 以前は rust-alc-api の `/api/admin/users*` を叩いていた。認可 (管理者か・自分自身を消さないか) はここで行う。
 */

import type { Env } from "../index";
import { listUserRoles, setUserRole } from "../lib/alc-internal";
import {
  callTenantAdmin,
  errorResponse,
  jsonResponse,
  requireCaller,
  tenantPath,
} from "../lib/alc-tenant-admin";

/** `/admin/users` で付け外しできるロール (alc-auth-worker の持つロールのうち画面に出すもの)。 */
const TOGGLEABLE_ROLES = new Set(["leave"]);

/** `/api/users/list` — その会社の user の一覧 (`{users:[{id,email,name,role,created_at}]}`)。 */
export async function handleUsersList(request: Request, env: Env): Promise<Response> {
  const caller = await requireCaller(request, env, { admin: true, write: false });
  if (caller instanceof Response) return caller;
  const r = await callTenantAdmin(env, tenantPath(caller.tenantId, "users"));
  return r.status === 200 ? jsonResponse(r.body) : errorResponse(r);
}

/** `/api/users/invitations` — 招待の一覧 (`{invitations:[…]}`)。 */
export async function handleInvitationsList(request: Request, env: Env): Promise<Response> {
  const caller = await requireCaller(request, env, { admin: true, write: false });
  if (caller instanceof Response) return caller;
  const r = await callTenantAdmin(env, tenantPath(caller.tenantId, "invitations"));
  return r.status === 200 ? jsonResponse(r.body) : errorResponse(r);
}

/** `POST /api/users/invite` — body `{email, role?}` で招待する (role の省略は admin)。招待の 1 行を返す。 */
export async function handleInviteUser(request: Request, env: Env): Promise<Response> {
  const caller = await requireCaller(request, env, { admin: true, write: true });
  if (caller instanceof Response) return caller;
  const body = (await request.json().catch(() => null)) as { email?: unknown; role?: unknown } | null;
  if (!body || typeof body.email !== "string" || !body.email) {
    return jsonResponse({ error: "email is required" }, 400);
  }
  const role = typeof body.role === "string" && body.role ? body.role : "admin";
  const r = await callTenantAdmin(env, tenantPath(caller.tenantId, "invitations"), {
    method: "POST",
    body: { email: body.email, role },
  });
  return r.status === 200 ? jsonResponse(r.body) : errorResponse(r);
}

/** body の `id` (文字列) を取る。無ければ null */
async function readId(request: Request): Promise<string | null> {
  const body = (await request.json().catch(() => null)) as { id?: unknown } | null;
  return body && typeof body.id === "string" && body.id ? body.id : null;
}

/** `POST /api/users/invite/delete` — body `{id}` の招待を消す。 */
export async function handleDeleteInvitation(request: Request, env: Env): Promise<Response> {
  const caller = await requireCaller(request, env, { admin: true, write: true });
  if (caller instanceof Response) return caller;
  const id = await readId(request);
  if (!id) return jsonResponse({ error: "id is required" }, 400);
  const r = await callTenantAdmin(env, tenantPath(caller.tenantId, "invitations", id), { method: "DELETE" });
  return r.status === 204 ? jsonResponse({ success: true }) : errorResponse(r);
}

/** `POST /api/users/delete` — body `{id}` の user を消す。自分自身は消せない (400)。 */
export async function handleDeleteUser(request: Request, env: Env): Promise<Response> {
  const caller = await requireCaller(request, env, { admin: true, write: true });
  if (caller instanceof Response) return caller;
  const id = await readId(request);
  if (!id) return jsonResponse({ error: "id is required" }, 400);
  if (id === caller.userId) return jsonResponse({ error: "cannot_delete_self" }, 400);
  const r = await callTenantAdmin(env, tenantPath(caller.tenantId, "users", id), { method: "DELETE" });
  return r.status === 204 ? jsonResponse({ success: true }) : errorResponse(r);
}

/**
 * `GET /api/users/roles` — その会社の user ごとのロール (`{ user_roles: [{user_id, roles}] }`)。
 * ロールの持ち主は alc-auth-worker (Refs ohishi-exp/rust-leave-worker#1)。
 */
export async function handleUserRolesList(
  request: Request,
  env: Env,
): Promise<Response> {
  const auth = await requireCaller(request, env, { admin: true, write: false });
  if (auth instanceof Response) return auth;
  const result = await listUserRoles(env, auth.tenantId);
  if (!result.ok) return jsonResponse({ error: result.error }, result.status);
  return jsonResponse({ user_roles: result.value });
}

/** `POST /api/users/roles` — body `{user_id, role, on}` でロールを付ける / 外す。 */
export async function handleUserRoleSet(
  request: Request,
  env: Env,
): Promise<Response> {
  const auth = await requireCaller(request, env, { admin: true, write: true });
  if (auth instanceof Response) return auth;
  const body = (await request.json().catch(() => null)) as {
    user_id?: unknown;
    role?: unknown;
    on?: unknown;
  } | null;
  if (!body || typeof body.user_id !== "string" || !body.user_id || typeof body.on !== "boolean") {
    return jsonResponse({ error: "user_id and on are required" }, 400);
  }
  if (typeof body.role !== "string" || !TOGGLEABLE_ROLES.has(body.role)) {
    return jsonResponse({ error: "unknown_role" }, 400);
  }
  const result = await setUserRole(env, auth.tenantId, body.user_id, body.role, body.on);
  if (!result.ok) return jsonResponse({ error: result.error }, result.status);
  return jsonResponse({ success: true });
}
