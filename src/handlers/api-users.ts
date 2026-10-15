/**
 * User Management API endpoints
 * Client JS → auth-worker API → rust-alc-api REST API
 */

import type { Env } from "../index";
import {
  buildAdminForwardHeaders,
  debugRustResponse,
} from "../lib/admin-proxy";
import { listUserRoles, setUserRole } from "../lib/alc-internal";
import { verifyJwt } from "../lib/jwt";
import { resolveSecret } from "../lib/secret";

/** `/admin/users` で付け外しできるロール (alc-auth-worker の持つロールのうち画面に出すもの)。 */
const TOGGLEABLE_ROLES = new Set(["leave"]);

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function extractToken(request: Request): string | null {
  const auth = request.headers.get("Authorization");
  if (auth?.startsWith("Bearer ")) {
    return auth.slice(7);
  }
  return null;
}

export async function handleUsersList(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const headers = await buildAdminForwardHeaders(token, env, "users_list");
  if (!headers) return jsonResponse({ error: "Unauthorized" }, 401);

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/users`, {
    headers,
  });

  if (!resp.ok) {
    const text = await resp.text();
    debugRustResponse(env, "users_list", resp.status, text);
    return jsonResponse({ error: text }, resp.status);
  }

  return jsonResponse(await resp.json());
}

export async function handleInvitationsList(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const headers = await buildAdminForwardHeaders(
    token,
    env,
    "users_invitations",
  );
  if (!headers) return jsonResponse({ error: "Unauthorized" }, 401);

  const resp = await fetch(
    `${env.ALC_API_ORIGIN}/api/admin/users/invitations`,
    { headers },
  );

  if (!resp.ok) {
    const text = await resp.text();
    debugRustResponse(env, "users_invitations", resp.status, text);
    return jsonResponse({ error: text }, resp.status);
  }

  return jsonResponse(await resp.json());
}

export async function handleInviteUser(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json()) as { email: string; role?: string };
  if (!body.email) {
    return jsonResponse({ error: "email is required" }, 400);
  }

  const headers = await buildAdminForwardHeaders(token, env, "users_invite", {
    "Content-Type": "application/json",
  });
  if (!headers) return jsonResponse({ error: "Unauthorized" }, 401);

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/users/invite`, {
    method: "POST",
    headers,
    body: JSON.stringify({ email: body.email, role: body.role || "admin" }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    debugRustResponse(env, "users_invite", resp.status, text);
    return jsonResponse({ error: text }, resp.status);
  }

  return jsonResponse(await resp.json());
}

export async function handleDeleteInvitation(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json()) as { id: string };
  if (!body.id) {
    return jsonResponse({ error: "id is required" }, 400);
  }

  const headers = await buildAdminForwardHeaders(
    token,
    env,
    "users_invite_delete",
  );
  if (!headers) return jsonResponse({ error: "Unauthorized" }, 401);

  const resp = await fetch(
    `${env.ALC_API_ORIGIN}/api/admin/users/invite/${body.id}`,
    {
      method: "DELETE",
      headers,
    },
  );

  if (!resp.ok) {
    const text = await resp.text();
    debugRustResponse(env, "users_invite_delete", resp.status, text);
    return jsonResponse({ error: text }, resp.status);
  }

  return jsonResponse({ success: true });
}

export async function handleDeleteUser(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json()) as { id: string };
  if (!body.id) {
    return jsonResponse({ error: "id is required" }, 400);
  }

  const headers = await buildAdminForwardHeaders(token, env, "users_delete");
  if (!headers) return jsonResponse({ error: "Unauthorized" }, 401);

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/users/${body.id}`, {
    method: "DELETE",
    headers,
  });

  if (!resp.ok) {
    const text = await resp.text();
    debugRustResponse(env, "users_delete", resp.status, text);
    return jsonResponse({ error: text }, resp.status);
  }

  return jsonResponse({ success: true });
}

/**
 * Bearer を検証し、管理者なら JWT の tenant_id を返す。tenant は検証済みの claim からだけ取る
 * (body・query の tenant は受けない)。開発用・端末の token は読み取りだけ許す (alc-proxy の #433 と同じ考え方)。
 */
async function requireAdminTenant(
  request: Request,
  env: Env,
  write: boolean,
): Promise<{ tenantId: string } | Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);
  const secret = await resolveSecret(env.JWT_SECRET);
  const claims = secret ? await verifyJwt(token, secret, env.WORKER_ENV) : null;
  if (!claims) return jsonResponse({ error: "Unauthorized" }, 401);
  const tenantId = typeof claims.tenant_id === "string" ? claims.tenant_id : "";
  if (!tenantId) return jsonResponse({ error: "Unauthorized" }, 401);
  if (claims.role !== "admin") return jsonResponse({ error: "Forbidden" }, 403);
  const tokenKind = claims.token_kind;
  if (write && (tokenKind === "dev" || tokenKind === "device-key")) {
    return jsonResponse({ error: "Forbidden" }, 403);
  }
  return { tenantId };
}

/**
 * `GET /api/users/roles` — その会社の user ごとのロール (`{ user_roles: [{user_id, roles}] }`)。
 * ロールの持ち主は alc-auth-worker (Refs ohishi-exp/rust-leave-worker#1)。
 */
export async function handleUserRolesList(
  request: Request,
  env: Env,
): Promise<Response> {
  const auth = await requireAdminTenant(request, env, false);
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
  const auth = await requireAdminTenant(request, env, true);
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
