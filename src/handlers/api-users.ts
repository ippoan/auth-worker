/**
 * User Management API endpoints
 * Client JS → auth-worker API → rust-alc-api REST API
 */

import type { Env } from "../index";
import {
  buildAdminForwardHeaders,
  debugRustResponse,
} from "../lib/admin-proxy";

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
