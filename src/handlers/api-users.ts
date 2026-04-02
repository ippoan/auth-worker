/**
 * User Management API endpoints
 * Client JS → auth-worker API → rust-alc-api REST API
 */

import type { Env } from "../index";

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

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/users`, {
    headers: { "Authorization": `Bearer ${token}` },
  });

  if (!resp.ok) {
    const text = await resp.text();
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

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/users/invitations`, {
    headers: { "Authorization": `Bearer ${token}` },
  });

  if (!resp.ok) {
    const text = await resp.text();
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

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/users/invite`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email: body.email, role: body.role || "admin" }),
  });

  if (!resp.ok) {
    const text = await resp.text();
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

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/users/invite/${body.id}`, {
    method: "DELETE",
    headers: { "Authorization": `Bearer ${token}` },
  });

  if (!resp.ok) {
    const text = await resp.text();
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

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/users/${body.id}`, {
    method: "DELETE",
    headers: { "Authorization": `Bearer ${token}` },
  });

  if (!resp.ok) {
    const text = await resp.text();
    return jsonResponse({ error: text }, resp.status);
  }

  return jsonResponse({ success: true });
}
