/**
 * Access Requests API endpoints (REST version)
 * Client JS → auth-worker API → rust-alc-api REST API
 */

import type { Env } from "../index";
import { alcIdentityHeaders } from "../lib/alc-data-fetch";

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

export async function handleAccessRequestCreate(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json()) as { orgSlug: string };
  if (!body.orgSlug) {
    return jsonResponse({ error: "orgSlug is required" }, 400);
  }

  // #434 lockdown: browser JWT を検証 → OIDC + X-Tenant-ID/X-User-* 注入で rust を叩く
  // (rust は dumb backend で素の JWT を見ず注入 header を読む / IAM は OIDC を要求)。
  const idh = await alcIdentityHeaders(env, token);
  if (!idh) return jsonResponse({ error: "Unauthorized" }, 401);

  console.log(JSON.stringify({ event: "access_request_create", orgSlug: body.orgSlug }));

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/access-requests`, {
    method: "POST",
    headers: { ...idh, "Content-Type": "application/json" },
    body: JSON.stringify({ org_slug: body.orgSlug }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    return jsonResponse({ error: text }, resp.status);
  }

  return jsonResponse(await resp.json());
}

export async function handleAccessRequestList(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json()) as { statusFilter?: string };

  const idh = await alcIdentityHeaders(env, token);
  if (!idh) return jsonResponse({ error: "Unauthorized" }, 401);

  const url = new URL(`${env.ALC_API_ORIGIN}/api/access-requests`);
  if (body.statusFilter) {
    url.searchParams.set("status", body.statusFilter);
  }

  const resp = await fetch(url.toString(), { headers: idh });

  if (!resp.ok) {
    const text = await resp.text();
    return jsonResponse({ error: text }, resp.status);
  }

  return jsonResponse(await resp.json());
}

export async function handleAccessRequestApprove(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json()) as { requestId: string; role?: string };
  if (!body.requestId) {
    return jsonResponse({ error: "requestId is required" }, 400);
  }

  const idh = await alcIdentityHeaders(env, token);
  if (!idh) return jsonResponse({ error: "Unauthorized" }, 401);

  console.log(JSON.stringify({ event: "access_request_approve", requestId: body.requestId }));

  const resp = await fetch(
    `${env.ALC_API_ORIGIN}/api/access-requests/${body.requestId}/approve`,
    {
      method: "POST",
      headers: { ...idh, "Content-Type": "application/json" },
      body: JSON.stringify({ role: body.role }),
    },
  );

  if (!resp.ok) {
    const text = await resp.text();
    return jsonResponse({ error: text }, resp.status);
  }

  return jsonResponse({ success: true });
}

export async function handleAccessRequestDecline(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json()) as { requestId: string };
  if (!body.requestId) {
    return jsonResponse({ error: "requestId is required" }, 400);
  }

  const idh = await alcIdentityHeaders(env, token);
  if (!idh) return jsonResponse({ error: "Unauthorized" }, 401);

  console.log(JSON.stringify({ event: "access_request_decline", requestId: body.requestId }));

  const resp = await fetch(
    `${env.ALC_API_ORIGIN}/api/access-requests/${body.requestId}/decline`,
    {
      method: "POST",
      headers: idh,
    },
  );

  if (!resp.ok) {
    const text = await resp.text();
    return jsonResponse({ error: text }, resp.status);
  }

  return jsonResponse({ success: true });
}
