/**
 * SSO Settings API endpoints
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

export async function handleSsoList(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) {
    return jsonResponse({ error: "Unauthorized" }, 401);
  }

  console.log(JSON.stringify({ event: "sso_list" }));

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/sso/configs`, {
    headers: { "Authorization": `Bearer ${token}` },
  });

  if (!resp.ok) {
    const text = await resp.text();
    return jsonResponse({ error: text || "Failed to list configs" }, resp.status);
  }

  const data = await resp.json() as { configs: Array<{
    provider: string;
    client_id: string;
    external_org_id: string;
    enabled: boolean;
    woff_id: string | null;
    created_at: string;
    updated_at: string;
  }> };

  return jsonResponse({
    configs: (data.configs || []).map((c) => ({
      provider: c.provider,
      clientId: c.client_id,
      hasClientSecret: true,
      externalOrgId: c.external_org_id,
      enabled: c.enabled,
      woffId: c.woff_id || "",
      createdAt: c.created_at,
      updatedAt: c.updated_at,
    })),
  });
}

export async function handleSsoUpsert(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) {
    return jsonResponse({ error: "Unauthorized" }, 401);
  }

  const body = (await request.json()) as {
    provider: string;
    clientId: string;
    clientSecret: string;
    externalOrgId: string;
    woffId?: string;
    enabled: boolean;
  };

  if (!body.provider || !body.clientId || !body.externalOrgId) {
    return jsonResponse({ error: "provider, clientId, externalOrgId are required" }, 400);
  }

  console.log(JSON.stringify({ event: "sso_upsert", provider: body.provider, externalOrgId: body.externalOrgId }));

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/sso/configs`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      provider: body.provider,
      client_id: body.clientId,
      client_secret: body.clientSecret || null,
      external_org_id: body.externalOrgId,
      woff_id: body.woffId || null,
      enabled: body.enabled ?? true,
    }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    return jsonResponse({ error: text || "Failed to upsert config" }, resp.status);
  }

  const c = await resp.json() as {
    provider: string;
    client_id: string;
    external_org_id: string;
    enabled: boolean;
    woff_id: string | null;
  };

  return jsonResponse({
    provider: c.provider,
    clientId: c.client_id,
    hasClientSecret: true,
    externalOrgId: c.external_org_id,
    woffId: c.woff_id || "",
    enabled: c.enabled,
  });
}

export async function handleSsoDelete(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) {
    return jsonResponse({ error: "Unauthorized" }, 401);
  }

  const body = (await request.json()) as { provider: string };
  if (!body.provider) {
    return jsonResponse({ error: "provider is required" }, 400);
  }

  console.log(JSON.stringify({ event: "sso_delete", provider: body.provider }));

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/sso/configs`, {
    method: "DELETE",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ provider: body.provider }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    return jsonResponse({ error: text || "Failed to delete config" }, resp.status);
  }

  return jsonResponse({ success: true });
}
