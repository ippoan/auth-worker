/**
 * SSO Settings API endpoints
 * Client JS → auth-worker API → rust-alc-api REST API
 */

import type { Env } from "../index";
import type {
  SsoConfigListResponse,
  SsoConfigRow as SsoConfig,
} from "../types/alc-api";
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

export async function handleSsoList(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) {
    return jsonResponse({ error: "Unauthorized" }, 401);
  }

  console.log(JSON.stringify({ event: "sso_list" }));

  const headers = await buildAdminForwardHeaders(token, env, "sso_list");
  if (!headers) {
    return jsonResponse({ error: "Unauthorized" }, 401);
  }

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/sso/configs`, {
    headers,
  });

  if (!resp.ok) {
    const text = await resp.text();
    debugRustResponse(env, "sso_list", resp.status, text);
    return jsonResponse({ error: text }, resp.status);
  }

  const data = (await resp.json()) as SsoConfigListResponse;

  return jsonResponse({
    configs: data.configs.map((c) => ({
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
    return jsonResponse(
      { error: "provider, clientId, externalOrgId are required" },
      400,
    );
  }

  console.log(
    JSON.stringify({
      event: "sso_upsert",
      provider: body.provider,
      externalOrgId: body.externalOrgId,
    }),
  );

  const headers = await buildAdminForwardHeaders(token, env, "sso_upsert", {
    "Content-Type": "application/json",
  });
  if (!headers) {
    return jsonResponse({ error: "Unauthorized" }, 401);
  }

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/sso/configs`, {
    method: "POST",
    headers,
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
    debugRustResponse(env, "sso_upsert", resp.status, text);
    return jsonResponse({ error: text }, resp.status);
  }

  const c = (await resp.json()) as SsoConfig;

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

  const headers = await buildAdminForwardHeaders(token, env, "sso_delete", {
    "Content-Type": "application/json",
  });
  if (!headers) {
    return jsonResponse({ error: "Unauthorized" }, 401);
  }

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/sso/configs`, {
    method: "DELETE",
    headers,
    body: JSON.stringify({ provider: body.provider }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    debugRustResponse(env, "sso_delete", resp.status, text);
    return jsonResponse({ error: text }, resp.status);
  }

  return jsonResponse({ success: true });
}
