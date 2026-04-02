/**
 * Bot Config API endpoints
 * Client JS → auth-worker API → rust-alc-api REST API
 */

import type { Env } from "../index";
import type { BotConfigListResponse, BotConfigResponse } from "../types/alc-api";

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

export async function handleBotConfigList(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  console.log(JSON.stringify({ event: "bot_config_list" }));

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/bot/configs`, {
    headers: { "Authorization": `Bearer ${token}` },
  });

  if (!resp.ok) {
    const text = await resp.text();
    return jsonResponse({ error: text || "Failed to list configs" }, resp.status);
  }

  const data = await resp.json() as BotConfigListResponse;

  return jsonResponse({
    configs: (data.configs || []).map((c) => ({
      id: c.id,
      provider: c.provider,
      name: c.name,
      clientId: c.client_id,
      hasClientSecret: true,
      serviceAccount: c.service_account,
      hasPrivateKey: true,
      botId: c.bot_id,
      enabled: c.enabled,
      createdAt: c.created_at,
      updatedAt: c.updated_at,
    })),
  });
}

export async function handleBotConfigUpsert(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json()) as {
    id?: string;
    provider?: string;
    name: string;
    clientId: string;
    clientSecret?: string;
    serviceAccount: string;
    privateKey?: string;
    botId: string;
    enabled: boolean;
  };

  if (!body.name || !body.clientId || !body.botId || !body.serviceAccount) {
    return jsonResponse(
      { error: "name, clientId, serviceAccount, and botId are required" },
      400,
    );
  }

  console.log(JSON.stringify({ event: "bot_config_upsert", name: body.name, botId: body.botId }));

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/bot/configs`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      id: body.id || null,
      provider: body.provider || "lineworks",
      name: body.name,
      client_id: body.clientId,
      client_secret: body.clientSecret || null,
      service_account: body.serviceAccount,
      private_key: body.privateKey || null,
      bot_id: body.botId,
      enabled: body.enabled ?? true,
    }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    return jsonResponse({ error: text || "Failed to upsert config" }, resp.status);
  }

  const c = await resp.json() as BotConfigResponse;

  return jsonResponse({
    id: c.id,
    provider: c.provider,
    name: c.name,
    clientId: c.client_id,
    hasClientSecret: true,
    serviceAccount: c.service_account,
    hasPrivateKey: true,
    botId: c.bot_id,
    enabled: c.enabled,
  });
}

export async function handleBotConfigDelete(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json()) as { id: string };
  if (!body.id) {
    return jsonResponse({ error: "id is required" }, 400);
  }

  console.log(JSON.stringify({ event: "bot_config_delete", id: body.id }));

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/admin/bot/configs`, {
    method: "DELETE",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ id: body.id }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    return jsonResponse({ error: text || "Failed to delete config" }, resp.status);
  }

  return jsonResponse({ success: true });
}
