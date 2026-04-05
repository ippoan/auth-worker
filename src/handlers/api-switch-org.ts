/**
 * Organization switch API endpoint (REST version)
 * POST /api/switch-org — switch to a different organization/tenant
 */

import type { Env } from "../index";
import { corsJsonResponse, extractToken } from "../lib/errors";

export async function handleSwitchOrg(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return corsJsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json()) as { organizationId: string };
  if (!body.organizationId) {
    return corsJsonResponse({ error: "organizationId is required" }, 400);
  }

  console.log(JSON.stringify({ event: "switch_org", organizationId: body.organizationId }));

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/auth/switch-org`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ organization_id: body.organizationId }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    return corsJsonResponse({ error: text }, resp.status);
  }

  const data = await resp.json() as {
    token: string;
    expires_at: string;
    organization_id: string;
  };

  return corsJsonResponse({
    token: data.token,
    expiresAt: data.expires_at,
    organizationId: data.organization_id,
  });
}
