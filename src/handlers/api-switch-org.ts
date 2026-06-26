/**
 * Organization switch API endpoint (REST version)
 * POST /api/switch-org — switch to a different organization/tenant
 */

import type { Env } from "../index";
import { corsJsonResponse, extractToken } from "../lib/errors";
import { verifiedIdentityHeaders } from "../lib/identity-headers";

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

  // rust-alc-api#434: rust-alc-api /api/auth/switch-org は require_tenant_header
  // (dumb backend) の後ろ。JWT を検証して X-Tenant-ID + X-User-* を注入する
  // (switch_org は auth_user.user_id=sub で対象テナントの同一 identity を引く)。
  const identity = await verifiedIdentityHeaders(
    token,
    env.JWT_SECRET,
    env.WORKER_ENV,
  );
  if (!identity) return corsJsonResponse({ error: "Unauthorized" }, 401);

  console.log(JSON.stringify({ event: "switch_org", organizationId: body.organizationId }));

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/auth/switch-org`, {
    method: "POST",
    headers: {
      ...identity,
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
