/**
 * Organization list API endpoint
 * POST /api/my-orgs — returns organizations the authenticated user belongs to
 */

import type { Env } from "../index";
import { corsJsonResponse, extractToken } from "../lib/errors";
import { verifiedIdentityHeaders } from "../lib/identity-headers";

export async function handleMyOrgs(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return corsJsonResponse({ error: "Unauthorized" }, 401);

  // rust-alc-api#434: rust-alc-api /api/my-orgs は require_tenant_header (dumb
  // backend) の後ろにあり raw Bearer を読まない。ここで JWT を検証して
  // X-Tenant-ID + X-User-* を注入する (前段 proxy 役)。検証失敗は 401。
  const identity = await verifiedIdentityHeaders(env, token);
  if (!identity) return corsJsonResponse({ error: "Unauthorized" }, 401);

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/my-orgs`, {
    method: "POST",
    headers: identity,
  });

  if (!resp.ok) {
    const text = await resp.text();
    return corsJsonResponse({ error: text }, resp.status);
  }

  return corsJsonResponse(await resp.json());
}
