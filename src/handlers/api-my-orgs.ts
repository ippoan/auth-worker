/**
 * Organization list API endpoint
 * POST /api/my-orgs — returns organizations the authenticated user belongs to
 */

import type { Env } from "../index";
import { corsJsonResponse, extractToken } from "../lib/errors";

export async function handleMyOrgs(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return corsJsonResponse({ error: "Unauthorized" }, 401);

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/my-orgs`, {
    method: "POST",
    headers: { "Authorization": `Bearer ${token}` },
  });

  if (!resp.ok) {
    const text = await resp.text();
    return corsJsonResponse({ error: text }, resp.status);
  }

  return corsJsonResponse(await resp.json());
}
