/**
 * WOFF SDK authentication endpoints
 * POST /auth/woff      — WOFF access token → JWT
 * GET  /auth/woff-config — domain → WOFF SDK ID lookup
 */

import type { Env } from "../index";
import { corsJsonResponse } from "../lib/errors";
import { isAllowedRedirectUri } from "../lib/security";
import { setAuthCookie } from "../lib/cookies";

interface WoffAuthRequest {
  accessToken: string;
  domainId: string;
  redirectUri: string;
}

export async function handleWoffAuth(
  request: Request,
  env: Env,
): Promise<Response> {
  let body: WoffAuthRequest;
  try {
    body = await request.json();
  } catch {
    return corsJsonResponse({ error: "Invalid JSON body" }, 400);
  }

  const { accessToken, domainId, redirectUri } = body;

  if (!accessToken || !domainId) {
    return corsJsonResponse({ error: "accessToken and domainId are required" }, 400);
  }

  if (!redirectUri || !isAllowedRedirectUri(redirectUri, env.ALLOWED_REDIRECT_ORIGINS)) {
    return corsJsonResponse({ error: "Invalid or missing redirect_uri" }, 400);
  }

  console.log(JSON.stringify({ event: "woff_auth", domainId }));

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/auth/woff`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      access_token: accessToken,
      domain_id: domainId,
      redirect_uri: redirectUri,
    }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    console.log(JSON.stringify({ event: "woff_auth_failure", domainId, error: text }));
    return corsJsonResponse({ error: text }, resp.status);
  }

  const data = await resp.json() as { token: string; expires_at: string };

  // Extract org_id from JWT payload
  let orgId = "";
  const payloadB64 = data.token.split(".")[1];
  if (payloadB64) {
    try {
      const payload = JSON.parse(atob(payloadB64));
      orgId = payload.tenant_id || payload.org || "";
    } catch {
      // ignore decode error
    }
  }

  console.log(JSON.stringify({ event: "woff_auth_success", domainId, orgId }));
  // Set auth cookie + return JSON with CORS headers
  const responseBody = JSON.stringify({ token: data.token, expiresAt: data.expires_at, orgId });
  return new Response(responseBody, {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Set-Cookie": setAuthCookie(data.token, new URL(request.url).hostname),
    },
  });
}

export async function handleWoffConfig(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const domain = url.searchParams.get("domain");
  if (!domain) {
    return corsJsonResponse({ error: "domain parameter required" }, 400);
  }

  console.log(JSON.stringify({ event: "woff_config", domain }));

  const resp = await fetch(
    `${env.ALC_API_ORIGIN}/api/auth/woff-config?domain=${encodeURIComponent(domain)}`,
  );

  if (!resp.ok) {
    const text = await resp.text();
    console.log(JSON.stringify({ event: "woff_config_not_found", domain }));
    return corsJsonResponse({ error: text }, resp.status);
  }

  const data = await resp.json() as { woff_id: string };
  console.log(JSON.stringify({ event: "woff_config_found", domain, woffId: data.woff_id }));
  return corsJsonResponse({ woffId: data.woff_id });
}
