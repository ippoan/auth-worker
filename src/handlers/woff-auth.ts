/**
 * WOFF SDK authentication endpoints
 * POST /auth/woff      — WOFF access token → JWT
 * GET  /auth/woff-config — domain → WOFF SDK ID lookup
 */

import type { Env } from "../index";
import { alcOidcToken } from "../lib/alc-data-fetch";
import { getAllowedOrigins } from "../lib/config";
import { checkOrgAccess, checkAppTenant } from "../lib/acl";
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

  if (!redirectUri || !isAllowedRedirectUri(redirectUri, await getAllowedOrigins(env))) {
    return corsJsonResponse({ error: "Invalid or missing redirect_uri" }, 400);
  }

  console.log(JSON.stringify({ event: "woff_auth", domainId }));

  // #434 lockdown: rust は allUsers 削除後 Google OIDC (aud=ALC_API_ORIGIN) を要求する。
  // mint 不可 (SA key 未設定 = lockdown 前) は Authorization 無しで fail-open。
  const oidc = await alcOidcToken(env);
  const woffHeaders: Record<string, string> = { "Content-Type": "application/json" };
  if (oidc) woffHeaders.Authorization = `Bearer ${oidc}`;
  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/auth/woff`, {
    method: "POST",
    headers: woffHeaders,
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

  // Extract org_id + email from JWT payload
  let orgId = "";
  let email = "";
  const payloadB64 = data.token.split(".")[1];
  if (payloadB64) {
    try {
      const payload = JSON.parse(atob(payloadB64));
      orgId = payload.tenant_id || payload.org || "";
      email = payload.email || "";
    } catch {
      // ignore decode error
    }
  }

  // Enforce per-org ACL. WOFF returns JSON, so reject with CORS JSON.
  const redirectOrigin = new URL(redirectUri).origin;
  if (!(await checkOrgAccess(env, redirectOrigin, orgId, email))) {
    console.log(JSON.stringify({ event: "woff_auth_acl_denied", domainId, orgId, email }));
    return corsJsonResponse({ error: "このアプリへのアクセスが許可されていません" }, 403);
  }
  // Per-app tenant partitioning (after org ACL).
  if (!checkAppTenant(env, redirectOrigin, orgId, email)) {
    console.log(JSON.stringify({ event: "woff_auth_app_tenant_denied", domainId, orgId, email }));
    return corsJsonResponse({ error: "このアカウントはこのアプリにアクセスできません" }, 403);
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

  // #434 lockdown: rust は allUsers 削除後 Google OIDC (aud=ALC_API_ORIGIN) を要求する。
  // mint 不可 (SA key 未設定 = lockdown 前) は Authorization 無しで fail-open。
  const configOidc = await alcOidcToken(env);
  const resp = await fetch(
    `${env.ALC_API_ORIGIN}/api/auth/woff-config?domain=${encodeURIComponent(domain)}`,
    configOidc ? { headers: { Authorization: `Bearer ${configOidc}` } } : undefined,
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
