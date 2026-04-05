/**
 * Password login API endpoint (REST version)
 * POST /auth/login — form data → rust-alc-api /api/auth/login → JWT → redirect
 */

import type { Env } from "../index";
import { isAllowedRedirectUri } from "../lib/security";

export async function handleAuthLogin(
  request: Request,
  env: Env,
): Promise<Response> {
  const requestUrl = new URL(request.url);

  // Parse form body
  const formData = await request.formData();
  const organizationId = formData.get("organization_id") as string | null;
  const username = formData.get("username") as string | null;
  const password = formData.get("password") as string | null;
  const redirectUri = formData.get("redirect_uri") as string | null;

  if (!redirectUri || !isAllowedRedirectUri(redirectUri, env.ALLOWED_REDIRECT_ORIGINS)) {
    return new Response("Invalid redirect_uri", { status: 400 });
  }

  if (!username || !password) {
    return redirectToLogin(requestUrl.origin, redirectUri, "Username and password are required");
  }

  console.log(JSON.stringify({ event: "login_attempt", username, orgId: organizationId }));

  // Call rust-alc-api password login endpoint
  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      organization_id: organizationId || "",
      username,
      password,
    }),
  });

  if (!resp.ok) {
    const errorText = await resp.text();
    console.log(JSON.stringify({ event: "login_failure", username, orgId: organizationId, error: errorText }));
    return redirectToLogin(requestUrl.origin, redirectUri, errorText || "Authentication failed", organizationId || undefined);
  }

  const data = (await resp.json()) as {
    access_token: string;
    expires_in: number;
  };

  // Redirect back with JWT in URL fragment
  const fragment = new URLSearchParams({
    token: data.access_token,
    expires_at: String(Math.floor(Date.now() / 1000) + data.expires_in),
  });

  // Extract org_id from JWT payload for convenience
  const payloadB64 = data.access_token.split(".")[1];
  if (payloadB64) {
    try {
      const payload = JSON.parse(atob(payloadB64));
      fragment.set("org_id", payload.tenant_id || payload.org || "");
    } catch {
      // ignore decode error
    }
  }

  console.log(JSON.stringify({ event: "login_success", username, orgId: organizationId }));
  return Response.redirect(`${redirectUri}#${fragment.toString()}`, 302);
}

function redirectToLogin(
  origin: string,
  redirectUri: string,
  error: string,
  orgId?: string,
): Response {
  const params = new URLSearchParams({
    redirect_uri: redirectUri,
    error,
  });
  if (orgId) params.set("org_id", orgId);
  return Response.redirect(`${origin}/login?${params.toString()}`, 302);
}
