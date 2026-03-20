import type { Env } from "../index";
import { isAllowedRedirectUri } from "../lib/security";
import { renderLoginPage } from "../lib/html";

export async function handleLoginPage(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const redirectUri = url.searchParams.get("redirect_uri");
  const orgId = url.searchParams.get("org_id") || undefined;
  const error = url.searchParams.get("error") || undefined;

  if (!redirectUri) {
    return Response.redirect(
      `${env.AUTH_WORKER_ORIGIN}/login?redirect_uri=${encodeURIComponent(env.AUTH_WORKER_ORIGIN + "/top")}`,
      302,
    );
  }

  if (!isAllowedRedirectUri(redirectUri, env.ALLOWED_REDIRECT_ORIGINS)) {
    return new Response("Invalid redirect_uri", { status: 400 });
  }

  const googleEnabled = Boolean(env.GOOGLE_CLIENT_ID);
  const alcApiOrigin = env.ALC_API_ORIGIN || '';
  const googleRedirectUrl = googleEnabled
    ? `${alcApiOrigin}/api/auth/google/redirect?redirect_uri=${encodeURIComponent(redirectUri)}`
    : "";

  console.log(JSON.stringify({ event: "login_page", redirectUri, orgId, error }));

  const html = renderLoginPage({
    redirectUri,
    orgId,
    error,
    googleEnabled,
    googleRedirectUrl,
    lineworksRedirectUrl: `${alcApiOrigin}/api/auth/lineworks/redirect`,
  });

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
