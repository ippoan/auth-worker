import type { Env } from "../index";
import { getAllowedOrigins } from "../lib/config";
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

  const requestOrigin = url.origin;

  // Delegate OAuth to another auth-worker (used by /wt-quick tunnel worktrees).
  // Note: wrangler dev (miniflare) rewrites Response.redirect Location headers to
  // the dev server host, so we use client-side JS redirect instead.
  if (env.LOGIN_DELEGATE_TO) {
    const selfOrigin = env.AUTH_WORKER_ORIGIN || requestOrigin;
    const target = redirectUri || `${selfOrigin}/top`;
    const params = new URLSearchParams({ redirect_uri: target });
    if (orgId) params.set("org_id", orgId);
    const loc = `${env.LOGIN_DELEGATE_TO}/login?${params.toString()}`;
    const html = `<!DOCTYPE html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=${loc}"><script>location.replace(${JSON.stringify(loc)})</script><a href="${loc}">continue to login</a>`;
    return new Response(html, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  if (!redirectUri) {
    return Response.redirect(
      `${requestOrigin}/login?redirect_uri=${encodeURIComponent(requestOrigin + "/top")}`,
      302,
    );
  }

  if (!isAllowedRedirectUri(redirectUri, await getAllowedOrigins(env))) {
    return new Response("Invalid redirect_uri", { status: 400 });
  }

  const googleEnabled = Boolean(env.GOOGLE_CLIENT_ID);
  const authOrigin = requestOrigin;
  const alcApiOrigin = env.ALC_API_ORIGIN || '';
  const googleRedirectUrl = googleEnabled
    ? `${authOrigin}/oauth/google/redirect?redirect_uri=${encodeURIComponent(redirectUri)}`
    : "";
  const lineLoginRedirectUrl = `${alcApiOrigin}/api/auth/line/redirect?redirect_uri=${encodeURIComponent(redirectUri)}`;

  console.log(JSON.stringify({ event: "login_page", redirectUri, orgId, error }));

  const html = renderLoginPage({
    redirectUri,
    orgId,
    error,
    googleEnabled,
    googleRedirectUrl,
    lineworksRedirectUrl: `${authOrigin}/oauth/lineworks/redirect`,
    lineLoginRedirectUrl,
  });

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
