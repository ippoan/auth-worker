/**
 * LINE WORKS OAuth redirect — proxy to rust-alc-api
 */
import type { Env } from "../index";
import { isAllowedRedirectUri } from "../lib/security";

export async function handleLineworksRedirect(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const redirectUri = url.searchParams.get("redirect_uri");
  const address = url.searchParams.get("address");

  if (!redirectUri || !isAllowedRedirectUri(redirectUri, env.ALLOWED_REDIRECT_ORIGINS)) {
    return new Response("Invalid or missing redirect_uri", { status: 400 });
  }

  if (!address) {
    return new Response("Missing address parameter", { status: 400 });
  }

  // Extract domain from LINE WORKS address (e.g., "tanaka@ohishi" → "ohishi")
  const domain = address.includes("@") ? address.split("@")[1] : address;
  if (!domain) {
    return new Response("Invalid LINE WORKS address", { status: 400 });
  }

  console.log(JSON.stringify({ event: "lw_redirect", domain, redirectUri }));

  // Proxy to rust-alc-api lineworks redirect endpoint
  const alcUrl = new URL(`${env.ALC_API_ORIGIN}/api/auth/lineworks/redirect`);
  alcUrl.searchParams.set("domain", domain);
  alcUrl.searchParams.set("redirect_uri", redirectUri);

  const resp = await fetch(alcUrl.toString(), { redirect: "manual" });

  // Pass through the redirect response (307 + Location header)
  return new Response(resp.body, {
    status: resp.status,
    headers: resp.headers,
  });
}
