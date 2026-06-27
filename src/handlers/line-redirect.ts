/**
 * LINE Login OAuth redirect (rust-alc-api#434 Phase 3)。
 *
 * notify recipient の LINE Login 開始。グローバル LINE Login channel
 * (`LINE_LOGIN_CHANNEL_ID`) で authorize URL に飛ばす。`tenant_id` は QR 招待時に
 * 指定され、callback で recipient 自動登録に使う (省略時は callback で recipients 逆引き)。
 */
import type { Env } from "../index";
import { getAllowedOrigins } from "../lib/config";
import { isAllowedRedirectUri, generateOAuthState } from "../lib/security";
import { authorizeUrl } from "../lib/line-oauth";

export async function handleLineRedirect(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const redirectUri = url.searchParams.get("redirect_uri");
  const tenantId = url.searchParams.get("tenant_id") ?? "";

  if (!redirectUri || !isAllowedRedirectUri(redirectUri, await getAllowedOrigins(env))) {
    return new Response("Invalid or missing redirect_uri", { status: 400 });
  }

  const channelId = env.LINE_LOGIN_CHANNEL_ID;
  if (!channelId) {
    return new Response("line login not configured", { status: 503 });
  }

  const signedState = await generateOAuthState(redirectUri, env.OAUTH_STATE_SECRET, {
    provider: "line",
    external_org_id: tenantId,
  });
  const callbackUri = `${url.origin}/oauth/line/callback`;
  const authorize = authorizeUrl(
    channelId,
    encodeURIComponent(callbackUri),
    encodeURIComponent(signedState),
  );
  return new Response(null, { status: 302, headers: { Location: authorize } });
}
