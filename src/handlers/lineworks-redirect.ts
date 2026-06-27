/**
 * LINE WORKS OAuth redirect (rust-alc-api#434 Phase 2)。
 *
 * 旧実装は rust-alc-api `/api/auth/lineworks/redirect` への proxy だったが、認証
 * オーケストレーションを auth-worker に移管。SSO 設定は rust internal endpoint で
 * 解決し、authorize URL の構築 + state 署名は auth-worker 側で行う。
 */
import type { Env } from "../index";
import { getAllowedOrigins } from "../lib/config";
import { isAllowedRedirectUri, generateOAuthState } from "../lib/security";
import { resolveSsoConfig } from "../lib/alc-internal";
import { authorizeUrl } from "../lib/lineworks-oauth";

export async function handleLineworksRedirect(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const redirectUri = url.searchParams.get("redirect_uri");
  const address = url.searchParams.get("address");
  const domainParam = url.searchParams.get("domain");

  if (!redirectUri || !isAllowedRedirectUri(redirectUri, await getAllowedOrigins(env))) {
    return new Response("Invalid or missing redirect_uri", { status: 400 });
  }

  // domain は明示 param、無ければ address (user@domain) から抽出。
  const domain = domainParam || (address?.includes("@") ? address.split("@")[1] : address);
  if (!domain) {
    return new Response("Missing domain or address parameter", { status: 400 });
  }

  const config = await resolveSsoConfig(env, "lineworks", domain);
  if (!config) {
    console.log(JSON.stringify({ event: "lw_redirect_no_sso_config", domain }));
    return new Response("No SSO config found for domain", { status: 404 });
  }

  // state に provider + external_org_id を載せる (callback で sso-config を再解決するため)。
  const signedState = await generateOAuthState(redirectUri, env.OAUTH_STATE_SECRET, {
    provider: "lineworks",
    external_org_id: config.external_org_id,
  });

  // callback は auth-worker 自身 (旧: rust)。LINE WORKS console の redirect_uri 登録もこれに合わせる。
  const callbackUri = `${url.origin}/oauth/lineworks/callback`;
  const authorize = authorizeUrl(
    config.client_id,
    encodeURIComponent(callbackUri),
    encodeURIComponent(signedState),
  );

  console.log(JSON.stringify({ event: "lw_redirect", domain, redirectUri }));
  return new Response(null, { status: 302, headers: { Location: authorize } });
}
