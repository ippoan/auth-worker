/**
 * ログイン後段の共通処理 (issue #522)。
 *
 * 元は `google-callback.ts` の一部だった (ACL 2 段 → join 分岐 → cookie /
 * fragment 配布)。VoiceS3R の ed25519 署名で認証する device-login
 * (`handlers/device-login.ts`) も **mint 済みの token を持って** ここに合流する
 * ため、handler から切り出して共有 helper にした (移動であって削減ではない —
 * google-callback.ts 側の行数がそのまま新設ファイルに移る)。
 *
 * 入口は「token は既に mint 済み」であること。Google のように IdP から
 * identity を取ってくる部分・device-key のように署名を検証する部分は、
 * それぞれの handler の責務のまま (ここでは扱わない)。
 */
import type { Env } from "../index";
import { checkOrgAccess, checkAppTenant } from "./acl";
import { setAuthCookie, authCookieReachesHost } from "./cookies";

export interface FinishLoginParams {
  /** mint 済み access JWT (`createAccessToken` / device-login の inline `signJwt` 等)。 */
  token: string;
  /** `token` の失効時刻 (unix 秒、文字列)。URL fragment の `expires_at` に載る。 */
  expiresAt: string;
  tenantId: string;
  email: string;
  redirectUri: string;
  /** Google の join flow (`/join/:slug/done` へ redirect)。device-login は渡さない。 */
  joinOrg?: string;
  /** cookie の Max-Age (秒)。省略時は `setAuthCookie` の既定 (86400 = 24h、Google 既存挙動)。
   *  device-login は JWT の実 TTL (3600s) を渡し、cookie が token の失効より長生きしないようにする。 */
  cookieMaxAgeSec?: number;
  /** ログ event 名の prefix (`<prefix>_acl_denied` 等)。呼び出し元ごとに区別する。 */
  eventPrefix: string;
}

/**
 * ACL 2 段 (`checkOrgAccess` → `checkAppTenant`) → (join があれば) join 分岐 →
 * cookie (共有 cookie が届く host) / fragment fallback (届かない host) → 302。
 *
 * 401/403 系の判定は無い — token が既に mint 済みという前提のため、呼び出し元が
 * 認証 (署名検証 / IdP 応答検証) を済ませてから呼ぶこと。
 */
export async function finishLogin(
  request: Request,
  env: Env,
  params: FinishLoginParams,
): Promise<Response> {
  const { token, expiresAt, tenantId, email, redirectUri, joinOrg, cookieMaxAgeSec, eventPrefix } =
    params;
  const url = new URL(request.url);
  const origin = url.origin;
  const authHostname = url.hostname;

  const fragment = new URLSearchParams({ token, expires_at: expiresAt });
  if (tenantId) fragment.set("org_id", tenantId);

  // Enforce per-org ACL for the final redirect target.
  const redirectOrigin = new URL(redirectUri).origin;
  if (!(await checkOrgAccess(env, redirectOrigin, tenantId, email))) {
    console.log(
      JSON.stringify({ event: `${eventPrefix}_acl_denied`, redirectUri, tenantId, email }),
    );
    return new Response("このアプリへのアクセスが許可されていません", { status: 403 });
  }
  // Per-app tenant partitioning (after org ACL).
  if (!checkAppTenant(env, redirectOrigin, tenantId, email)) {
    console.log(
      JSON.stringify({ event: `${eventPrefix}_app_tenant_denied`, redirectUri, tenantId, email }),
    );
    return new Response("このアカウントはこのアプリにアクセスできません", { status: 403 });
  }

  // Join flow: redirect to /join/:slug/done with JWT fragment.
  if (joinOrg) {
    const joinDoneUrl = new URL(`${origin}/join/${joinOrg}/done`);
    console.log(JSON.stringify({ event: `${eventPrefix}_join`, joinOrg }));
    return new Response(null, {
      status: 302,
      headers: {
        Location: `${joinDoneUrl.toString()}#${fragment.toString()}`,
        "Set-Cookie": setAuthCookie(token, authHostname, cookieMaxAgeSec),
      },
    });
  }

  // Normal flow: redirect back to original redirect_uri.
  const finalUrl = new URL(redirectUri);

  // 共有 cookie (logi_auth_token, Domain=.ippoan.org) が redirect 先に届くなら、
  // token を URL fragment に載せず cookie だけで渡す (アドレスバー/履歴に token を出さない)。
  // 届かない host (例: *.workers.dev は public suffix で Domain cookie 不可) は従来どおり
  // fragment で配布する (consumeFragment で受ける)。
  if (authCookieReachesHost(authHostname, finalUrl.hostname)) {
    console.log(JSON.stringify({ event: `${eventPrefix}_success`, redirectUri, delivery: "cookie" }));
    return new Response(null, {
      status: 302,
      headers: {
        Location: finalUrl.toString(),
        "Set-Cookie": setAuthCookie(token, authHostname, cookieMaxAgeSec),
      },
    });
  }

  // Fallback: cookie が届かない host へは fragment で渡す。
  if (!finalUrl.searchParams.has("lw_callback")) {
    finalUrl.searchParams.set("lw_callback", "1");
  }
  console.log(JSON.stringify({ event: `${eventPrefix}_success`, redirectUri, delivery: "fragment" }));
  return new Response(null, {
    status: 302,
    headers: {
      Location: `${finalUrl.toString()}#${fragment.toString()}`,
      "Set-Cookie": setAuthCookie(token, authHostname, cookieMaxAgeSec),
    },
  });
}
