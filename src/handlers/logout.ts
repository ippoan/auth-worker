/**
 * GET /logout — cookie 削除 + ログインページへリダイレクト
 */

import type { Env } from "../index";

/** 削除対象の cookie 一覧 */
const COOKIES_TO_CLEAR = [
  "sso_admin_token; Path=/admin",
  "logi_auth_token; Path=/; Domain=.mtamaramu.com",
];

export async function handleLogout(
  request: Request,
  _env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const redirectTo = url.searchParams.get("redirect_uri") || "/login";

  const headers = new Headers({ Location: redirectTo });
  for (const cookie of COOKIES_TO_CLEAR) {
    headers.append(
      "Set-Cookie",
      `${cookie}; Max-Age=0; Secure; SameSite=Lax`,
    );
  }

  return new Response(null, { status: 302, headers });
}
