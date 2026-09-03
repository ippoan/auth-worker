/**
 * GET /logout/return — Cloudflare Access のログアウトからの戻りを最終先へ送り出す
 * 中継 (Refs #499)。
 *
 * Access の `returnTo` は **Access が知っているホスト名にしか戻さない**ため、
 * 消費者アプリの URL を直接渡すと、そのホストに Access アプリが無い場合に
 * `Invalid redirect URL` (400) で行き止まりになる。そこで `/logout` は returnTo を
 * 常にこの endpoint (= auth-worker 自身 = Access の既知ホスト) に向け、最終先は
 * `?to=` に畳んで渡す。経緯と制約は `src/lib/access-logout.ts` の doc を参照。
 *
 * `to` は **auth-worker と共有 cookie を持つ親ドメイン配下の https URL** のときだけ
 * 通す (open redirect 防止)。外部ホスト・非 https・壊れた値は `/login` に落とす。
 */

import { resolveLogoutReturnTarget } from "../lib/access-logout";

export function handleLogoutReturn(request: Request): Response {
  const url = new URL(request.url);
  const to = url.searchParams.get("to") || "/login";
  const target = resolveLogoutReturnTarget(url.origin, url.hostname, to);
  return new Response(null, {
    status: 302,
    headers: {
      Location: target ? target.toString() : "/login",
      // 中継結果は利用者ごとに違う。CDN にも履歴にも残さない。
      "Cache-Control": "no-store",
    },
  });
}
