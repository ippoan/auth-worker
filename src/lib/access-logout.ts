/**
 * `/logout` から Cloudflare Access のログアウトへ chain するための URL 組み立て
 * (Refs #477)。
 *
 * ## なぜ必要か
 *
 * `logi_auth_token` を捨てただけでは **Access のセッション (24h) が生き残る**。
 * Access に守られたアプリ (`dtako.ippoan.org`) へ戻ると Access は既存セッションで
 * 無言に通し、その先の `/oidc/authorize` も (cookie を消した直後なので) `/login` に
 * 落ちる — つまり「ログアウトしたのに Access だけ入ったまま」の中途半端な状態になる。
 * 逆に Access だけログアウトしても auth-worker の cookie が残っていれば
 * `/oidc/authorize` が silent に通してしまい、こちらも「再ログイン」にならない。
 *
 * **順序は auth-worker → Access で固定**。先に Access を切ると、Access からの
 * 戻り先を auth-worker の `/logout` に向けることになり手順が逆立ちする。
 *
 * ## `returnTo` の制約 (2026-08-26 実測)
 *
 * `https://<team>.cloudflareaccess.com/cdn-cgi/access/logout?returnTo=<url>` は
 * **Access が知っているホスト名にしか戻さない**:
 *
 * ```
 * returnTo=https://dtako.ippoan.org/    → 302 Location: https://dtako.ippoan.org/
 * returnTo=https://auth.ippoan.org/login → 302 Location: https://auth.ippoan.org/login
 * returnTo=https://example.com/evil     → 400
 * returnTo=http://localhost:3000/       → 400
 * returnTo 無し                          → 200 (CF の汎用ログアウト完了ページ)
 * ```
 *
 * 400 に落ちると「ログアウト後に CF のエラーページで行き止まり」になるので、
 * **戻り先が共有 cookie の届く親ドメイン配下 (= 自分たちのホスト) の https URL の
 * ときだけ chain する**。それ以外 (`*.pages.dev` 消費者・相対でない外部 URL など) は
 * 従来どおり素直にその URL へ飛ばす (非破壊)。
 */

import { authCookieReachesHost } from "./cookies";

/**
 * `ACCESS_TEAM_DOMAIN` var を裸のホスト名に正規化する。
 *
 * `https://` 付き / 末尾スラッシュ付きで書かれても受け取るが、path や port を
 * 含むような値は **null** にして chain 自体を諦める (誤設定で利用者を知らない場所へ
 * 飛ばさないため)。
 */
export function normalizeAccessTeamDomain(raw: string | undefined | null): string | null {
  const trimmed = (raw ?? "").trim().replace(/\/+$/, "");
  if (!trimmed) return null;
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    return null;
  }
  // host !== hostname は port 付き。pathname が "/" 以外なら path 付き。
  if (parsed.host !== parsed.hostname) return null;
  if (parsed.pathname !== "/") return null;
  if (!parsed.hostname.includes(".")) return null;
  return parsed.hostname;
}

/**
 * `/logout` が最後に飛ばす先を決める。
 *
 * - chain できるとき: Access のログアウト URL (戻り先 = 本来の遷移先)
 * - できないとき: `redirectTo` をそのまま (= 従来の挙動)
 *
 * @param authOrigin   auth-worker 自身の origin (相対 `redirect_uri` の解決基準)
 * @param authHostname auth-worker 自身のホスト名 (親ドメイン判定に使う)
 * @param redirectTo   `?redirect_uri=` の生値。相対も絶対もあり得る
 * @param accessTeamDomain `ACCESS_TEAM_DOMAIN` var (未設定なら chain しない)
 */
export function logoutNavigationTarget(
  authOrigin: string,
  authHostname: string,
  redirectTo: string,
  accessTeamDomain: string | undefined | null,
): string {
  const team = normalizeAccessTeamDomain(accessTeamDomain);
  if (!team) return redirectTo;

  let returnTo: URL;
  try {
    returnTo = new URL(redirectTo, authOrigin);
  } catch {
    return redirectTo;
  }
  // Access の returnTo は https のみ。http/javascript: 等は chain せず素通し。
  if (returnTo.protocol !== "https:") return redirectTo;
  // 自分たちのホストでない戻り先は Access が 400 で弾く → chain しない。
  if (!authCookieReachesHost(authHostname, returnTo.hostname)) return redirectTo;

  return `https://${team}/cdn-cgi/access/logout?returnTo=${encodeURIComponent(returnTo.toString())}`;
}
