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
 *
 * ## returnTo は必ず auth-worker 自身へ向ける (Refs #499)
 *
 * 「自分たちのホストなら Access も知っている」は **成り立たなかった**。
 * `alc.ippoan.org` には Access アプリが 1 つも無く (bypass アプリがあったのは
 * staging の `alc-staging.ippoan.org` だけ)、放置で token が切れた後の `/logout` が
 * `returnTo=https://alc.ippoan.org/login` で chain した結果、利用者は
 * `Invalid redirect URL` (400) で行き止まりになった (2026-09-03 実測)。
 *
 * Access アプリを足して回るのは消費者ホストが増えるたびの後追いになるので、
 * **returnTo は常に auth-worker 自身の `/logout/return?to=<最終先>` へ向ける**。
 * auth-worker の origin は Access 側の設定に必ず載っている既知ホストで、
 * 最終先の `to` は中継側で同じ検証をかけてから 302 する。これで
 * 「消費者ホストが Access に登録されているか」と chain の可否が切り離される。
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

/** chain 済みマーカー cookie の名前 (Refs #477 の redirect loop)。 */
export const ACCESS_LOGOUT_CHAIN_COOKIE = "access_logout_chained";

/** マーカーの寿命 (秒)。redirect loop は数秒で 1 周するので 1 分あれば足りる。 */
export const ACCESS_LOGOUT_CHAIN_TTL_SEC = 60;

/** 直前に `/logout` を通っているか (= マーカー cookie が生きているか)。 */
export function hasAccessLogoutChainMarker(request: Request): boolean {
  const cookie = request.headers.get("Cookie") || "";
  return new RegExp(`(?:^|;\\s*)${ACCESS_LOGOUT_CHAIN_COOKIE}=1(?:;|$)`).test(cookie);
}

/** マーカーを張り直す Set-Cookie 値。`/logout` に来るたび寿命を更新する。 */
export function accessLogoutChainMarkerCookie(): string {
  return `${ACCESS_LOGOUT_CHAIN_COOKIE}=1; Path=/; Max-Age=${ACCESS_LOGOUT_CHAIN_TTL_SEC}; Secure; SameSite=Lax`;
}

/**
 * Access ログアウトからの戻りを受ける中継 endpoint の path (Refs #499)。
 *
 * `returnTo` をこの path に向けることで、最終的な戻り先が Access に登録された
 * ホストかどうかを問わなくなる。詳細はこのファイル冒頭の doc を参照。
 */
export const ACCESS_LOGOUT_RETURN_PATH = "/logout/return";

/**
 * `/logout` および `/logout/return` が飛ばしてよい戻り先か検証して URL を返す。
 *
 * 通すのは **共有 cookie の届く親ドメイン配下 (= 自分たちのホスト) の https URL**
 * だけ。相対 URL は `authOrigin` を基準に解決する。それ以外 (外部ホスト・
 * `javascript:` 等・パースできない値) は null。
 */
export function resolveLogoutReturnTarget(
  authOrigin: string,
  authHostname: string,
  redirectTo: string,
): URL | null {
  let returnTo: URL;
  try {
    returnTo = new URL(redirectTo, authOrigin);
  } catch {
    return null;
  }
  if (returnTo.protocol !== "https:") return null;
  if (!authCookieReachesHost(authHostname, returnTo.hostname)) return null;
  return returnTo;
}

/**
 * `/logout` が最後に飛ばす先を決める。
 *
 * - chain するとき: `{ target: Access のログアウト URL, chained: true }`
 * - しないとき: `{ target: redirectTo, chained: false }` (= 従来の挙動)
 *
 * chain するときの `returnTo` は **常に auth-worker 自身の
 * `/logout/return?to=<最終先>`** で、最終先へはそこから 302 で送り出す
 * (理由は冒頭の doc、Refs #499)。
 *
 * ## `recentlyChained` が要る理由 — redirect loop を 1 周で止める
 *
 * `@ippoan/auth-client` の `initAuthSession` は、auth-worker から `?lw_callback=1` で
 * 戻ったのにセッションを復元できないと **毒 cookie を捨てる目的で `/logout` を叩く**
 * (`redirectToLogin({ reauth: true })`)。これは「安く 1 回で済む掃除」の想定で書かれて
 * いるが、そこに Access ログアウトを無条件で挟むと 1 周ごとに Cloudflare Access を
 * 丸ごと往復する無限ループになる:
 *
 * ```
 * dtako/?lw_callback=1 → 復元失敗 → /logout → Access ログアウト
 *   → /login → IdP → dtako/?lw_callback=1 → 復元失敗 → …
 * ```
 *
 * そこで `/logout` を通るたびマーカー cookie を張り直し、**マーカーが生きている間は
 * chain しない**。人間が押す本物のログアウトは 1 分と空けずに二度は起きないので
 * 実害が無く、ループの側だけが 1 周で Access から切り離される。
 *
 * @param authOrigin   auth-worker 自身の origin (相対 `redirect_uri` の解決基準)
 * @param authHostname auth-worker 自身のホスト名 (親ドメイン判定に使う)
 * @param redirectTo   `?redirect_uri=` の生値。相対も絶対もあり得る
 * @param accessTeamDomain `ACCESS_TEAM_DOMAIN` var (未設定なら chain しない)
 * @param recentlyChained  直前にも `/logout` を通っているか (`hasAccessLogoutChainMarker`)
 */
export function logoutNavigationTarget(
  authOrigin: string,
  authHostname: string,
  redirectTo: string,
  accessTeamDomain: string | undefined | null,
  recentlyChained = false,
): { target: string; chained: boolean } {
  const plain = { target: redirectTo, chained: false };

  // 直前にも /logout を通っている = ループの可能性。Access は巻き込まない。
  if (recentlyChained) return plain;

  const team = normalizeAccessTeamDomain(accessTeamDomain);
  if (!team) return plain;

  const returnTo = resolveLogoutReturnTarget(authOrigin, authHostname, redirectTo);
  if (!returnTo) return plain;

  // Access に見せる returnTo は自分自身。最終先は `to` に畳んで中継へ渡す。
  let relay: URL;
  try {
    relay = new URL(ACCESS_LOGOUT_RETURN_PATH, authOrigin);
  } catch {
    return plain;
  }
  relay.searchParams.set("to", returnTo.toString());

  return {
    target: `https://${team}/cdn-cgi/access/logout?returnTo=${encodeURIComponent(relay.toString())}`,
    chained: true,
  };
}
