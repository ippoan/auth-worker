/**
 * Cookie helpers for logi_auth_token
 */

export const AUTH_COOKIE = "logi_auth_token";

/**
 * 旧 admin 画面が使っていた cookie 名 (Path=/admin)。現在は発行しておらず
 * `/logout` が破棄するだけだが、admin ページの門番 (`admin-auth-script.ts`) が
 * 後方互換で読むため定数として持つ (ページ JS 側にハードコードを増やさない)。
 */
export const LEGACY_ADMIN_COOKIE = "sso_admin_token";

/**
 * Set-Cookie header value for auth token (shared across subdomains).
 *
 * `maxAgeSec` は既定 86400 (24h、Google login 等の既存挙動)。issue #522
 * (device-login) は JWT の TTL (3600s) を超えて cookie を生かさないよう
 * ここへ実際の残り秒数を渡す。
 */
export function setAuthCookie(token: string, hostname: string, maxAgeSec = 86400): string {
  const domain = getParentDomain(hostname);
  return `${AUTH_COOKIE}=${token}; Domain=${domain}; Path=/; Max-Age=${maxAgeSec}; Secure; SameSite=Lax`;
}

/** Set-Cookie header value to clear auth token */
export function clearAuthCookie(hostname: string): string {
  const domain = getParentDomain(hostname);
  return `${AUTH_COOKIE}=; Domain=${domain}; Path=/; Max-Age=0; Secure; SameSite=Lax`;
}

/** Extract parent domain from hostname (e.g. auth.ippoan.org → .ippoan.org) */
function getParentDomain(hostname: string): string {
  const parts = hostname.split(".");
  return parts.length > 2 ? "." + parts.slice(-2).join(".") : hostname;
}

/**
 * 共有 auth cookie (logi_auth_token, Domain=親ドメイン) が target host にも届くか。
 * true の場合、OAuth callback は token を URL fragment に載せず cookie だけで渡せる
 * (= アドレスバー/履歴に token を出さない)。false の場合は fragment 配布が必要
 * (例: `*.workers.dev` / `*.pages.dev` は public suffix で Domain cookie が設定不可)。
 *
 * 判定: auth-worker host と target host が同じ親ドメイン配下で、その親ドメインが
 * public suffix でないこと。
 */
const PUBLIC_SUFFIX_PARENTS = [".workers.dev", ".pages.dev"];

export function authCookieReachesHost(authHostname: string, targetHostname: string): boolean {
  const domain = getParentDomain(authHostname);
  if (!domain.startsWith(".")) return false; // 単一ラベル / localhost 等は共有 cookie 不可
  if (PUBLIC_SUFFIX_PARENTS.includes(domain)) return false; // public suffix → Domain cookie 拒否
  return targetHostname === domain.slice(1) || targetHostname.endsWith(domain);
}

/** Extract auth token from request Cookie header */
export function getAuthCookie(request: Request): string | null {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/logi_auth_token=([^;]+)/);
  return match?.[1] ?? null;
}

/**
 * 同名 cookie (logi_auth_token) を **全て** 返す (Refs #387)。
 *
 * host-only cookie と Domain 付き cookie は別物としてブラウザが両方送るため、
 * 古い方が先頭に来ると `getAuthCookie` (先頭のみ) では有効な cookie が
 * 陰に隠れる (shadowing)。login-gated ページは全候補を verify すること。
 */
export function getAuthCookies(request: Request): string[] {
  const cookie = request.headers.get("Cookie") || "";
  const out: string[] = [];
  const re = /logi_auth_token=([^;]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(cookie)) !== null) out.push(m[1]!);
  return out;
}

/**
 * 検証に落ちた cookie の自動破棄用 Set-Cookie 群 (Refs #387)。
 *
 * setAuthCookie は Domain=親ドメインで set するが、過去版や別経路が残した
 * host-only cookie も同時に破棄できるよう **Domain 付き / 無しの両方**を返す。
 * 毒 cookie (期限切れ / env claim 不一致 / 署名不正) を手動 logout に頼らず
 * 回収するため、login-gated ページの「cookie 有り + 検証全滅」応答に付ける。
 */
export function clearAuthCookieVariants(hostname: string): string[] {
  return [
    clearAuthCookie(hostname),
    `${AUTH_COOKIE}=; Path=/; Max-Age=0; Secure; SameSite=Lax`,
  ];
}

/**
 * /top ↔ /login の往復回数と、直前に /top が弾いた理由を /login のログへ運ぶ
 * 短命 cookie (Refs #526)。値は `<count>:<reason>`。
 *
 * host-only (Domain 無し) にする: /top と /login は同一 host で、配下アプリへ
 * 送出する必要が無い。書き方は access-logout.ts の chain marker と同型。
 * 挙動 (redirect / cookie 破棄 / 画面) には一切関与せず、ログ専用。
 */
export const BOUNCE_COOKIE = "logi_bounce";

/** 寿命 (秒)。往復は数秒で 1 周するので 2 分あれば連続バウンスを繋げられる。 */
export const BOUNCE_TTL_SEC = 120;

export type BounceReason = "no_cookie" | "expired" | "env_mismatch" | "invalid" | "no_org";

const BOUNCE_REASONS: readonly BounceReason[] = [
  "no_cookie",
  "expired",
  "env_mismatch",
  "invalid",
  "no_org",
];

/** 往復 cookie を読む。無い・壊れている (count が非数 / reason が未知) なら null。 */
export function getBounce(
  request: Request,
): { count: number; reason: BounceReason | null } | null {
  const cookie = request.headers.get("Cookie") || "";
  const m = new RegExp(`(?:^|;\\s*)${BOUNCE_COOKIE}=([^;]*)`).exec(cookie);
  if (!m) return null;
  const [countRaw, reasonRaw] = m[1]!.split(":");
  if (!/^\d{1,6}$/.test(countRaw ?? "")) return null;
  const reason = BOUNCE_REASONS.find((r) => r === reasonRaw) ?? null;
  return { count: Number(countRaw), reason };
}

/** 往復 cookie を張る Set-Cookie 値 (count は「今回で何回目か」)。 */
export function setBounceCookie(count: number, reason: BounceReason): string {
  return `${BOUNCE_COOKIE}=${count}:${reason}; Path=/; Max-Age=${BOUNCE_TTL_SEC}; Secure; SameSite=Lax`;
}

/** 往復 cookie を消す Set-Cookie 値 (/top が正常描画したら計数をリセット)。 */
export function clearBounceCookie(): string {
  return `${BOUNCE_COOKIE}=; Path=/; Max-Age=0; Secure; SameSite=Lax`;
}
