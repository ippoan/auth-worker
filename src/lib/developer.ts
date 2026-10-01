/**
 * 開発者アカウントの判定 (Refs ippoan/alc-app#387)。
 *
 * 使い道は 2 つで、強さが違う:
 *
 * - `isDeveloperEmail` — 画面の出し分け (dev ビルドの checkbox、鍵一覧の切替ボタン)。
 *   これだけでは何も守らない。
 * - `isDeveloperGoogleSession` — 端末の鍵を開発用にする口
 *   (`/device/setup/dev-device`、`/device/setup/alarm-key/dev-device`) のサーバ側の認可。
 *   開発用にするとその端末の記録が本番の記録簿から消え、webhook と通知も止まるため、
 *   テナントの管理者にも付けさせない。
 *
 * `lib/admin-html.ts` の同名の定数はブラウザに埋め込む script 内の表示用で、別物。
 */

/** 開発者アカウント (小文字)。 */
export const DEVELOPER_EMAILS = ["m.tama.ramu@gmail.com"];

/** email が開発者アカウントか (大文字小文字を区別しない)。空は false。 */
export function isDeveloperEmail(email: string): boolean {
  const lower = email.toLowerCase();
  return DEVELOPER_EMAILS.some((e) => e.toLowerCase() === lower);
}

/**
 * 開発者アカウントが Google でログインした session か。
 *
 * fail-closed: `tokenKind` が空 (dev ログイン・device-key の token ではない) かつ
 * `idp` が `"google"` (Google の callback が発行した token) かつ email が開発者、の
 * 3 つが揃ったときだけ true。`idp` の無い token (LINE / LINE WORKS のログイン、
 * claim を足す前に発行された cookie) は false。
 */
export function isDeveloperGoogleSession(session: {
  email: string;
  tokenKind: string;
  idp: string;
}): boolean {
  return session.tokenKind === "" && session.idp === "google" && isDeveloperEmail(session.email);
}
