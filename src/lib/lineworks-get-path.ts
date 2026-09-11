/**
 * MCP tool `lineworks_get` の宛先検証 (純関数)。
 *
 * LINE WORKS API (`https://www.worksapis.com`) への **GET だけ**を、掲示板 (`/v1.0/boards`)
 * とユーザー (`/v1.0/users`) の配下に限って通す。Service Account の token で組織全体を
 * 読める口なので、ここが緩むと任意の LINE WORKS API を叩ける汎用転送口に化ける
 * (`internal-entrypoint.ts` の path allowlist と同じ理由で coverage_100 に載せている)。
 *
 * 判定は WHATWG URL で正規化した後の pathname で行う — URL は `%2e%2e` を `..`、`\` を `/`
 * と読み、タブ・改行を捨てるため、生の文字列だけで前方一致を見ると抜けられる。その手前で
 * `%` `\` `?` `#` 空白・制御文字と `//` を丸ごと拒否し、正規化で形が変わった入力
 * (`..` / `.` セグメント) も拒否する。
 */

export const WORKS_API_ORIGIN = "https://www.worksapis.com";

/** `lineworks_get` の応答 body の上限 (verify_eval の戻り値上限と揃える)。 */
export const LINEWORKS_GET_BODY_MAX = 64 * 1024;

/** path 前方一致 → token の scope。前方一致は `=== prefix` か `prefix + "/"` だけ
 *  (`/v1.0/boardsX` を通さない)。 */
const PREFIX_SCOPES: ReadonlyArray<readonly [string, string]> = [
  ["/v1.0/boards", "board.read"],
  ["/v1.0/users", "directory.read"],
];

/** `%` `\` `?` `#`・空白・制御文字 (U+0000-U+001F, U+007F)。`-` は userId (UUID) に要るので含めない。 */
const FORBIDDEN_CHARS = /[%\\?#\s\x00-\x1f\x7f]/;

export type LineworksGetTarget =
  | { ok: true; url: string; scope: string }
  | { ok: false; error: string };

export function resolveLineworksGetTarget(path: unknown, query: unknown): LineworksGetTarget {
  if (typeof path !== "string" || !path.startsWith("/")) {
    return { ok: false, error: "path must be a string starting with /" };
  }
  if (FORBIDDEN_CHARS.test(path) || path.includes("//")) {
    return { ok: false, error: `path not allowed: ${path}` };
  }
  const url = new URL(path, WORKS_API_ORIGIN);
  // `..` / `.` セグメントは URL が畳む。畳まれて入力と変わったものは通さない。
  if (url.pathname !== path) {
    return { ok: false, error: `path not allowed: ${path}` };
  }
  const hit = PREFIX_SCOPES.find(([p]) => path === p || path.startsWith(`${p}/`));
  if (!hit) {
    return { ok: false, error: `path not allowed: ${path}` };
  }

  if (query !== undefined) {
    if (typeof query !== "object" || query === null || Array.isArray(query)) {
      return { ok: false, error: "query must be an object of string values" };
    }
    for (const [key, value] of Object.entries(query)) {
      if (typeof value !== "string") {
        return { ok: false, error: `query.${key} must be a string` };
      }
      url.searchParams.set(key, value);
    }
  }
  return { ok: true, url: url.toString(), scope: hit[1] };
}
