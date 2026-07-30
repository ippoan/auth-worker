/**
 * workerd の `RequestInit` 検証を再現する fetch stub wrapper。
 *
 * 本 repo の test は vanilla vitest (node / undici) で走る。undici は workerd が
 * 拒否する init をそのまま受け付けるため、stub を素の `vi.fn()` で作ると
 * 「node では通るが Workers 上では fetch 前に throw する」コードを検知できない。
 *
 * 実害が出た例 (auth-worker の CIMD、#449 PR-B): `fetch(url, { redirect: "error" })` は workerd で
 *   TypeError: Invalid redirect value, must be one of "follow" or "manual"
 *   ("error" won't be implemented since it does not make sense at the edge;
 *    use "manual" and check the response status code).
 * になる。CIMD 取得がこれを try/catch で潰していたため、全 CIMD client が
 * 無言で `invalid_client` になっていた。node 側の stub は "error" を通すので
 * unit test も handler test も緑のまま prod に出た。
 *
 * fetch を stub する箇所ではこれを通すことで、同種の init 不一致を node 上で捕まえる。
 */

import { vi } from "vitest";

/** workerd が `redirect` に受け付ける値 (`"error"` は未実装)。 */
const WORKERD_REDIRECT_MODES = ["follow", "manual"];

/**
 * @param impl 実際に返す Response を作る関数 (`vi.fn().mockResolvedValue(...)` 相当)
 * @returns `vi.fn()` — `.mock.calls` / `toHaveBeenCalledWith` はそのまま使える
 */
export function workerdFetch(
  impl: (input: unknown, init?: RequestInit) => unknown,
): ReturnType<typeof vi.fn> {
  return vi.fn((input: unknown, init?: RequestInit) => {
    const redirect = init?.redirect;
    if (redirect !== undefined && !WORKERD_REDIRECT_MODES.includes(redirect)) {
      throw new TypeError(
        `Invalid redirect value, must be one of "follow" or "manual" ("error" won't be implemented since it does not make sense at the edge; use "manual" and check the response status code).`,
      );
    }
    return impl(input, init);
  });
}

/** `workerdFetch` の頻出形 — 常に同じ Response を返す stub。 */
export function workerdFetchResolving(response: () => Response): ReturnType<typeof vi.fn> {
  return workerdFetch(() => Promise.resolve(response()));
}
