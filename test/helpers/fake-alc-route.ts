/**
 * proxy の handler テスト用 — 振り分け表 (`lib/alc-backend-route.ts`) が binding を返さない path でも
 * 「転送先がある」ことにして、その転送を `globalThis.fetch` (各テストが差し替える mock) へ流す。
 * 表が binding を返す path (env に binding を置いたテスト) は本物のまま。
 *
 * 目的: proxy の認可・許可表・ヘッダ付け直しの検証を、表の行 (path ごとの binding) から切り離す
 * (表そのものの検証と「表に無い path は 404」は `alc-binding-route.test.ts` が
 * この置き換え無しで行う。W9 で Cloud Run 退避を撤去した後は転送先が binding だけなので、
 * 任意 path の転送を観測するにはこの置き換えが要る)。
 * 呼び出しは `vi.mock("../../src/lib/alc-backend-route", async (orig) =>
 *   (await import("../helpers/fake-alc-route")).fakeAlcRouteFactory(await orig<object>()))`
 * (vi.mock は巻き上げられるので、factory の中で動的 import する)。
 */
import type { Env } from "../../src/index";
import type * as Route from "../../src/lib/alc-backend-route";

/** mock された転送先 (URL の origin だけ固定。テストは `https://alc-api.test.example${path}` で照合する)。 */
export const FAKE_BACKEND_ORIGIN = "https://alc-api.test.example";

export function fakeAlcRouteFactory(actual: object): typeof Route {
  const real = actual as typeof Route;
  return {
    ...real,
    resolveAlcBinding: (path: string, env: Env, proxy: Route.AlcProxyKind, method?: string) =>
      real.resolveAlcBinding(path, env, proxy, method) ?? {
        host: "fake-backend",
        fetcher: {
          fetch: (url: string, init?: RequestInit) => {
            const u = new URL(url);
            return globalThis.fetch(`${FAKE_BACKEND_ORIGIN}${u.pathname}${u.search}`, init);
          },
        } as unknown as Fetcher,
      },
  };
}
