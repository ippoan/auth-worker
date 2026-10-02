import type { Env } from "../index";

/** 表を引く proxy の種別 (画面用 = alc-proxy / 内部用 = alc-internal-proxy / 端末用 = device-data-proxy)。 */
export type AlcProxyKind = "browser" | "internal" | "device";

/** 振り分け表の 1 行。 */
export interface AlcBindingRoute {
  /** `prefix` = `path` (末尾 `/` 付き) で始まる、または末尾 `/` を外した値と完全一致。`exact` = 完全一致だけ。 */
  match: "prefix" | "exact";
  path: string;
  binding: keyof Env;
  /** 転送先 URL の host (ダミー。binding は URL の host で経路が決まらない)。 */
  host: string;
  /** この行を引いてよい proxy。ここに無い proxy から引いたときは、従来どおり Cloud Run。 */
  proxies: ReadonlyArray<AlcProxyKind>;
}

/**
 * rust-alc-api (Cloud Run monolith) を domain 別 Worker へ段階移行する (strangler) ための
 * 振り分け表。各 proxy が認証・ACL・ヘッダ付け直しを終えた後、backendPath がここに一致し、
 * その proxy が行の `proxies` に入っていて、かつ env に binding が定義されていれば Service Binding へ流す。
 * worker を足すときは、この表に行を足す (Env 型にも binding を足す)。
 *
 * `/api/upload` を完全一致にしているのは、下位の path (`/api/upload/…`) が別の口だから。
 * `/api/uploads`・`/api/internal/pending`・`/api/internal/download/…`・`/api/internal/rerun/…` は、アップロード履歴の
 * 読み取りと、やり直しの口。`alc-dtako` へ回すのは画面用の proxy だけ。
 */
export const ALC_BINDING_ROUTES: ReadonlyArray<AlcBindingRoute> = [
  { match: "prefix", path: "/api/vein/", binding: "ALC_VEIN", host: "alc-vein", proxies: ["browser", "device"] },
  { match: "exact", path: "/api/upload", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser", "internal"] },
  { match: "prefix", path: "/api/split-csv/", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/split-csv-all", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/uploads", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/internal/pending", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "prefix", path: "/api/internal/download/", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "prefix", path: "/api/internal/rerun/", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
];

/** 転送先 (Service Binding と、URL に使うダミーの host)。 */
export interface AlcBindingTarget {
  fetcher: Fetcher;
  host: string;
}

function matchesRoute(route: AlcBindingRoute, backendPath: string): boolean {
  if (route.match === "exact") return backendPath === route.path;
  return backendPath === route.path.replace(/\/$/, "") || backendPath.startsWith(route.path);
}

/**
 * backendPath に対応する転送先を返す。表の行に一致し、`proxy` がその行を引いてよく、かつ binding が
 * 定義されているときだけ返す (どれかが欠ければ null = 従来どおり Cloud Run)。method は見ない。
 */
export function resolveAlcBinding(
  backendPath: string,
  env: Env,
  proxy: AlcProxyKind,
): AlcBindingTarget | null {
  for (const route of ALC_BINDING_ROUTES) {
    if (!matchesRoute(route, backendPath)) continue;
    if (!route.proxies.includes(proxy)) return null;
    const fetcher = env[route.binding] as Fetcher | undefined;
    return fetcher ? { fetcher, host: route.host } : null;
  }
  return null;
}

/** cf-flickr-cam-worker-proxy と同じ defense-in-depth (decode 後に別 path へ化けるのを防ぐ)。 */
export function isUnsafeBackendPath(backendPath: string): boolean {
  return backendPath.includes("%") || backendPath.includes("..") || backendPath.includes("\\");
}

/**
 * Service Binding 経由の転送。付け直し済みヘッダ (Authorization = Cloud Run 用 OIDC は
 * 含めない) と body をそのまま渡す。`redirect: "manual"` は cf-flickr と同じ理由 (binding 先の
 * 自己再呼び出し防止)。URL の host は表の行のダミーの値 (binding は URL の host で経路が決まらない)。
 */
export function forwardViaAlcBinding(
  target: AlcBindingTarget,
  backendPath: string,
  search: string,
  init: { method: string; headers: Record<string, string>; body: BodyInit | undefined },
): Promise<Response> {
  return target.fetcher.fetch(`https://${target.host}${backendPath}${search}`, {
    method: init.method,
    headers: init.headers,
    body: init.body,
    redirect: "manual",
  });
}
