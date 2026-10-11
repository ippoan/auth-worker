import type { Env } from "../index";

/**
 * 表を引く proxy の種別 (画面用 = alc-proxy / 内部用 = alc-internal-proxy / 端末用 = device-data-proxy /
 * 管理画面用 = admin-notify-api・api-line-users)。
 */
export type AlcProxyKind = "browser" | "internal" | "device" | "admin";

/** 振り分け表の 1 行の一致のさせ方。 */
export type AlcRouteMatch =
  /** `path` (末尾 `/` 付き) で始まる、または末尾 `/` を外した値と完全一致。 */
  | { match: "prefix"; path: string }
  /** 完全一致だけ。 */
  | { match: "exact"; path: string }
  /** 正規表現 (先頭 `^`・末尾 `$` で固定する)。id を挟む口を、id の形まで含めて拾うときに使う。 */
  | { match: "pattern"; pattern: RegExp };

/** 振り分け表の 1 行。 */
export type AlcBindingRoute = AlcRouteMatch & {
  binding: keyof Env;
  /** 転送先 URL の host (ダミー。binding は URL の host で経路が決まらない)。 */
  host: string;
  /** この行を引いてよい proxy。ここに無い proxy から引いたときは、従来どおり Cloud Run。 */
  proxies: ReadonlyArray<AlcProxyKind>;
};

/**
 * rust-alc-api (Cloud Run monolith) を domain 別 Worker へ段階移行する (strangler) ための
 * 振り分け表。各 proxy が認証・ACL・ヘッダ付け直しを終えた後、backendPath がここに一致し、
 * その proxy が行の `proxies` に入っていて、かつ env に binding が定義されていれば Service Binding へ流す。
 * worker を足すときは、この表に行を足す (Env 型にも binding を足す)。
 *
 * `/api/upload` を完全一致にしているのは、下位の path (`/api/upload/…`) が別の口だから。
 * `/api/uploads`・`/api/internal/pending`・`/api/internal/download/…`・`/api/internal/rerun/…` は、アップロード履歴の
 * 読み取りと、やり直しの口。`alc-dtako` へ回すのは画面用の proxy だけ。
 * `/api/recalculate`・`/api/recalculate-driver`・`/api/recalculate-drivers` は再計算の 3 口 (完全一致)。`alc-dtako` へ回すのは画面用の proxy だけ。
 * `/api/recalculate-pending` は「要再計算」の印が付いた 乗務員 × 月 をまとめて計算し直す口 (完全一致)。画面のアップロード後と、取り込みの一区切りの relay (内部用) の両方から呼ぶ。
 * `/api/leave/` は勤怠申請 (休暇・遅刻などの申請) の管理 API (prefix)。管理画面からだけ呼ぶので `alc-leave` へ回すのは画面用の proxy だけ
 * (端末用・内部用は入れない。メール受信の取り込みは、この表を通らず email-receiver から直接 Service Binding で呼ぶ)。
 * `/api/internal/lineworks/send` は LINE WORKS への通知の送信 (完全一致)。内部用の proxy (internal-jwt クラス) と端末通知
 * (`device-notify-send.ts`、同じく `internal` として引く) から `alc-lineworks` へ回す。
 * `/api/lineworks/deploy-check` は本番デプロイ後の確認の通知 (完全一致)。画面用の proxy (/alc-proxy) だけ `alc-lineworks` へ回す。
 * method はこの表では絞らない (worker 側が GET しか受けない)。
 * `/api/notify/` の宛先・グループ・LINE の設定・LINE WORKS のトークルームとメンバー・試し配信は `alc-notify` へ回す
 * (画面用と、Cloud Run を直に叩いていた管理画面用の 2 つ)。文書の配信は id を UUID に固定した pattern で、画面用だけ。
 * `/api/notify/documents/` と `/api/notify/lineworks/` の prefix は足さない (文書の他の口・ingest・viewer・LINE の webhook・
 * 既読の記録は Cloud Run に残る)。
 * `/api/trouble/` は trouble の全部の口 (prefix)。worker が rust の口を全部持つので丸ごと `alc-trouble` へ回す。画面用の proxy だけ
 * (nuxt-trouble は /alc-proxy 経由)。予約の発火 (`/api/internal/trouble/schedules/{id}/fire`) は id を UUID に固定した pattern で、
 * 内部用の proxy (internal-jwt クラス。大小文字は alc-internal-proxy の分類と揃える) だけ。
 * カメラ停止の自動チケット (`/api/internal/trouble/camera-down-tickets`) は完全一致で、内部用の proxy (shared-secret クラス) だけ。
 */
export const ALC_BINDING_ROUTES: ReadonlyArray<AlcBindingRoute> = [
  { match: "prefix", path: "/api/vein/", binding: "ALC_VEIN", host: "alc-vein", proxies: ["browser", "device"] },
  { match: "exact", path: "/api/upload", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser", "internal", "device"] },
  { match: "prefix", path: "/api/split-csv/", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/split-csv-all", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/uploads", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/internal/pending", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "prefix", path: "/api/internal/download/", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "prefix", path: "/api/internal/rerun/", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/recalculate", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/recalculate-driver", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/recalculate-drivers", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/recalculate-pending", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser", "internal"] },
  { match: "prefix", path: "/api/leave/", binding: "ALC_LEAVE", host: "rust-leave", proxies: ["browser"] },
  { match: "exact", path: "/api/internal/lineworks/send", binding: "ALC_LINEWORKS", host: "alc-lineworks", proxies: ["internal"] },
  { match: "exact", path: "/api/lineworks/deploy-check", binding: "ALC_LINEWORKS", host: "alc-lineworks", proxies: ["browser"] },
  { match: "prefix", path: "/api/notify/recipients/", binding: "ALC_NOTIFY", host: "alc-notify", proxies: ["browser", "admin"] },
  { match: "prefix", path: "/api/notify/groups/", binding: "ALC_NOTIFY", host: "alc-notify", proxies: ["browser", "admin"] },
  { match: "prefix", path: "/api/notify/lineworks/channels/", binding: "ALC_NOTIFY", host: "alc-notify", proxies: ["browser", "admin"] },
  { match: "exact", path: "/api/notify/line-config", binding: "ALC_NOTIFY", host: "alc-notify", proxies: ["browser", "admin"] },
  { match: "exact", path: "/api/notify/lineworks/users", binding: "ALC_NOTIFY", host: "alc-notify", proxies: ["browser", "admin"] },
  { match: "exact", path: "/api/notify/lineworks/login-activity", binding: "ALC_NOTIFY", host: "alc-notify", proxies: ["browser", "admin"] },
  { match: "exact", path: "/api/notify/test-distribute", binding: "ALC_NOTIFY", host: "alc-notify", proxies: ["browser", "admin"] },
  {
    match: "pattern",
    pattern: /^\/api\/notify\/documents\/[0-9a-f-]{36}\/distribute$/,
    binding: "ALC_NOTIFY",
    host: "alc-notify",
    proxies: ["browser"],
  },
  { match: "prefix", path: "/api/trouble/", binding: "ALC_TROUBLE", host: "alc-trouble", proxies: ["browser"] },
  {
    match: "pattern",
    pattern: /^\/api\/internal\/trouble\/schedules\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/fire$/i,
    binding: "ALC_TROUBLE",
    host: "alc-trouble",
    proxies: ["internal"],
  },
  { match: "exact", path: "/api/internal/trouble/camera-down-tickets", binding: "ALC_TROUBLE", host: "alc-trouble", proxies: ["internal"] },
];

/** 転送先 (Service Binding と、URL に使うダミーの host)。 */
export interface AlcBindingTarget {
  fetcher: Fetcher;
  host: string;
}

function matchesRoute(route: AlcBindingRoute, backendPath: string): boolean {
  if (route.match === "exact") return backendPath === route.path;
  if (route.match === "pattern") return route.pattern.test(backendPath);
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
