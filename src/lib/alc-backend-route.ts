import type { Env } from "../index";

/**
 * 表を引く proxy の種別 (画面用 = alc-proxy / 内部用 = alc-internal-proxy / 端末用 = device-data-proxy /
 * 管理画面用 = admin-notify-api・api-line-users / RPC = Service Binding の entrypoint の `forwardAlcTenantRequest`)。
 */
export type AlcProxyKind = "browser" | "internal" | "device" | "admin" | "rpc";

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
 * `/api/fuel/` は燃料 (給油の実績・給油カード) の参照と CSV 取り込みの API (prefix)。画面 (nuxt-dtako-admin) からだけ呼ぶので
 * `rust-fuel-worker` へ回すのは画面用の proxy だけ (Windows の常駐アプリは `/m/fuel-utran/*` の machine-relay を通り、この表は引かない)。
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
 * `/api/measurements` は測定 (アルコール検査の記録) の 7 口で、`alc-measurements` へ回す。画面用と端末用の proxy だけ
 * (内部用の proxy は /api/measurements を 403 で通さないので入れない)。一覧・登録 (`/api/measurements`)・開始 (`/api/measurements/start`) は完全一致、
 * 1 件の取得・更新 (`/{id}`) と顔写真・動画 (`/{id}/face-photo`・`/{id}/video`) は id を UUID に固定した pattern。prefix は足さない
 * (UUID に固定するので `GET /api/measurements/start` や他の下位 path は Cloud Run に残る)。
 * `/api/upload/face-photo`・`/api/upload/blow-video`・`/api/upload/report-audio` は顔写真・吹きかけ動画・運行報告の音声を R2 に
 * 置く 3 口 (完全一致)。`alc-measurements` へ回す (Refs ippoan/rust-alc-api#680)。画面用と端末用 (キオスクの `KIOSK_ROUTES` の 3 行)。
 * `/api/upload` (完全一致、dtako の取り込み) とは別の口なので prefix にしない。
 * 物品 (`/api/items/`・`/api/item-files/`)・携行品 (`/api/carrying-items/`)・伝達事項 (`/api/communication-items/`)・指導記録
 * (`/api/guidance-records/`) は `alc-records` へ回す (Refs ippoan/rust-alc-api#680)。worker が rust の口を全部持つので prefix。
 * 画面用 (nuxt-items・alc-app) と、携行品だけ端末用 (キオスクの `GET /api/carrying-items`。device-data-proxy の role の表で絞る)。
 * 車検証 (`/api/car-inspections/`・`/api/files`・`/api/nfc-tags/`) と車両整備 (`/api/maintenance/`) は `alc-carins` へ回す
 * (Refs ippoan/rust-alc-api#680)。画面用は nuxt-pwa-carins・nuxt-trouble・nuxt-vehicle-maintenance・alc-app。端末用は
 * 車検証の登録 (`/api/files`) と期限の照合 (`/api/car-inspections/lookup`。どちらも device-data-proxy の role の表で絞る)。
 * RPC は smb Worker の取り込み (SmbIngest の `/api/files`)。`/api/files` は下位の口が別なので完全一致・個別の行にし、
 * worker に無い下位の口 (`not-attached`・`{uuid}` の取得・削除・復元) と `/api/car-inspection-files/` は Cloud Run に残す。
 * タイムカード (`/api/timecard/`) は `alc-people` へ回す (W4d-a、Refs ippoan/rust-alc-api#680)。worker が rust の口を全部持つので
 * prefix。画面用 (alc-app の管理画面)・端末用 (キオスク・運行管理者席など。device-data-proxy の role の表で絞る)・RPC
 * (InternalEntrypoint の `bulk-by-code`・`delete-by-card` = カード台帳の同期。`FORWARDABLE_PATHS` で絞る)。
 * 社員 (`/api/employees/`) も `alc-people` へ回す (W4d-b)。worker が rust の口を全部持つので prefix。経路はタイムカードと同じ 3 つ
 * (画面用・端末用 = キオスク・運行管理者席・測定台の照会と顔データ。role の表で絞る・RPC = 乗務員マスタの同期 `bulk-by-code`)。
 * `/api/notify/employees` (宛先の画面の社員の選択肢) は別の口で `alc-notify` のまま。
 * 機械の取り込み (W5a、Refs ippoan/rust-alc-api#680) も `alc-dtako` へ回す。車両の現在地のログ `/api/dtako-logs/bulk` (完全一致。
 * 同じ prefix の読み取り `current`・`by-date` などは Cloud Run に残る) は端末用 (dtako 取り込みの端末 role) と RPC
 * (InternalEntrypoint の `FORWARDABLE_PATHS`、dtako-scraper-relay)。DVR の動画通知 `/api/dvr/notifications` (完全一致) と実体
 * `/api/dvr/files/{uuid}` (UUID に固定。alc-internal-proxy の分類と同じ形) は内部用の proxy (shared-secret のクラス) だけ。
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
  { match: "exact", path: "/api/dtako-logs/bulk", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["device", "rpc"] },
  { match: "exact", path: "/api/dvr/notifications", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["internal"] },
  {
    match: "pattern",
    pattern: /^\/api\/dvr\/files\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_DTAKO",
    host: "alc-dtako",
    proxies: ["internal"],
  },
  { match: "prefix", path: "/api/leave/", binding: "ALC_LEAVE", host: "rust-leave", proxies: ["browser"] },
  { match: "prefix", path: "/api/fuel/", binding: "FUEL_WORKER", host: "rust-fuel-worker", proxies: ["browser"] },
  { match: "exact", path: "/api/internal/lineworks/send", binding: "ALC_LINEWORKS", host: "alc-lineworks", proxies: ["internal"] },
  { match: "exact", path: "/api/lineworks/deploy-check", binding: "ALC_LINEWORKS", host: "alc-lineworks", proxies: ["browser"] },
  // Bot 設定 (一覧・保存・削除)。rust-alc-api から alc-lineworks-worker へ移した (Refs ippoan/rust-alc-api#680)。
  // 画面 (nuxt-leave・nuxt-notify の alc-proxy) と auth-worker 自身 (管理画面・MCP の Bot 選び = admin proxy) が呼ぶ。
  // id 付きの削除は nuxt-leave の形 (UUID に固定。開発者だけの `/export` は Cloud Run に残す)
  { match: "exact", path: "/api/admin/bot/configs", binding: "ALC_LINEWORKS", host: "alc-lineworks", proxies: ["browser", "admin"] },
  {
    match: "pattern",
    pattern: /^\/api\/admin\/bot\/configs\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_LINEWORKS",
    host: "alc-lineworks",
    proxies: ["browser"],
  },
  { match: "prefix", path: "/api/notify/recipients/", binding: "ALC_NOTIFY", host: "alc-notify", proxies: ["browser", "admin"] },
  { match: "prefix", path: "/api/notify/groups/", binding: "ALC_NOTIFY", host: "alc-notify", proxies: ["browser", "admin"] },
  { match: "prefix", path: "/api/notify/lineworks/channels/", binding: "ALC_NOTIFY", host: "alc-notify", proxies: ["browser", "admin"] },
  { match: "exact", path: "/api/notify/line-config", binding: "ALC_NOTIFY", host: "alc-notify", proxies: ["browser", "admin"] },
  { match: "exact", path: "/api/notify/lineworks/users", binding: "ALC_NOTIFY", host: "alc-notify", proxies: ["browser", "admin"] },
  { match: "exact", path: "/api/notify/lineworks/login-activity", binding: "ALC_NOTIFY", host: "alc-notify", proxies: ["browser", "admin"] },
  { match: "exact", path: "/api/notify/test-distribute", binding: "ALC_NOTIFY", host: "alc-notify", proxies: ["browser", "admin"] },
  // 宛先の画面の社員の選択肢 (宛先と社員の結び付け、Refs ippoan/alc-app#436)。alc-notify-worker v0.1.5 から
  { match: "exact", path: "/api/notify/employees", binding: "ALC_NOTIFY", host: "alc-notify", proxies: ["browser", "admin"] },
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
  { match: "exact", path: "/api/measurements", binding: "ALC_MEASUREMENTS", host: "alc-measurements", proxies: ["browser", "device"] },
  { match: "exact", path: "/api/measurements/start", binding: "ALC_MEASUREMENTS", host: "alc-measurements", proxies: ["browser", "device"] },
  { match: "exact", path: "/api/measurements/alert-test", binding: "ALC_MEASUREMENTS", host: "alc-measurements", proxies: ["browser", "admin"] },
  // 血圧の日報のテスト送信 (admin だけ。判定は alc-measurements-worker が X-User-Role で行う。alert-test と同じ経路。Refs ippoan/alc-app#436)
  { match: "exact", path: "/api/measurements/bp-report-test", binding: "ALC_MEASUREMENTS", host: "alc-measurements", proxies: ["browser", "admin"] },
  // 血圧の通知の設定 (社員 ↔ LINE WORKS、本人への通知・日報の受け取り。既存の通知の宛先とは別管理、Refs ippoan/alc-app#436)。
  // 管理者の画面 (alc-app) からだけ使う。admin の判定は alc-measurements-worker が X-User-Role で行う
  { match: "prefix", path: "/api/bp-notify/", binding: "ALC_MEASUREMENTS", host: "alc-measurements", proxies: ["browser"] },
  // 拠点カメラの SD 録画の時間指定の切り出し (ippoan/alc-cam の ingest/)。管理者の画面から使う。
  // 端末用は運行管理者席の鍵がカメラ一覧 (`GET /api/cam-clips/cameras`) を、拠点 PC の拡張の鍵が
  // 担当カメラ (`GET /api/cam-clips/cameras/mine`) を読むためだけに足してある (通せる口は
  // device-data-proxy の `TENKO_MANAGER_ROUTES` と `CAM_HOST_ROUTES` の各 1 行。他の device role の表には無い)。
  // 呼び手とテナントの判定は alc-cam-sd-ingest が X-User-Role / X-Device-Role / X-Tenant-ID で行う
  { match: "prefix", path: "/api/cam-clips/", binding: "ALC_CAM_CLIPS", host: "alc-cam-sd-ingest", proxies: ["browser", "device"] },
  {
    match: "pattern",
    pattern: /^\/api\/measurements\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_MEASUREMENTS",
    host: "alc-measurements",
    proxies: ["browser", "device"],
  },
  {
    match: "pattern",
    pattern: /^\/api\/measurements\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/(face-photo|video|tenko)$/i,
    binding: "ALC_MEASUREMENTS",
    host: "alc-measurements",
    proxies: ["browser", "device"],
  },
  { match: "exact", path: "/api/upload/face-photo", binding: "ALC_MEASUREMENTS", host: "alc-measurements", proxies: ["browser", "device"] },
  { match: "exact", path: "/api/upload/blow-video", binding: "ALC_MEASUREMENTS", host: "alc-measurements", proxies: ["browser", "device"] },
  { match: "exact", path: "/api/upload/report-audio", binding: "ALC_MEASUREMENTS", host: "alc-measurements", proxies: ["browser", "device"] },
  { match: "prefix", path: "/api/items/", binding: "ALC_RECORDS", host: "alc-records", proxies: ["browser"] },
  { match: "prefix", path: "/api/item-files/", binding: "ALC_RECORDS", host: "alc-records", proxies: ["browser"] },
  { match: "prefix", path: "/api/carrying-items/", binding: "ALC_RECORDS", host: "alc-records", proxies: ["browser", "device"] },
  { match: "prefix", path: "/api/communication-items/", binding: "ALC_RECORDS", host: "alc-records", proxies: ["browser"] },
  { match: "prefix", path: "/api/guidance-records/", binding: "ALC_RECORDS", host: "alc-records", proxies: ["browser"] },
  { match: "prefix", path: "/api/car-inspections/", binding: "ALC_CARINS", host: "alc-carins", proxies: ["browser", "device"] },
  { match: "exact", path: "/api/files", binding: "ALC_CARINS", host: "alc-carins", proxies: ["browser", "device", "rpc"] },
  { match: "exact", path: "/api/files/recent", binding: "ALC_CARINS", host: "alc-carins", proxies: ["browser"] },
  { match: "exact", path: "/api/files/verify", binding: "ALC_CARINS", host: "alc-carins", proxies: ["browser"] },
  {
    match: "pattern",
    pattern: /^\/api\/files\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/download$/i,
    binding: "ALC_CARINS",
    host: "alc-carins",
    proxies: ["browser"],
  },
  { match: "prefix", path: "/api/nfc-tags/", binding: "ALC_CARINS", host: "alc-carins", proxies: ["browser"] },
  { match: "prefix", path: "/api/maintenance/", binding: "ALC_CARINS", host: "alc-carins", proxies: ["browser"] },
  { match: "prefix", path: "/api/timecard/", binding: "ALC_PEOPLE", host: "alc-people", proxies: ["browser", "device", "rpc"] },
  { match: "prefix", path: "/api/employees/", binding: "ALC_PEOPLE", host: "alc-people", proxies: ["browser", "device", "rpc"] },
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
