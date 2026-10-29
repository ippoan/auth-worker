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
  /**
   * proxy ごとに通す method (大文字)。書いた proxy はここに無い method を Cloud Run へ回す (worker に渡さない)。
   * 書かない proxy・この欄の無い行は method を見ない。同じ path を画面用と内部用で別の method に使う口
   * (一覧の GET は画面、起票の POST は内部用) で、画面から内部用の method が worker に届かないようにする。
   */
  methods?: Partial<Record<AlcProxyKind, ReadonlyArray<string>>>;
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
 * 文書とメールの閲覧 (W8c-1、Refs ippoan/rust-alc-api#680) も `alc-notify` へ回す: 文書の一覧 `/api/notify/documents` と
 * メールの一覧 `/api/notify/emails` (完全一致)、文書の 1 件・preview・download (`/api/notify/documents/{uuid}`・`/preview`・
 * `/download`) とメールの 1 件 (`/api/notify/emails/{uuid}`) (UUID に固定した pattern)。画面用 (nuxt-notify の /api/proxy →
 * /alc-proxy) だけで、閲覧の口は method を GET に絞る。
 * 文書の書きの口 (W8c-2) も画面用だけ `alc-notify` へ回す: 文書の削除 (DELETE `/api/notify/documents/{uuid}`。1 件の GET と同じ行)、
 * upload (POST `/api/notify/documents/upload`、完全一致。multipart の本文と Content-Type はそのまま渡る)、やり直し
 * (POST `/api/notify/documents/{uuid}/redact-recompute`・`/extract-recompute`)。`/api/notify/documents/search` は入れない (rust から消す)。
 * **メールの取り込み `/api/notify/ingest` は載せない** — worker の ingest は tenant の検査の外で Service Binding だけを信頼する口なので、
 * ここに載せると外からどの tenant にも書ける (届くのは nuxt-notify の email-receiver の binding `NOTIFY` だけ。テストで固定)。
 * `/api/notify/documents/` と `/api/notify/lineworks/` の prefix は足さない (ingest・viewer・LINE の webhook・既読の記録を拾わない)。
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
 * 勤怠向けの読み取り (W5b、Refs ippoan/rust-alc-api#680) も `alc-dtako` へ回す (どちらも完全一致)。`/api/dtako/events` は RPC だけ
 * (rust-ichibanboshi の勤怠 Worker = `KintaiAlcEntrypoint`)。`/api/dtako/events/etags` は RPC (`KintaiAlcEntrypoint` と
 * `InternalEntrypoint` の `FORWARDABLE_PATHS` = dtako-scraper-relay)・画面用 (nuxt-dtako-admin の取り込み後の答え合わせ)・
 * 端末用 (dtako relay の端末 role)。etags の ETag は呼び手の月の指紋の入力で、worker も同じ形 (引用符の無い MD5) を返す。
 * 画面向けの読み取りと分類の更新 (W5c-1、Refs ippoan/rust-alc-api#680) も `alc-dtako` へ回す。画面用の proxy だけ:
 * 乗務員・車両・セグメント (`/api/drivers`・`/api/vehicles`・`/api/work-times`、完全一致)、日別 (`/api/daily-hours/`、
 * 1 日ぶんのセグメントを含む prefix)、運行 (`/api/operations/`、一覧・カレンダー・1 件の取得と削除・CSV を含む prefix)、
 * 変更記録 (`/api/dtako/operation-changes`)、イベントの分類 (`/api/event-classifications/`、更新を含む prefix)、
 * 車両の現在地のログの読み取り 4 口 (`/api/dtako-logs/current`・`current/select`・`by-date`・`by-date-range`、完全一致。
 * `bulk` は上の行のまま)。nuxt-dtako-admin・nuxt_dtako_logs・alc-app の管理画面が /alc-proxy 経由で呼ぶ。
 * `/api/internal/operations` (完全一致) は内部用の proxy (shared-secret のクラス。nuxt-dtako-admin の server route) だけ。
 * `/api/scraper/history` (完全一致、GET と POST) は画面用・RPC (`InternalEntrypoint` の `FORWARDABLE_PATHS` = dtako-scraper-relay)・
 * 端末用 (dtako relay の端末 role) の 3 つ。どの prefix も rust-alc-api の他の口と重ならない (worker が下位の口を全部持つ)。
 * Y時間 export (W5c-2、Refs ippoan/rust-alc-api#680) の 2 口 (`GET /api/dtako/y-time-export`・`POST /api/dtako/y-time-rows`、
 * 完全一致) も `alc-dtako` へ回す。画面用の proxy だけ (nuxt-dtako-admin の server route が /alc-proxy 経由で呼ぶ)。
 * 拘束時間の帳票 (W5c-3、Refs ippoan/rust-alc-api#680) の 2 口 (`GET /api/restraint-report`・`POST /api/restraint-report/compare-csv`、
 * 完全一致) も `alc-dtako` へ回す。画面用の proxy だけ (nuxt-dtako-admin の画面が /alc-proxy 経由で呼ぶ)。
 * その PDF (W5c-4) の 2 口 (`GET /api/restraint-report/pdf`・`GET /api/restraint-report/pdf-stream`、完全一致。
 * pdf-stream の応答は event-stream で、binding の応答をそのまま返すので進み具合は届いた順に画面へ流れる) も同じ。画面用の proxy だけ。
 * 車両のエラーの起票 (W5c-5、Refs ippoan/rust-alc-api#680) の 5 口も `alc-dtako` へ回す。`/api/dtako/tickets` (完全一致) は
 * 一覧 (GET、画面用 = nuxt_dtako_logs) と起票 (POST、内部用の proxy の shared-secret のクラス = email-receiver) の両方で、
 * method を proxy ごとに絞る (画面からの POST は worker に渡さない。rust でも画面の経路は GET しか受けなかった)。
 * 結果の反映 `/api/dtako/tickets/{uuid}/scraped` (UUID に固定) は内部用だけ。1 件 `/api/dtako/tickets/{uuid}` (UUID に固定) と
 * close_token で閉じる `/api/dtako/tickets/close` (完全一致) は画面用だけ。prefix は足さない。
 * 端末の測定・打刻 (`/api/hub/measurements`、完全一致。W6a、Refs ippoan/rust-alc-api#680) も `alc-people` へ回す。
 * 取り込み (POST) は内部用の proxy (shared-secret のクラス = cf-alc-recorder) だけ、一覧 (GET) は画面用 (alc-app) と
 * RPC (MCP の試験記録) だけ (method を proxy ごとに絞る。画面から取り込みを打てないようにする)。
 * 端末の登録・管理・報告 (W6b-a、Refs ippoan/rust-alc-api#680) は `alc-devices` へ回す。1 口ずつ exact か id を固定した pattern で
 * (prefix にしない — 着信の設定 `/api/devices/{id}/call-settings` は FCM の通知を足した W6b-c で回し、
 * FCM の 7 口と再ペアリング (`re-pair`・`authorize-repair`) も残す)。管理画面の口は画面用、一覧・承認待ちは dev の鍵のキオスクの
 * GET (端末用) も、設定・最終ログインは端末の JWT (alc-proxy = 画面用) とキオスク (端末用)、FCM token・版・watchdog の報告は
 * 端末の JWT (画面用)、登録の受け取りは内部用の public-ingest、`pairing-tenant` は auth-worker 自身 (`lib/alc-internal.ts`)。
 * 登録の申請・状態 (`register/request`・`register/status/{code}`) は内部用の許可リストに無く、今どの経路からも届かないので足さない。
 * kiosk の再ペアリング (W6b-b) も `alc-devices` へ回す。`/api/devices/re-pair` (完全一致) は内部用の public-ingest、
 * 管理画面の許可 `/api/devices/{uuid}/authorize-repair` (UUID に固定) は画面用。worker は発行を auth-worker の
 * `DevicePairEntrypoint` に Service Binding で頼む (共有の秘密を持たない)。
 * FCM で端末に送る口と着信の設定 (W6b-c) も `alc-devices` へ回す (worker は既存の FCM の送信専用の鍵を共有する)。
 * 画面用は着信の設定 `PUT /api/devices/{uuid}/call-settings`・試し送り `POST /api/devices/{uuid}/test-fcm`・
 * `POST /api/devices/test-fcm-all`・OTA の通知 `POST /api/devices/trigger-update`、内部用 (public-ingest) は
 * `POST /api/devices/fcm-dismiss-test`。共有の秘密 (`X-Internal-Secret`) を照合する 3 口 (`fcm-notify-call`・
 * `test-fcm-all-exclude`・`trigger-update-dev`) は足さない (本番にその秘密が無く今も使えない。前の 2 つは cf-alc-signaling が
 * Cloud Run を直接呼び、この表を通らない)。
 * 点呼の読み取りと管理 (W7a、Refs ippoan/rust-alc-api#680) は `alc-tenko` へ回す。記録の一覧・CSV、予定 (一覧・作成・一括・
 * 1 件・更新・削除・乗務員の未消費の予定)、基準値、機器故障、webhook の設定と配信の記録、ダッシュボード、日々の健康状態、
 * 乗務員情報、点呼の電話の番号・乗務員 (画面用。端末用は device-data-proxy の role の表にある口だけ) と、点呼の電話の
 * 登録・点呼 (内部用 public-ingest)。
 * 点呼のセッションは `alc-measurements` へ回す (点呼の記録の入口を測定の口に一本化した。点呼セッションと点呼記録を書く worker は
 * alc-measurements だけ。W7b で alc-tenko に移した口を alc-measurements へ移し直した)。一覧 `GET /api/tenko/sessions`・開始 `POST /api/tenko/sessions/start`・1 件
 * `GET /api/tenko/sessions/{uuid}` と各段 (`/{uuid}/{段}`)。画面用 (alc-app の管理画面) は rust と同じ method の全部、端末用は
 * device-data-proxy の role の表にある口 (キオスク = 開始・6 つの段 (アルコールの段は測定の保存で進むので無い)・中止・一覧・1 件・中断・自己再開、運行管理者席 = 一覧・
 * 1 件・判定)。遠隔への切り替え (`escalate-remote`) と管理者の再開 (`resume`) は画面用だけ。id は UUID に固定 (UUID でない id は
 * Cloud Run に落ちる)。webhook は alc-measurements が応答の後に alc-tenko の内部の口へ渡し、alc-tenko が送る (dev端末の要求では送らない)。
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
  { match: "exact", path: "/api/dtako/events", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["rpc"] },
  { match: "exact", path: "/api/dtako/events/etags", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["rpc", "browser", "device"] },
  // 画面向けの読み取りと分類の更新 (W5c-1)。画面用だけ (内部用の operations と、relay も呼ぶ scraper/history を除く)
  { match: "exact", path: "/api/drivers", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/vehicles", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/work-times", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "prefix", path: "/api/daily-hours/", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "prefix", path: "/api/operations/", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/dtako/operation-changes", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "prefix", path: "/api/event-classifications/", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/dtako-logs/current", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/dtako-logs/current/select", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/dtako-logs/by-date", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/dtako-logs/by-date-range", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/internal/operations", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["internal"] },
  { match: "exact", path: "/api/scraper/history", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser", "rpc", "device"] },
  // Y時間 export (W5c-2)。画面用だけ
  { match: "exact", path: "/api/dtako/y-time-export", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/dtako/y-time-rows", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  // 拘束時間の帳票 (W5c-3)。画面用だけ。PDF は回さない
  { match: "exact", path: "/api/restraint-report", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/restraint-report/compare-csv", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/restraint-report/pdf", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  { match: "exact", path: "/api/restraint-report/pdf-stream", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  // 車両のエラーの起票 (W5c-5)。一覧と起票は同じ path (画面用・内部用)、結果の反映は内部用、1 件と close は画面用
  {
    match: "exact",
    path: "/api/dtako/tickets",
    binding: "ALC_DTAKO",
    host: "alc-dtako",
    proxies: ["browser", "internal"],
    methods: { browser: ["GET"], internal: ["POST"] },
  },
  { match: "exact", path: "/api/dtako/tickets/close", binding: "ALC_DTAKO", host: "alc-dtako", proxies: ["browser"] },
  {
    match: "pattern",
    pattern: /^\/api\/dtako\/tickets\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_DTAKO",
    host: "alc-dtako",
    proxies: ["browser"],
  },
  {
    match: "pattern",
    pattern: /^\/api\/dtako\/tickets\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/scraped$/i,
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
  // id 付きの削除は nuxt-leave の形 (UUID に固定。`/export` には当たらない)
  { match: "exact", path: "/api/admin/bot/configs", binding: "ALC_LINEWORKS", host: "alc-lineworks", proxies: ["browser", "admin"] },
  // 開発者だけの export (W9、Refs ippoan/rust-alc-api#680)。alc-lineworks-worker は X-Tenant-ID しか見ないので、開発者の判定と
  // 会社の差し替えを済ませる auth-worker 自身 (`handleBotConfigExport` = admin proxy) からだけ回す。画面の proxy からは届かない
  { match: "exact", path: "/api/admin/bot/configs/export", binding: "ALC_LINEWORKS", host: "alc-lineworks", proxies: ["admin"] },
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
  // 文書とメールの閲覧 (W8c-1) と文書の書きの口 (W8c-2)。画面用だけ。行ごとに method を絞る (表は最初に当たった行で決まる)。
  // /api/notify/ingest は載せない (上の注)
  {
    match: "exact",
    path: "/api/notify/documents",
    binding: "ALC_NOTIFY",
    host: "alc-notify",
    proxies: ["browser"],
    methods: { browser: ["GET"] },
  },
  {
    match: "pattern",
    pattern: /^\/api\/notify\/documents\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_NOTIFY",
    host: "alc-notify",
    proxies: ["browser"],
    methods: { browser: ["GET", "DELETE"] },
  },
  {
    match: "pattern",
    pattern: /^\/api\/notify\/documents\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/(preview|download)$/i,
    binding: "ALC_NOTIFY",
    host: "alc-notify",
    proxies: ["browser"],
    methods: { browser: ["GET"] },
  },
  {
    match: "pattern",
    pattern: /^\/api\/notify\/documents\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/(redact|extract)-recompute$/i,
    binding: "ALC_NOTIFY",
    host: "alc-notify",
    proxies: ["browser"],
    methods: { browser: ["POST"] },
  },
  {
    match: "exact",
    path: "/api/notify/documents/upload",
    binding: "ALC_NOTIFY",
    host: "alc-notify",
    proxies: ["browser"],
    methods: { browser: ["POST"] },
  },
  {
    match: "exact",
    path: "/api/notify/emails",
    binding: "ALC_NOTIFY",
    host: "alc-notify",
    proxies: ["browser"],
    methods: { browser: ["GET"] },
  },
  {
    match: "pattern",
    pattern: /^\/api\/notify\/emails\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_NOTIFY",
    host: "alc-notify",
    proxies: ["browser"],
    methods: { browser: ["GET"] },
  },
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
  // 端末の測定・打刻 (W6a)。取り込みは内部用の POST、一覧は画面用・RPC の GET
  {
    match: "exact",
    path: "/api/hub/measurements",
    binding: "ALC_PEOPLE",
    host: "alc-people",
    proxies: ["browser", "internal", "rpc"],
    methods: { browser: ["GET"], internal: ["POST"], rpc: ["GET"] },
  },
  // 端末の登録・管理・報告 (W6b-a)。着信の設定と FCM の口は下の W6b-c、再ペアリングは W6b-b の行。
  // 一覧・承認待ちは画面用と dev の鍵のキオスク (端末用) の GET。設定・最終ログインは画面用 (端末の JWT) とキオスク (端末用)
  {
    match: "exact",
    path: "/api/devices",
    binding: "ALC_DEVICES",
    host: "alc-devices",
    proxies: ["browser", "device"],
    methods: { browser: ["GET"], device: ["GET"] },
  },
  {
    match: "exact",
    path: "/api/devices/pending",
    binding: "ALC_DEVICES",
    host: "alc-devices",
    proxies: ["browser", "device"],
    methods: { browser: ["GET"], device: ["GET"] },
  },
  { match: "exact", path: "/api/devices/register/create-token", binding: "ALC_DEVICES", host: "alc-devices", proxies: ["browser"] },
  { match: "exact", path: "/api/devices/register/create-permanent-qr", binding: "ALC_DEVICES", host: "alc-devices", proxies: ["browser"] },
  { match: "exact", path: "/api/devices/register/create-device-owner-token", binding: "ALC_DEVICES", host: "alc-devices", proxies: ["browser"] },
  {
    match: "pattern",
    pattern: /^\/api\/devices\/(approve|reject|disable|enable)\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_DEVICES",
    host: "alc-devices",
    proxies: ["browser"],
  },
  {
    match: "pattern",
    pattern: /^\/api\/devices\/approve-by-code\/[A-Za-z0-9_-]{1,64}$/,
    binding: "ALC_DEVICES",
    host: "alc-devices",
    proxies: ["browser"],
  },
  {
    match: "pattern",
    pattern: /^\/api\/devices\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_DEVICES",
    host: "alc-devices",
    proxies: ["browser"],
    methods: { browser: ["DELETE"] },
  },
  {
    match: "pattern",
    pattern: /^\/api\/devices\/settings\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_DEVICES",
    host: "alc-devices",
    proxies: ["browser", "device"],
  },
  { match: "exact", path: "/api/devices/update-last-login", binding: "ALC_DEVICES", host: "alc-devices", proxies: ["browser", "device"] },
  { match: "exact", path: "/api/devices/register-fcm-token", binding: "ALC_DEVICES", host: "alc-devices", proxies: ["browser"] },
  { match: "exact", path: "/api/devices/report-version", binding: "ALC_DEVICES", host: "alc-devices", proxies: ["browser"] },
  { match: "exact", path: "/api/devices/report-watchdog", binding: "ALC_DEVICES", host: "alc-devices", proxies: ["browser"] },
  // 登録の受け取り (端末、ペアリング前)。内部用の proxy の public-ingest のクラスだけ
  { match: "exact", path: "/api/devices/register/claim", binding: "ALC_DEVICES", host: "alc-devices", proxies: ["internal"] },
  // kiosk の再ペアリング (W6b-b)。端末からは内部用の public-ingest、許可は管理画面
  { match: "exact", path: "/api/devices/re-pair", binding: "ALC_DEVICES", host: "alc-devices", proxies: ["internal"] },
  {
    match: "pattern",
    pattern: /^\/api\/devices\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/authorize-repair$/i,
    binding: "ALC_DEVICES",
    host: "alc-devices",
    proxies: ["browser"],
  },
  // FCM で端末に送る口と着信の設定 (W6b-c)。画面用 4 口と内部用 (public-ingest) の dismiss の試し送り
  {
    match: "pattern",
    pattern: /^\/api\/devices\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/call-settings$/i,
    binding: "ALC_DEVICES",
    host: "alc-devices",
    proxies: ["browser"],
    methods: { browser: ["PUT"] },
  },
  {
    match: "pattern",
    pattern: /^\/api\/devices\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/test-fcm$/i,
    binding: "ALC_DEVICES",
    host: "alc-devices",
    proxies: ["browser"],
    methods: { browser: ["POST"] },
  },
  { match: "exact", path: "/api/devices/test-fcm-all", binding: "ALC_DEVICES", host: "alc-devices", proxies: ["browser"], methods: { browser: ["POST"] } },
  { match: "exact", path: "/api/devices/trigger-update", binding: "ALC_DEVICES", host: "alc-devices", proxies: ["browser"], methods: { browser: ["POST"] } },
  { match: "exact", path: "/api/devices/fcm-dismiss-test", binding: "ALC_DEVICES", host: "alc-devices", proxies: ["internal"], methods: { internal: ["POST"] } },
  // auth-worker 自身の pairing-tenant の問い合わせ (lib/alc-internal.ts。proxy の種別は internal として引く)
  {
    match: "pattern",
    pattern: /^\/api\/internal\/devices\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/pairing-tenant$/i,
    binding: "ALC_DEVICES",
    host: "alc-devices",
    proxies: ["internal"],
    methods: { internal: ["GET"] },
  },
  // 点呼の読み取りと管理 (W7a)。1 口ずつ exact か id を UUID (電話の番号は数字) に固定した pattern で
  // (`/api/tenko/` の prefix にしない — 下のセッションの行 (W7b) と同じく口ごとに method まで絞る)。
  // 端末用は device-data-proxy の role の表 (キオスク・運行管理者席・dev の鍵のキオスク) が method まで絞る
  { match: "exact", path: "/api/tenko/records", binding: "ALC_TENKO", host: "alc-tenko", proxies: ["browser", "device"], methods: { device: ["GET"] } },
  { match: "exact", path: "/api/tenko/records/csv", binding: "ALC_TENKO", host: "alc-tenko", proxies: ["browser", "device"], methods: { device: ["GET"] } },
  { match: "exact", path: "/api/tenko/schedules", binding: "ALC_TENKO", host: "alc-tenko", proxies: ["browser", "device"] },
  { match: "exact", path: "/api/tenko/schedules/batch", binding: "ALC_TENKO", host: "alc-tenko", proxies: ["browser", "device"] },
  {
    match: "pattern",
    pattern: /^\/api\/tenko\/schedules\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_TENKO",
    host: "alc-tenko",
    proxies: ["browser", "device"],
  },
  {
    match: "pattern",
    pattern: /^\/api\/tenko\/schedules\/pending\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_TENKO",
    host: "alc-tenko",
    proxies: ["device"],
  },
  { match: "exact", path: "/api/tenko/health-baselines", binding: "ALC_TENKO", host: "alc-tenko", proxies: ["browser"] },
  {
    match: "pattern",
    pattern: /^\/api\/tenko\/health-baselines\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_TENKO",
    host: "alc-tenko",
    proxies: ["browser"],
  },
  { match: "exact", path: "/api/tenko/equipment-failures", binding: "ALC_TENKO", host: "alc-tenko", proxies: ["browser"] },
  { match: "exact", path: "/api/tenko/equipment-failures/csv", binding: "ALC_TENKO", host: "alc-tenko", proxies: ["browser"] },
  {
    match: "pattern",
    pattern: /^\/api\/tenko\/equipment-failures\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_TENKO",
    host: "alc-tenko",
    proxies: ["browser"],
  },
  { match: "exact", path: "/api/tenko/webhooks", binding: "ALC_TENKO", host: "alc-tenko", proxies: ["browser"] },
  {
    match: "pattern",
    pattern: /^\/api\/tenko\/webhooks\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_TENKO",
    host: "alc-tenko",
    proxies: ["browser"],
  },
  {
    match: "pattern",
    pattern: /^\/api\/tenko\/webhooks\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/deliveries$/i,
    binding: "ALC_TENKO",
    host: "alc-tenko",
    proxies: ["browser"],
  },
  { match: "exact", path: "/api/tenko/dashboard", binding: "ALC_TENKO", host: "alc-tenko", proxies: ["browser", "device"], methods: { device: ["GET"] } },
  { match: "exact", path: "/api/tenko/daily-health-status", binding: "ALC_TENKO", host: "alc-tenko", proxies: ["browser"] },
  {
    match: "pattern",
    pattern: /^\/api\/tenko\/driver-info\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_TENKO",
    host: "alc-tenko",
    proxies: ["browser", "device"],
  },
  { match: "exact", path: "/api/tenko-call/numbers", binding: "ALC_TENKO", host: "alc-tenko", proxies: ["browser"] },
  {
    match: "pattern",
    pattern: /^\/api\/tenko-call\/numbers\/[0-9]+$/i,
    binding: "ALC_TENKO",
    host: "alc-tenko",
    proxies: ["browser"],
  },
  { match: "exact", path: "/api/tenko-call/drivers", binding: "ALC_TENKO", host: "alc-tenko", proxies: ["browser", "device"], methods: { device: ["GET"] } },
  // 点呼のセッション (W7b → 点呼の記録の入口の一本化で alc-measurements へ)。`start` は固定の path、ほかは id を UUID に固定。method は rust の route と同じだけを通す
  {
    match: "exact",
    path: "/api/tenko/sessions",
    binding: "ALC_MEASUREMENTS",
    host: "alc-measurements",
    proxies: ["browser", "device"],
    methods: { browser: ["GET"], device: ["GET"] },
  },
  {
    match: "exact",
    path: "/api/tenko/sessions/start",
    binding: "ALC_MEASUREMENTS",
    host: "alc-measurements",
    proxies: ["browser", "device"],
    methods: { browser: ["POST"], device: ["POST"] },
  },
  {
    match: "pattern",
    pattern: /^\/api\/tenko\/sessions\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    binding: "ALC_MEASUREMENTS",
    host: "alc-measurements",
    proxies: ["browser", "device"],
    methods: { browser: ["GET"], device: ["GET"] },
  },
  {
    match: "pattern",
    pattern:
      /^\/api\/tenko\/sessions\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/(medical|self-declaration|daily-inspection|instruction-confirm|report|carrying-items)$/i,
    binding: "ALC_MEASUREMENTS",
    host: "alc-measurements",
    proxies: ["browser", "device"],
    methods: { browser: ["PUT"], device: ["PUT"] },
  },
  {
    match: "pattern",
    pattern: /^\/api\/tenko\/sessions\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/(cancel|interrupt|self-resume|judgment)$/i,
    binding: "ALC_MEASUREMENTS",
    host: "alc-measurements",
    proxies: ["browser", "device"],
    methods: { browser: ["POST"], device: ["POST"] },
  },
  {
    match: "pattern",
    pattern: /^\/api\/tenko\/sessions\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/escalate-remote$/i,
    binding: "ALC_MEASUREMENTS",
    host: "alc-measurements",
    proxies: ["browser"],
    methods: { browser: ["PUT"] },
  },
  {
    match: "pattern",
    pattern: /^\/api\/tenko\/sessions\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/resume$/i,
    binding: "ALC_MEASUREMENTS",
    host: "alc-measurements",
    proxies: ["browser"],
    methods: { browser: ["POST"] },
  },
  { match: "exact", path: "/api/tenko-call/register", binding: "ALC_TENKO", host: "alc-tenko", proxies: ["internal"], methods: { internal: ["POST"] } },
  { match: "exact", path: "/api/tenko-call/tenko", binding: "ALC_TENKO", host: "alc-tenko", proxies: ["internal"], methods: { internal: ["POST"] } },
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
 * 定義されているときだけ返す (どれかが欠ければ null = 従来どおり Cloud Run)。行が `proxy` の method を
 * 絞っていれば、`method` がその中に無いとき (渡さないときを含む) も null。
 */
export function resolveAlcBinding(
  backendPath: string,
  env: Env,
  proxy: AlcProxyKind,
  method?: string,
): AlcBindingTarget | null {
  for (const route of ALC_BINDING_ROUTES) {
    if (!matchesRoute(route, backendPath)) continue;
    if (!route.proxies.includes(proxy)) return null;
    const allowed = route.methods?.[proxy];
    if (allowed && !allowed.includes((method ?? "").toUpperCase())) return null;
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
