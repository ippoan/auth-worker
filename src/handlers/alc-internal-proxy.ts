/**
 * `/alc-internal-proxy/*` — rust-alc-api の **internal ingest 経路**向け data-proxy
 * (rust-alc-api#434 step 3d、caller #4 email-receiver / 将来の server-to-server caller)。
 *
 * W9 (Refs ippoan/rust-alc-api#680): Cloud Run (rust-alc-api) への forward・OIDC mint は撤去した。
 * ①〜③ を通った path は domain worker (Service Binding、`ALC_BINDING_ROUTES`) へ渡し、
 * binding 表に当たらない path (`internal-secret` クラス含む) は 404。
 *
 * `/alc-proxy` (handlers/alc-proxy.ts) は **browser JWT を伴うユーザー経路**だが、
 * email-receiver 等の **server-to-server 内部呼び出しは browser JWT を持たない**。
 * これらは rust の `require_internal_shared_secret` 経路 (`X-Internal-Shared-Secret`)
 * を叩く。lockdown (`allUsers` 削除) 後は Cloud Run IAM が OIDC を要求するため、内部
 * worker は **このハンドラ経由 (service binding 推奨)** で OIDC mint を委譲する。
 *
 *   ① consumer worker proof — `X-Alc-Proxy-Secret` を `INTERNAL_SHARED_SECRET*` と
 *      constant-time 比較 (fail-closed)。`/alc-proxy` と同じ関門 (公開 route でもあるため必須)。
 *   ② **path allowlist** — `require_internal_shared_secret` で守られた ingest 経路のみ
 *      forward する。data 経路 (`require_tenant_header`) を通すと shared secret だけで
 *      `X-Tenant-ID` を詐称でき **#434 の脆弱性そのものの再現**になるため、必ず allowlist
 *      で塞ぐ (data 経路は browser JWT 経路 = `/alc-proxy` 専用)。
 *   ③ forward — binding 表が返す domain worker へ (明示 tenant + Content-Type のみ渡す)。
 *
 * allowlist は 2 クラスに分かれる (`classifyInternalPath`):
 *
 *   - **`shared-secret`** (例: dtako ingest) — rust の `require_internal_shared_secret`
 *     で守られた ingest。`X-Tenant-ID` **必須** (欠落 → 400)、`X-Internal-Shared-Secret`
 *     (= base secret、rust の app 認証) と `X-Tenant-ID` を forward。
 *   - **`public-ingest`** (例: tenko-call register/tenko、devices/register/claim) — rust の
 *     `public_router` (認証なし)。tenant は body/registration_code 等から **RLS / lookup で
 *     解決**し `X-Tenant-ID` は **honor されない**。caller #5 (Android、rust-alc-api#434 step
 *     3d) が browser JWT も device JWT も持たない経路。ここでは **`X-Tenant-ID` を一切
 *     forward しない (strip)**。これにより「万一 data 経路を public-ingest に誤分類しても
 *     X-Tenant-ID 欠落で rust 側 `require_tenant_header` が 401 → 詐称不能」という二重の安全に
 *     なる。`X-Internal-Shared-Secret` も forward しない (public route は検証しないため)。
 *
 * 値 (shared secret) は log / response に出さない。
 */
import type { Env } from "../index";
import {
  forwardViaAlcBinding,
  isUnsafeBackendPath,
  resolveAlcBinding,
} from "../lib/alc-backend-route";
import { resolveAllSharedSecrets } from "./mcp-introspect";

const ROUTE_PREFIX = "/alc-internal-proxy";

/** consumer worker proof を運ぶ header (`/alc-proxy` と共通)。 */
const PROXY_SECRET_HEADER = "X-Alc-Proxy-Secret";

/** allowlist の分類。`null` は不許可 (403)。 */
type InternalPathClass =
  | "shared-secret"
  | "public-ingest"
  | "internal-secret"
  | "internal-jwt";

/**
 * forward 可能な ingest 経路だけを許可し、そのクラスを返す。
 * data 経路 (`require_tenant_header`) を許すと shared secret だけで X-Tenant-ID 詐称が
 * 成立し #434 の再現になるため、ここを通すパスは厳密に列挙する。
 *
 * - `public-ingest` には **rust の `public_router` (認証なし・tenant を body/lookup で解決
 *   = X-Tenant-ID を honor しない) パスだけ**を入れること。`require_tenant_header` の
 *   data 経路を絶対に入れない (入れても X-Tenant-ID は strip されるので 401 になるが、
 *   そもそも data 経路は `/alc-proxy` 専用)。
 * - `internal-secret` は rust が **caller 由来の `X-Internal-Secret` (= FCM_INTERNAL_SECRET)
 *   で自前認証する dev 経路**用。OIDC transport を付けつつ caller の `X-Internal-Secret` を
 *   pass-through し、X-Tenant-ID は forward しない。rust 側で secret 検証されるので proxy は
 *   素通しでよい (consumer proof は X-Alc-Proxy-Secret で別途取れている)。
 * - `internal-jwt` は rust の **`require_internal_jwt` (aud=alc-api-internal) 経路**用。
 *   Authorization を `internalAuthToken` (aud=alc-api-internal) に差し替えて forward する。
 *   X-Tenant-ID / X-Internal-Shared-Secret は forward しない (この経路の rust ハンドラは
 *   RLS バイパスの id 引き — schedule fire なら schedule id、LINE WORKS 送信なら channel id —
 *   で tenant を自分で解決するため)。POST のみ許可。
 */
function classifyInternalPath(path: string): InternalPathClass | null {
  // ── shared-secret: rust の require_internal_shared_secret ingest ──
  if (path === "/api/dtako/tickets") return "shared-secret"; // POST 起票
  if (/^\/api\/dtako\/tickets\/[^/]+\/scraped$/.test(path)) return "shared-secret"; // PATCH 結果反映
  if (path === "/api/upload") return "shared-secret"; // POST dtako csvdata.zip 取り込み (ohishi-exp/dtako-scraper#22)
  if (path === "/api/recalculate-pending") return "shared-secret"; // POST 「要再計算」の印が付いた 乗務員 × 月 の一括再計算 (取り込みの一区切りで relay が呼ぶ、ippoan/alc-dtako-worker#23)。既存の再計算の 3 口は開けない
  if (path === "/api/internal/operations") return "shared-secret"; // GET dtako 実運行一覧 (nuxt-ichibanboshi の一番星突合、ohishi-exp/nuxt-dtako-admin#198 Phase 8)
  if (path === "/api/hub/measurements") return "shared-secret"; // POST CoreS3 測定データ ingest (cf-alc-recorder 経由、#363 / ippoan/alc-app#106 / ippoan/rust-alc-api#564)
  // DVR 動画通知の ingest (Refs ohishi-exp/nuxt-dtako-admin#1094)。rust-alc-api 側の新 route は
  // internal_shared_secret_router (= require_internal_shared_secret + X-Tenant-ID) に載るため
  // shared-secret クラス。UUID は正規表現で厳密検証 (path injection 防止、fire path と同作法)。
  if (path === "/api/dvr/notifications") return "shared-secret"; // POST DVR 通知行の batch ingest
  if (
    /^\/api\/dvr\/files\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      path,
    )
  ) {
    return "shared-secret"; // POST .vdf 本体のストリーム保存
  }

  // ── public-ingest: rust の public_router (caller #5 Android、tenant は body/lookup 解決) ──
  if (path === "/api/tenko-call/register") return "public-ingest"; // TenkoCall 端末登録
  if (path === "/api/tenko-call/tenko") return "public-ingest"; // TenkoCall 点呼送信
  if (path === "/api/devices/register/claim") return "public-ingest"; // AlcoholChecker 端末登録 (pairing 前)
  if (path === "/api/devices/fcm-dismiss-test") return "public-ingest"; // FCM dismiss test (device_id lookup)
  if (path === "/api/devices/re-pair") return "public-ingest"; // kiosk 端末 re-pair (再認証、rust-alc-api#495)

  // ── internal-secret: rust が X-Internal-Secret (FCM_INTERNAL_SECRET) で自前認証する dev 経路 ──
  if (path === "/api/devices/trigger-update-dev") return "internal-secret"; // CI/dev OTA push

  // ── internal-jwt: rust の require_internal_jwt (aud=alc-api-internal) 経路 ──
  // schedule-alarm DO worker (nuxt-notify) の通知予約発火 (Refs ippoan/rust-alc-api#550,
  // ippoan/auth-worker#359)。fire は id 引きの冪等操作で X-Tenant-ID を使わない。
  // UUID は正規表現で厳密検証 (path injection 防止)。
  if (
    /^\/api\/internal\/trouble\/schedules\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/fire$/i.test(
      path,
    )
  ) {
    return "internal-jwt";
  }
  // LINE WORKS への通知テキスト送信 (Refs ohishi-exp/nuxt-dtako-admin#874、ippoan/rust-alc-api
  // の #874-6)。無人 cron (dtako-scraper-relay) が netprint の予約番号をトークルームへ流す。
  // 同等の tenant 経路 (`/api/notify/lineworks/channels/{id}/test-send`) は
  // require_tenant_header なので **絶対に allowlist しない** (browser JWT 経路 = /alc-proxy 専用)。
  // rust 側は channel_id の id 引き (RLS バイパス) で tenant を解決するため X-Tenant-ID は不要。
  if (path === "/api/internal/lineworks/send") return "internal-jwt"; // POST 通知送信

  return null;
}

/** 定数時間比較 (alc-proxy.ts / mcp-introspect.ts と同実装)。 */
function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function jsonError(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export async function handleAlcInternalProxy(request: Request, env: Env): Promise<Response> {
  // ── env guard ────────────────────────────────────────────────────────────
  const sharedSecrets = await resolveAllSharedSecrets(env);
  if (!sharedSecrets) return jsonError(503, "alc-internal-proxy not configured");

  // ── ① consumer worker proof ───────────────────────────────────────────────
  const proxySecret = request.headers.get(PROXY_SECRET_HEADER) ?? "";
  if (!proxySecret || !sharedSecrets.some((s) => constantTimeEquals(proxySecret, s))) {
    return jsonError(401, "Unauthorized");
  }

  // ── ② path allowlist (data 経路への X-Tenant-ID 詐称を塞ぐ) ─────────────────
  const url = new URL(request.url);
  const backendPath = url.pathname.slice(ROUTE_PREFIX.length) || "/";
  const pathClass = classifyInternalPath(backendPath);
  if (!pathClass) return jsonError(403, "forbidden");
  // internal-jwt は POST のみ許可 (発火 / 送信以外の操作を通さない)。
  if (pathClass === "internal-jwt" && request.method !== "POST") {
    return jsonError(403, "forbidden");
  }

  // ── ③ tenant — shared-secret 経路のみ必須 (内部呼び出し元が明示)。 ──────────
  //     public-ingest は rust 側が X-Tenant-ID を honor しないため strip する。
  const tenantId = request.headers.get("X-Tenant-ID") ?? "";
  if (pathClass === "shared-secret" && !tenantId) return jsonError(400, "X-Tenant-ID required");

  // ── domain worker (Service Binding) への振り分け ─────────────────────────
  // ①〜③ を通った shared-secret / internal-jwt / public-ingest クラスの path のうち、振り分け表がこの proxy に
  // binding を返すものだけ forward する。binding 未定義 / 表に無い path / internal-secret クラスは 404
  // (W9 で Cloud Run fallback を撤去、Refs ippoan/rust-alc-api#680)。渡すヘッダは明示された tenant
  // (shared-secret だけ。internal-jwt は tenant を渡さない) と Content-Type だけで、呼び手のほかのヘッダは渡さない。
  // public-ingest (登録の受け取り等。tenant は body/lookup で解決) は Content-Type だけを渡す。
  const binding =
    pathClass === "internal-secret"
      ? null
      : resolveAlcBinding(backendPath, env, "internal", request.method);
  if (!binding) return jsonError(404, "not_found");
  if (isUnsafeBackendPath(backendPath)) return jsonError(403, "forbidden");
  const bindingHeaders: Record<string, string> = {};
  if (pathClass === "shared-secret") {
    bindingHeaders["X-Tenant-ID"] = tenantId;
    // 開発用の鍵の印は値がちょうど "1" のときだけ渡す (dev の行と本番の行を分ける)
    if (request.headers.get("X-Device-Dev") === "1") bindingHeaders["X-Device-Dev"] = "1";
  }
  const bindingContentType = request.headers.get("content-type");
  if (bindingContentType) bindingHeaders["Content-Type"] = bindingContentType;
  const bindingHasBody = request.method !== "GET" && request.method !== "HEAD";
  return forwardViaAlcBinding(binding, backendPath, url.search, {
    method: request.method,
    headers: bindingHeaders,
    body: bindingHasBody ? await request.arrayBuffer() : undefined,
  });
}

export { ROUTE_PREFIX as ALC_INTERNAL_PROXY_PREFIX };
