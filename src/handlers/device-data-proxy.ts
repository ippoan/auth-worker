/**
 * `/device-data-proxy/*` — 無人デバイス (browser-render-rust の Kagoya VPS cron 等)
 * が device JWT で rust-alc-api の data 経路 (`require_tenant_header`) を叩くための
 * proxy (rust-alc-api#434 followup)。
 *
 * `/alc-proxy` (browser JWT + app origin ACL) でも `/alc-internal-proxy`
 * (shared-secret + path allowlist、data 経路は明示的に非対応) でもなく、
 * `/device/token` で mint した **device JWT** (`lib/device.ts::mintDeviceJwt`)
 * を検証入力にする第三の経路。device JWT は通常の browser JWT と同じ
 * `verifyJwt` (HS256/JWT_SECRET) で検証でき、`tenant_id` は pairing 時に
 * 確定済みで client からは詐称不能 — shared secret だけで任意 tenant の
 * X-Tenant-ID を詐称できてしまう問題が起きない (alc-internal-proxy.ts が
 * data 経路を弾いている理由そのものを、device 単位の tenant 束縛で解消する)。
 *
 *   ① `Authorization: Bearer <device JWT>` を `verifyJwt` で検証。
 *   ② `payload.role` を `ROLE_PATH_ALLOWLIST` に照合し、この role が転送を
 *      許可された path だけを通す (盗難時の blast radius を role 単位で限定)。
 *   ③ `ALC_API_PROXY_SA_KEY` (run.invoker) で aud=service URL の OIDC を mint。
 *   ④ `payload.tenant_id` (= device record 由来、client 入力ではない) を
 *      X-Tenant-ID として注入し `ALC_API_ORIGIN` + path へ forward する。
 *
 * rust-alc-api 側は無変更 — 通常の `require_tenant_header` data 経路をそのまま
 * 叩くだけで良い (proxy が identity 検証済みという #434 の dumb backend 前提を維持)。
 *
 * 値 (OIDC / SA key / device JWT) は log / response に出さない。
 */
import type { Env } from "../index";
import { extractToken } from "../lib/errors";
import { verifyJwt } from "../lib/jwt";
import { resolveSecret } from "../lib/secret";
import { mintGoogleIdToken } from "../lib/oidc";
import { DEVICE_ROLE_DTAKO_INGEST, DEVICE_ROLE_DTAKO_RELAY } from "../lib/device";

const ROUTE_PREFIX = "/device-data-proxy";

/**
 * device JWT の role → 転送を許可する rust-alc-api path の allowlist。
 * 新しい role / path を足す時はここに 1 行追加するだけで良い。role を
 * 割り当てない device は何も転送できない (デフォルト拒否)。
 */
const ROLE_PATH_ALLOWLIST: Readonly<Record<string, ReadonlySet<string>>> = {
  // Kagoya VPS の dtako ingest 系。**VPS は 2026-08-26 時点で停止中だが、この行は
  // 意図して残している** — 本番 KV に `device-dtako-ingest` の credential が 4 本
  // live で残っており、この行だけ先に消すと mint は通ったまま転送だけ 403 になる。
  // 経緯と撤去条件 (先に 4 本を revoke) は `lib/device.ts` の
  // `DEVICE_ROLE_DTAKO_INGEST` の doc を見ること (Refs #481)。
  [DEVICE_ROLE_DTAKO_INGEST]: new Set(["/api/dtako-logs/bulk", "/api/upload"]),
  // dtako-scraper-relay (無人 cron) のスクレイプ履歴 (Refs
  // ohishi-exp/nuxt-dtako-admin#931 = 無人実行が履歴に載らない / #933 = 履歴の
  // 読みが 403)。どちらも rust の `tenant_router()` = `require_tenant_header` の
  // data 経路なので `alc-internal-proxy` では通せない (あちらは data 経路を
  // 意図的に allowlist から外している — #434 の X-Tenant-ID 詐称対策)。
  //
  // **この allowlist は method を見ない** (下の `allowed.has(backendPath)`) ので、
  // `/api/scraper/history` の 1 行で **GET (履歴を読む) と POST (無人実行を
  // 載せる) の両方**が通る。**意図的にそうしている** — 読めない履歴に書いても
  // 意味が無く、#931 と #933 は同じ 1 経路で直る。
  [DEVICE_ROLE_DTAKO_RELAY]: new Set(["/api/scraper/history", "/api/dtako/events/etags"]),
};

function jsonError(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export async function handleDeviceDataProxy(request: Request, env: Env): Promise<Response> {
  // ── env guard ────────────────────────────────────────────────────────────
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) return jsonError(503, "server_error");
  const saKey = await resolveSecret(env.ALC_API_PROXY_SA_KEY);
  if (!saKey) return jsonError(503, "device-data-proxy not configured"); // SA key binding 未設定
  const apiOrigin = env.ALC_API_ORIGIN;
  if (!apiOrigin) return jsonError(503, "server_error");

  // ── ① device JWT 検証 (browser JWT と同じ検証関数・同じ HS256 secret) ────────
  const token = extractToken(request) ?? "";
  if (!token) return jsonError(401, "Unauthorized");
  const payload = await verifyJwt(token, jwtSecret, env.WORKER_ENV);
  if (!payload) return jsonError(401, "Unauthorized");

  const tenantId = (payload.tenant_id as string | undefined) || "";
  const role = (payload.role as string | undefined) || "";
  if (!tenantId || !role) return jsonError(401, "Unauthorized");

  // ── ② role → path allowlist (盗難時の blast radius を role 単位で限定) ──────
  const url = new URL(request.url);
  const backendPath = url.pathname.slice(ROUTE_PREFIX.length) || "/";
  const allowed = ROLE_PATH_ALLOWLIST[role];
  if (!allowed || !allowed.has(backendPath)) return jsonError(403, "forbidden");

  // ── ③ OIDC mint (Cloud Run IAM lockdown 用、aud=service URL) ────────────────
  let idToken: string;
  try {
    idToken = await mintGoogleIdToken(saKey, apiOrigin);
  } catch {
    return jsonError(502, "upstream auth error"); // 詳細は log のみ
  }

  // ── ④ forward (X-Tenant-ID は device record 由来、client からは詐称不能) ────
  const target = `${apiOrigin.replace(/\/$/, "")}${backendPath}${url.search}`;
  const fwdHeaders: Record<string, string> = {
    Authorization: `Bearer ${idToken}`,
    "X-Tenant-ID": tenantId,
  };
  const contentType = request.headers.get("content-type");
  if (contentType) fwdHeaders["Content-Type"] = contentType;

  const method = request.method;
  const hasBody = method !== "GET" && method !== "HEAD";
  const body = hasBody ? await request.arrayBuffer() : undefined;

  return fetch(target, { method, headers: fwdHeaders, body });
}

export { ROUTE_PREFIX as DEVICE_DATA_PROXY_PREFIX };
