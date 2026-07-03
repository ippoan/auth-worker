/**
 * `/alc-internal-proxy/*` — rust-alc-api の **internal ingest 経路**向け data-proxy
 * (rust-alc-api#434 step 3d、caller #4 email-receiver / 将来の server-to-server caller)。
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
 *   ③ OIDC mint — `ALC_API_PROXY_SA_KEY` (run.invoker) で aud=service URL を mint。
 *   ④ forward — `ALC_API_ORIGIN` + path に `Authorization: Bearer <OIDC>` (transport) を付与。
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
 * 値 (OIDC / SA key / shared secret) は log / response に出さない。
 */
import type { Env } from "../index";
import { resolveSecret } from "../lib/secret";
import { mintGoogleIdToken } from "../lib/oidc";
import { resolveAllSharedSecrets } from "./mcp-introspect";

const ROUTE_PREFIX = "/alc-internal-proxy";

/** consumer worker proof を運ぶ header (`/alc-proxy` と共通)。 */
const PROXY_SECRET_HEADER = "X-Alc-Proxy-Secret";

/** allowlist の分類。`null` は不許可 (403)。 */
type InternalPathClass = "shared-secret" | "public-ingest" | "internal-secret";

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
 */
function classifyInternalPath(path: string): InternalPathClass | null {
  // ── shared-secret: rust の require_internal_shared_secret ingest ──
  if (path === "/api/dtako/tickets") return "shared-secret"; // POST 起票
  if (/^\/api\/dtako\/tickets\/[^/]+\/scraped$/.test(path)) return "shared-secret"; // PATCH 結果反映
  if (path === "/api/upload") return "shared-secret"; // POST dtako csvdata.zip 取り込み (ohishi-exp/dtako-scraper#22)

  // ── public-ingest: rust の public_router (caller #5 Android、tenant は body/lookup 解決) ──
  if (path === "/api/tenko-call/register") return "public-ingest"; // TenkoCall 端末登録
  if (path === "/api/tenko-call/tenko") return "public-ingest"; // TenkoCall 点呼送信
  if (path === "/api/devices/register/claim") return "public-ingest"; // AlcoholChecker 端末登録 (pairing 前)
  if (path === "/api/devices/fcm-dismiss-test") return "public-ingest"; // FCM dismiss test (device_id lookup)
  if (path === "/api/devices/re-pair") return "public-ingest"; // kiosk 端末 re-pair (再認証、rust-alc-api#495)

  // ── internal-secret: rust が X-Internal-Secret (FCM_INTERNAL_SECRET) で自前認証する dev 経路 ──
  if (path === "/api/devices/trigger-update-dev") return "internal-secret"; // CI/dev OTA push

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
  const saKey = await resolveSecret(env.ALC_API_PROXY_SA_KEY);
  if (!saKey) return jsonError(503, "alc-internal-proxy not configured"); // SA key 未設定
  const apiOrigin = env.ALC_API_ORIGIN;
  if (!apiOrigin) return jsonError(503, "server_error");
  const sharedSecrets = await resolveAllSharedSecrets(env);
  if (!sharedSecrets) return jsonError(503, "alc-internal-proxy not configured");
  // rust の require_internal_shared_secret が期待する base secret (forward 用)。
  const baseSecret = await resolveSecret(env.INTERNAL_SHARED_SECRET);
  if (!baseSecret) return jsonError(503, "alc-internal-proxy not configured");

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

  // ── ③ tenant — shared-secret 経路のみ必須 (内部呼び出し元が明示)。 ──────────
  //     public-ingest は rust 側が X-Tenant-ID を honor しないため strip する。
  const tenantId = request.headers.get("X-Tenant-ID") ?? "";
  if (pathClass === "shared-secret" && !tenantId) return jsonError(400, "X-Tenant-ID required");

  // ── ④ OIDC mint (Cloud Run IAM lockdown 用、aud=service URL) ────────────────
  let idToken: string;
  try {
    idToken = await mintGoogleIdToken(saKey, apiOrigin);
  } catch {
    return jsonError(502, "upstream auth error"); // 詳細は log のみ
  }

  // ── ⑤ forward ─────────────────────────────────────────────────────────────
  const target = `${apiOrigin.replace(/\/$/, "")}${backendPath}${url.search}`;
  const fwdHeaders: Record<string, string> = {
    Authorization: `Bearer ${idToken}`,
  };
  if (pathClass === "shared-secret") {
    // rust の app 認証 (require_internal_shared_secret) + 明示 tenant。
    fwdHeaders["X-Internal-Shared-Secret"] = baseSecret;
    fwdHeaders["X-Tenant-ID"] = tenantId;
  } else if (pathClass === "internal-secret") {
    // rust が caller 由来の X-Internal-Secret (FCM_INTERNAL_SECRET) で自前認証する dev 経路。
    // caller (alc-app) が中継した値をそのまま pass-through する (無ければ rust 側で 401/403)。
    const callerSecret = request.headers.get("X-Internal-Secret");
    if (callerSecret) fwdHeaders["X-Internal-Secret"] = callerSecret;
  }
  // public-ingest / internal-secret は X-Tenant-ID を forward しない (rust は honor しない +
  // 誤分類時の詐称防止)。public-ingest は OIDC transport だけ。
  const contentType = request.headers.get("content-type");
  if (contentType) fwdHeaders["Content-Type"] = contentType;

  const method = request.method;
  const hasBody = method !== "GET" && method !== "HEAD";
  const body = hasBody ? await request.arrayBuffer() : undefined;

  return fetch(target, { method, headers: fwdHeaders, body });
}

export { ROUTE_PREFIX as ALC_INTERNAL_PROXY_PREFIX };
