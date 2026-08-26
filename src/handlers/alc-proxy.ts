/**
 * `/alc-proxy/*` — rust-alc-api 向け data-proxy (rust-alc-api#434 step 3、方式 B)。
 *
 * consumer (alc-app / carins / items …) の CF Worker が **service binding**
 * (`AUTH_WORKER`) でこの route に forward する。auth-worker が:
 *   ① consumer worker proof — `X-Alc-Proxy-Secret` を `INTERNAL_SHARED_SECRET*`
 *      と constant-time 比較 (fail-closed)。`/alc-proxy/*` は service binding
 *      だけでなく `auth.ippoan.org` 上の **公開 route** でもあるため、これが
 *      無いと「正当な JWT + 詐称した `X-Alc-Proxy-Origin`」で直叩きされ
 *      `checkAppTenant` の app 単位 ACL を回避できる (handoff #434)。
 *      secret を握る consumer worker からの forward だけを通す関門。
 *   ② cookie / Bearer の browser JWT を **ローカル検証** (JWT_SECRET 所有) + ACL
 *      (origin × tenant、`X-Alc-Proxy-Origin` ヘッダの consumer origin で判定)。
 *      **device 系 token (`aud` 有り / `role ∈ DEVICE_ROLES`) はここで弾く** —
 *      同じ `JWT_SECRET` で署名されるので署名だけでは区別できず、通すと
 *      `/device/pair-internal` (shared secret のみ・`tenant_id` は呼び手指定)
 *      と繋がって任意 tenant の `X-Tenant-ID` 詐称が成立する (#482)
 *   ③ `run.invoker` SA key (`ALC_API_PROXY_SA_KEY`、auth-worker のみ bind) で
 *      Google OIDC ID token を mint
 *   ④ `ALC_API_ORIGIN` (= rust-alc-api、Cloud Run IAM lockdown 後) へ
 *      `Authorization: Bearer <OIDC>` + `X-Tenant-ID` / `X-User-ID/Email/Role`
 *      を注入して forward
 * を 1 箇所で行う。SA key + OIDC mint を auth-worker に集約し、方式変更時の
 * 再配線を 1 repo に閉じる。
 *
 * 値 (token / SA key / OIDC / shared secret) は log / response に出さない。
 */
import type { Env } from "../index";
import { getAuthCookie } from "../lib/cookies";
import { extractToken } from "../lib/errors";
import { verifyJwt } from "../lib/jwt";
import { checkAppTenant, checkOrgAccess } from "../lib/acl";
import { resolveSecret } from "../lib/secret";
import { mintGoogleIdToken } from "../lib/oidc";
import { DEVICE_ROLES } from "../lib/device";
import { resolveAllSharedSecrets } from "./mcp-introspect";

const ROUTE_PREFIX = "/alc-proxy";

/** consumer worker proof を運ぶ header。`INTERNAL_SHARED_SECRET*` の生値を載せる。 */
const PROXY_SECRET_HEADER = "X-Alc-Proxy-Secret";

/**
 * flip 前 preview override を運ぶ header (Refs ippoan/ci-dashboard#472)。
 * ci-dashboard の preview-router が `alc_api_preview_base` cookie を Set し、
 * consumer の `createAuthWorkerProxyHandler` (auth-client) がこの header に
 * 変換して forward してくる。値は同一 Cloud Run service の tagged revision URL
 * (`https://<tag>---<ALC_API_PREVIEW_HOST_SUFFIX>`) のみ許可。
 */
const PREVIEW_BASE_HEADER = "X-Alc-Preview-Api-Base";

/**
 * preview override の値を検証して origin を返す (不正は null)。
 * `<tag>---<suffix>` 形式に pin することで、任意 host への forward
 * (= 認証済み利用者が自分の JWT 由来リクエストを外部に流す) を防ぐ。
 */
export function validatePreviewBase(raw: string, hostSuffix: string): string | null {
  if (!hostSuffix) return null;
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return null;
  }
  if (parsed.protocol !== "https:") return null;
  const marker = `---${hostSuffix}`;
  if (!parsed.hostname.endsWith(marker)) return null;
  const tag = parsed.hostname.slice(0, -marker.length);
  if (!/^[a-z0-9-]+$/.test(tag)) return null;
  return parsed.origin;
}

/** 定数時間比較。短絡せず全文字を XOR して合算 (mcp-introspect.ts と同実装)。 */
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

/**
 * issue #433 — `token_kind=dev` の write enforcement で使う allowlist ロジック。
 * `packages/auth-client/src/server/devLoginCore.mjs` (`isDevLoginWriteAllowed`)
 * と同じ semantics を、consumer 側パッケージに依存せず auth-worker 内で
 * 自己完結させたもの (この enforcement 自体が「唯一の source of truth」なので、
 * consumer 側実装への依存を持たせない)。
 */

/** GET/HEAD/OPTIONS はデータを変更しないため allowlist の対象外 (常に許可)。 */
function isSafeMethod(method: string): boolean {
  return method === "GET" || method === "HEAD" || method === "OPTIONS";
}

/** カンマ区切りの path prefix 文字列を配列にパースする (空/undefined は空配列)。 */
function parseDevWriteAllowlist(raw: string | undefined): string[] {
  if (!raw || !raw.trim()) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * path が allowlist で許可されているか判定する。いずれかの entry と完全一致
 * or `${entry}/` で始まる時のみ許可 (境界を跨いだ誤許可を防ぐ、例:
 * "/api/foo" は "/api/foo-bar" を許可しない)。safe method の判定は呼び出し側
 * (`isSafeMethod`) で別途行う。
 */
function isDevWriteAllowed(path: string, allowlist: readonly string[]): boolean {
  return allowlist.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
}

export async function handleAlcProxy(request: Request, env: Env): Promise<Response> {
  // ── env guard ────────────────────────────────────────────────────────────
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) return jsonError(503, "server_error");
  const saKey = await resolveSecret(env.ALC_API_PROXY_SA_KEY);
  if (!saKey) return jsonError(503, "alc-proxy not configured"); // SA key binding 未設定
  const apiOrigin = env.ALC_API_ORIGIN;
  if (!apiOrigin) return jsonError(503, "server_error");
  // consumer worker proof 用の shared secret。1 つも bind されていなければ
  // proxy であることを検証できない = fail-closed で route ごと無効化 (503)。
  const sharedSecrets = await resolveAllSharedSecrets(env);
  if (!sharedSecrets) return jsonError(503, "alc-proxy not configured");

  // ── ① consumer worker proof (公開 route での直叩き / origin 詐称を弾く関門) ─
  // service binding 越しに consumer worker が付与した `X-Alc-Proxy-Secret` を
  // `INTERNAL_SHARED_SECRET*` と constant-time 比較する。これを通らない限り
  // この後で読む `X-Alc-Proxy-Origin` (caller が詐称可能) を一切信用しない。
  const proxySecret = request.headers.get(PROXY_SECRET_HEADER) ?? "";
  if (!proxySecret || !sharedSecrets.some((s) => constantTimeEquals(proxySecret, s))) {
    return jsonError(401, "Unauthorized");
  }

  // ── 認証: browser JWT (cookie / Bearer) を auth-worker がローカル検証 ───────
  const token = getAuthCookie(request) ?? extractToken(request) ?? "";
  if (!token) return jsonError(401, "Unauthorized");

  // ACL 用 origin は consumer が `X-Alc-Proxy-Origin` で渡す (= 元アプリ origin)。
  // service binding 越しでは request.url が auth-worker のものになり origin を
  // 失うため。欠落 → ACL 強制不能なので fail-closed。
  const originRaw = request.headers.get("X-Alc-Proxy-Origin") ?? "";
  let origin: string;
  try {
    origin = new URL(originRaw).origin;
  } catch {
    return jsonError(401, "Unauthorized");
  }

  const payload = await verifyJwt(token, jwtSecret, env.WORKER_ENV);
  if (!payload) return jsonError(401, "Unauthorized");
  const tenantId =
    (payload.tenant_id as string | undefined) || (payload.org as string | undefined) || "";
  const email = (payload.email as string | undefined) || "";
  const role = (payload.role as string | undefined) || "";
  const sub = (payload.sub as string | undefined) || "";

  // ── device 系 token を弾く (issue #482) ───────────────────────────────────
  // device JWT (`lib/device.ts::mintDeviceJwt`) は **browser JWT と同じ
  // `JWT_SECRET`** で署名されるので `verifyJwt` だけでは区別できない。そして
  // `POST /device/pair-internal` は `INTERNAL_SHARED_SECRET*` (= ここの
  // `X-Alc-Proxy-Secret` と**同じ secret 集合**) だけで **body の `tenant_id` を
  // そのまま採用して** credential を mint する。放置すると
  // 「secret 1 本 → 任意 tenant の device JWT → この route → `X-Tenant-ID` 詐称」
  // が成立し、`alc-internal-proxy` が path allowlist で data 経路を塞いでいる
  // 意味 (#434) が隣から無効化される。
  //
  // この route は **browser JWT 専用**。device の data 経路は
  // `/device-data-proxy` (role×path allowlist) 側にあるので、ここで弾いても
  // 正規の device 用途は失われない。
  //
  // 判定は 2 本立てにする:
  //   ① `aud` が有る → 弾く。device JWT の `aud: "device"` (#482) に加え
  //      hub-token (`aud: "hub"`) / cam-relay-token (`aud: "cam-relay"`) も
  //      同じ鍵で署名されるので一緒に落ちる。browser JWT
  //      (`lib/access-token.ts` / `lib/dev-login.ts`) は `aud` を付けない。
  //   ② `role` が `DEVICE_ROLES` に有る → 弾く。**① だけでは deploy 前に
  //      発行済みの device JWT が TTL (1h) の間そのまま通ってしまう** —
  //      既発行分には `aud` が無いため。role は既発行の token にも即効く。
  //      device JWT の role は必ず `record.role ?? DEVICE_ROLE` で、
  //      `record.role` は `normalizeDeviceRole` の allowlist を通った値なので
  //      `role ∈ DEVICE_ROLES` ⟺ device JWT が成り立つ。browser JWT の role は
  //      `admin` / `member` で重ならない。
  if (payload.aud !== undefined || DEVICE_ROLES.has(role)) {
    return jsonError(401, "Unauthorized");
  }
  if (!(await checkOrgAccess(env, origin, tenantId, email))) return jsonError(401, "Unauthorized");
  if (!checkAppTenant(env, origin, tenantId, email)) return jsonError(401, "Unauthorized");
  if (!tenantId) return jsonError(401, "Unauthorized");

  // ── token_kind=dev の read-only enforcement (issue #433) ──────────────────
  // dev-login (#423) が発行する JWT は logi_auth_token と同じ JWT_SECRET で
  // 署名されており、手動で prod host の cookie に移すと ③④ の検証をそのまま
  // 通ってしまう (#423 が「残存リスク (受容)」と明記した経路)。
  //
  // consumer 側 (`@ippoan/auth-client` の `devLoginWriteAllowlist`、#429) にも
  // 同種の allowlist があるが、あちらは opt-in かつ per-consumer で「実装/設定
  // し忘れた consumer は無防備」という弱点がある。ここでの
  // `ALC_PROXY_DEV_WRITE_ALLOWLIST` (wrangler.toml top-level `[vars]`、起動時
  // 設定) を **唯一の source of truth** とし、判定ロジックは consumer 側
  // `devLoginCore.mjs` (`isDevLoginWriteAllowed`) と同じ prefix-match
  // セマンティクスにする (safe method は常に許可、それ以外は allowlist の
  // いずれかの entry と完全一致 or `${entry}/` で始まる時のみ許可)。
  const tokenKind = (payload.token_kind as string | undefined) || "";
  const backendPath = new URL(request.url).pathname.slice(ROUTE_PREFIX.length) || "/";
  if (
    tokenKind === "dev" &&
    !isSafeMethod(request.method) &&
    !isDevWriteAllowed(backendPath, parseDevWriteAllowlist(env.ALC_PROXY_DEV_WRITE_ALLOWLIST))
  ) {
    return jsonError(403, "dev_token_write_forbidden");
  }

  // ── flip 前 preview override (Refs ippoan/ci-dashboard#472) ───────────────
  // proof (①) + JWT/ACL 通過後のみ評価する。不正値は 400 で loud fail —
  // 黙って prod に流すと「flip 前を検証したつもりで prod を叩いていた」事故に
  // なるため、fallback しない。
  let targetOrigin = apiOrigin;
  const previewBase = request.headers.get(PREVIEW_BASE_HEADER);
  if (previewBase) {
    const previewOrigin = validatePreviewBase(
      previewBase,
      env.ALC_API_PREVIEW_HOST_SUFFIX ?? "",
    );
    if (!previewOrigin) return jsonError(400, "invalid preview override");
    targetOrigin = previewOrigin;
  }

  // ── OIDC mint (Cloud Run IAM lockdown 用)。aud = forward 先 service URL ──
  let idToken: string;
  try {
    idToken = await mintGoogleIdToken(saKey, targetOrigin);
  } catch {
    return jsonError(502, "upstream auth error"); // 詳細は log のみ (ここでは出さない)
  }

  // ── forward: targetOrigin + (/alc-proxy 以降の path) ──────────────────────
  // (backendPath は上の #433 enforcement で計算済みのものを再利用)
  const url = new URL(request.url);
  const target = `${targetOrigin.replace(/\/$/, "")}${backendPath}${url.search}`;

  const fwdHeaders: Record<string, string> = {
    Authorization: `Bearer ${idToken}`,
    "X-Tenant-ID": tenantId,
  };
  if (sub) fwdHeaders["X-User-ID"] = sub;
  if (email) fwdHeaders["X-User-Email"] = email;
  if (role) fwdHeaders["X-User-Role"] = role;
  const contentType = request.headers.get("content-type");
  if (contentType) fwdHeaders["Content-Type"] = contentType;

  const method = request.method;
  const hasBody = method !== "GET" && method !== "HEAD";
  const body = hasBody ? await request.arrayBuffer() : undefined;

  return fetch(target, { method, headers: fwdHeaders, body });
}

export { ROUTE_PREFIX as ALC_PROXY_PREFIX };
