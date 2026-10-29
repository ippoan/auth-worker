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
 *      同じ `JWT_SECRET` で署名されるので署名だけでは区別できない (#482)。この
 *      route は browser JWT 専用で、device 系 token はここでは受けない
 *      (device の data 経路は `/device-data-proxy` 側)
 *   ③ 認証・ACL 通過後、`X-Tenant-ID` / `X-User-ID/Email/Role` を注入して
 *      domain worker (Service Binding、`ALC_BINDING_ROUTES`) へ forward
 * を 1 箇所で行う。
 *
 * W9 (Refs ippoan/rust-alc-api#680): Cloud Run (rust-alc-api) への fallback・OIDC mint・
 * flip 前 preview override (`X-Alc-Preview-Api-Base`) は撤去した。me / logout / LINE WORKS
 * callback URL は session / hook helper が答え、それ以外は binding 表に当たらなければ 404
 * (`X-Alc-Preview-Api-Base` は無視する)。
 *
 * 値 (token / SA key / OIDC / shared secret) は log / response に出さない。
 */
import type { Env } from "../index";
import { getAuthCookie } from "../lib/cookies";
import { extractToken } from "../lib/errors";
import { verifyJwt } from "../lib/jwt";
import { checkAppTenant, checkOrgAccess } from "../lib/acl";
import { resolveSecret } from "../lib/secret";
import {
  forwardViaAlcBinding,
  isUnsafeBackendPath,
  resolveAlcBinding,
} from "../lib/alc-backend-route";
import { DEVICE_ROLES } from "../lib/device";
import { isDeveloperGoogleSession } from "../lib/developer";
import { handleSessionPath } from "../lib/alc-session";
import { handleWebhookUrlPath, WEBHOOK_URL_PATH } from "../lib/lineworks-hook-id";
import { resolveAllSharedSecrets } from "./mcp-introspect";

const ROUTE_PREFIX = "/alc-proxy";

/** consumer worker proof を運ぶ header。`INTERNAL_SHARED_SECRET*` の生値を載せる。 */
const PROXY_SECRET_HEADER = "X-Alc-Proxy-Secret";

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
  // `JWT_SECRET`** で署名されるので `verifyJwt` だけでは区別できない。
  //
  // この route は **browser JWT 専用**。device 系 token はこの route では
  // 受けない — device の data 経路は `/device-data-proxy`
  // (role×path allowlist) 側にあるので、ここで弾いても正規の device 用途は
  // 失われない。
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
  // `device-key` (issue #522、警告デバイス VoiceS3R の ed25519 署名ログイン) も
  // `token_kind: "dev"` と同じ read-only enforcement に並べる — 発行経路が違う
  // だけで「本人以外が持ち出した token が prod host に置かれた時のリスク」の
  // 形は同じため。
  const tokenKind = (payload.token_kind as string | undefined) || "";
  const backendPath = new URL(request.url).pathname.slice(ROUTE_PREFIX.length) || "/";
  if (
    (tokenKind === "dev" || tokenKind === "device-key") &&
    !isSafeMethod(request.method) &&
    !isDevWriteAllowed(backendPath, parseDevWriteAllowlist(env.ALC_PROXY_DEV_WRITE_ALLOWLIST))
  ) {
    return jsonError(403, "dev_token_write_forbidden");
  }

  // ── forward: (/alc-proxy 以降の path) を domain worker へ ──────────────────────
  // (backendPath は上の #433 enforcement で計算済みのものを再利用)
  const url = new URL(request.url);

  const fwdHeaders: Record<string, string> = {
    "X-Tenant-ID": tenantId,
  };
  if (sub) fwdHeaders["X-User-ID"] = sub;
  if (email) fwdHeaders["X-User-Email"] = email;
  if (role) fwdHeaders["X-User-Role"] = role;
  // 宛先 (社内 IP) を書ける「システム管理者」の判定を DEVELOPER_EMAILS 1 か所に寄せる。
  // fwdHeaders は毎回作り直すのでクライアントの同名ヘッダは届かない (Refs ippoan/alc-cam#2)
  if (
    isDeveloperGoogleSession({
      email,
      tokenKind,
      idp: (payload.idp as string | undefined) || "",
    })
  ) {
    fwdHeaders["X-User-Developer"] = "1";
  }
  // 開発の軸 (dev端末の行) を見る検証用 token (MCP `verify_eval` / `verify_screenshot` の `dev_axis`)。
  // 印は auth-worker 自身が署名した claim だけから読み、`token_kind: "dev"` (上で読み取り専用に絞った token) に限る。
  // fwdHeaders は毎回作り直すのでクライアントの同名ヘッダは届かない
  if (tokenKind === "dev" && payload.dev_axis === true) fwdHeaders["X-Device-Dev"] = "1";
  const perms = permissionsHeaderValue(payload.perms);
  if (perms) fwdHeaders["X-User-Permissions"] = perms;
  const contentType = request.headers.get("content-type");
  if (contentType) fwdHeaders["Content-Type"] = contentType;
  // 部分取得 (動画のシーク等) の Range を渡す。応答 (206 + Content-Range) は下でそのまま返すので、
  // ここで渡さないと backend が毎回 200 で丸ごと返し、ブラウザはシークできない (ippoan/alc-cam の切り出し)
  const range = request.headers.get("range");
  if (range) fwdHeaders["Range"] = range;

  const method = request.method;
  const hasBody = method !== "GET" && method !== "HEAD";
  const body = hasBody ? await request.arrayBuffer() : undefined;

  // ── domain worker (Service Binding) への振り分け ─────────────────────────
  // 認証・ACL・ヘッダ付け直しは上で完了済み。binding 未定義 / 表に無い path は 404
  // (W9 で Cloud Run fallback を撤去、Refs ippoan/rust-alc-api#680)。
  // me・logout は alc-auth-worker から答える (判定は lib/alc-session.ts の 1 か所)。
  const session = await handleSessionPath(env, backendPath, method, { tenantId, sub, email, role });
  if (session) return session;
  // LINE WORKS の callback URL (tenant を暗号化した識別子) も auth-worker が答える (鍵はここにしか無い)
  const hookUrl = await handleWebhookUrlPath(
    backendPath === WEBHOOK_URL_PATH ? await resolveSecret(env.SSO_ENCRYPTION_KEY) : null,
    backendPath,
    method,
    url.search,
    { tenantId, role },
  );
  if (hookUrl) return hookUrl;
  const binding = resolveAlcBinding(backendPath, env, "browser", method);
  if (!binding) return jsonError(404, "not_found");
  if (isUnsafeBackendPath(backendPath)) return jsonError(403, "forbidden");
  return forwardViaAlcBinding(binding, backendPath, url.search, {
    method,
    headers: fwdHeaders,
    body,
  });
}

/** 権限の文字列として下流へ渡してよい形 (`leave.use`・`*` 等)。 */
const PERMISSION_RE = /^[a-z*][a-z0-9.*_-]*$/;

/**
 * 検証済み JWT の `perms` claim (`lib/access-token.ts`) から `X-User-Permissions` の値
 * (空白区切り) を作る (Refs ohishi-exp/rust-leave-worker#1)。配列でない・形に合わない値は捨て、
 * 1 つも残らなければ null (ヘッダを付けない)。
 */
export function permissionsHeaderValue(perms: unknown): string | null {
  if (!Array.isArray(perms)) return null;
  const valid = perms.filter((p): p is string => typeof p === "string" && PERMISSION_RE.test(p));
  return valid.length > 0 ? valid.join(" ") : null;
}

export { ROUTE_PREFIX as ALC_PROXY_PREFIX };
