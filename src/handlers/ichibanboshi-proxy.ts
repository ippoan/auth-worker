/**
 * `/ichibanboshi-proxy/*` — dtako relay が **打刻 (タイムカード) を GCP 側の
 * rust-ichibanboshi へ渡す**ための proxy (Refs ohishi-exp/rust-ichibanboshi#205 の 04b)。
 *
 * オンプレの rust-ichibanboshi は社内 MariaDB から打刻を読めるが、GCP 側の同じ
 * バイナリは読めない。そこでオンプレが読んで relay 経由で GCP へ渡し、畳むのは
 * GCP 側にする。その経路の最後の hop がここ:
 *
 *   オンプレ rust-ichibanboshi (`[kintai_send]`)
 *     → dtako relay (`nuxt-dtako-admin-scraper-relay`、KV から tenant を解決)
 *     → **ここ** (service binding、OIDC mint)
 *     → rust-ichibanboshi (Cloud Run、`--no-allow-unauthenticated`)
 *
 * `alc-internal-proxy.ts` と同じ形だが**別 backend・別 SA** にする
 * (`ohishi-logi-proxy.ts` が `ALC_API_PROXY_SA_KEY` と SA を分けているのと同じ理由 —
 * blast radius を service 単位で切る)。
 *
 *   ① consumer worker proof — `X-Alc-Proxy-Secret` を constant-time 比較 (fail-closed)。
 *   ② path allowlist — 打刻の経路と、その畳み直しのみ。method も固定する。
 *   ③ tenant — `X-Tenant-ID` 必須。**relay が KV から解決した値**で、ここでは検証しない
 *      (relay を shared secret で信用する = alc-internal-proxy の `shared-secret` と同じ扱い)。
 *   ④ OIDC mint — `ICHIBANBOSHI_PROXY_SA_KEY` (run.invoker) で aud=service URL。
 *   ⑤ forward — `ICHIBANBOSHI_ORIGIN` + path。
 *
 * ## なぜ browser JWT の tenant を使わないのか
 *
 * この経路は cron / 無人で走り browser JWT を持たない。かつ `comp_id` は複数 tenant に
 * またがりうるので、トリガーした管理者の tenant と一致する保証が無い。relay の
 * `alc-internal-upload.ts` が `alc-proxy` (JWT の tenant 逆引き) を不採用にしたのと
 * 同じ理由で、**tenant は `DTAKO_ACCOUNTS` (comp_id → tenant_id) から解決した値**を
 * 明示 `X-Tenant-ID` で運ぶ。
 *
 * 値 (OIDC / SA key / shared secret) は log / response に出さない。
 */
import type { Env } from "../index";
import { resolveSecret } from "../lib/secret";
import { mintGoogleIdToken } from "../lib/oidc";
import { resolveAllSharedSecrets } from "./mcp-introspect";

const ROUTE_PREFIX = "/ichibanboshi-proxy";

/** consumer worker proof を運ぶ header (`/alc-internal-proxy` と共通)。 */
const PROXY_SECRET_HEADER = "X-Alc-Proxy-Secret";

/**
 * forward を許可する (path, method) の組。**完全一致**で持つ。
 *
 * `ohishi-logi-proxy` は prefix 一致だが、あちらは動的セグメント (日付/ファイル名) を
 * 持つ RPC surface だからで、こちらは数本しか無い。prefix にすると
 * `/api/kintai/*` の読み出し経路 (`/daily` `/kosoku-daily` 等) まで開いてしまう。
 *
 * **テナントをリクエストが名乗れる読み出し経路をここに足さないこと**
 * (`/daily` `/kosoku-daily` `/events` 等)。この関門は `X-Tenant-ID` を素直に信用する —
 * relay が KV から解決した値を握っている前提の ingest 用だから。受け口が
 * `X-Tenant-ID` で読み先を決める口を同じ関門に通すと、shared secret だけで他テナントの
 * データを引けることになる (`alc-internal-proxy` が data 経路を弾いている理由と同じ)。
 *
 * GET が混じっているのはこの線引きによる。
 *
 *   - `signatures` (相手が既に持っている署名) と `recalc` の preview (畳み直すと何件
 *     変わるか) が返すのは**運ぶ手順そのものの状態** — 乗務員CD と件数 — であって、
 *     勤務時間や賃金は載らない。
 *   - `day-summaries` は勤務データ (分数) を返すが、**受け口が `X-Tenant-ID` を読まない**
 *     — 読み先は instance の設定 (`[kintai_events] tenant_id`) で固定されている
 *     (`rust-ichibanboshi` の `src/routes/kintai_day_summaries.rs`)。ヘッダを差し替えても
 *     引ける先が変わらないので、上の「他テナントを名乗れる」根拠が当たらない。
 *     **金額は含まない** (識別情報 + 分数のみ) ので `/kyuyo/*` と同じ in-service gate
 *     側でもない。
 *
 * **受け口がヘッダでテナントを決めるように変わったら、その entry をここから外すこと。**
 * この allowlist が安全なのは受け口の実装が設定 pin だからで、ヘッダ方式に倒れた瞬間に
 * 根拠が静かに崩れる。
 */
const ALLOWED: ReadonlyArray<{ path: string; method: string }> = [
  // **窓ぶんをまるごと受けて、変わった日だけ書く** (ohishi-exp/rust-ichibanboshi#228)。
  // いまの経路はこれ 1 本で、GCP への往復は 1 回だけ
  { path: "/api/kintai/timecard/window", method: "POST" },
  // 全量再計算 (ohishi-exp/rust-ichibanboshi#237)。窓の受け口が畳み直すのは打刻が
  // 変わった乗務員だけなので、`kosoku.rs` の deploy や TOML の閾値変更で**全乗務員が
  // 一斉に stale** になる側はこちらが受け持つ (`after_driver_cd` でページングする)。
  //
  // **書けるのは POST だけ。** GET は preview で 1 行も書かない (受け口側が
  // `apply` を POST の body にしか置いていない)。ここで両方 POST にすると
  // 「読むだけのつもりが全乗務員を書き直す」を method の打ち間違いで作れてしまう
  { path: "/api/kintai/recalc", method: "POST" },
  { path: "/api/kintai/recalc", method: "GET" },
  // 畳んだ結果の読み出し (ohishi-exp/rust-ichibanboshi#205 の 18)。オンプレ基準との
  // 突合を総数から**行単位**へ上げるための口で、`乗務員CD|暦日|開始時刻` をキーに
  // 分数 11 列を返す。
  //
  // **GET だけ。** 受け口に `POST` は無い (1 行も書かない口)。ここに書き込み側を
  // 足さないこと — 足すなら受け口の doc と合わせて別 PR で
  { path: "/api/kintai/day-summaries", method: "GET" },
  // 以下 2 本は旧経路 (乗務員ごとに署名を引いて差分だけ運ぶ)。まだ外していない —
  // 窓の経路が本番で回りきったら別 PR で削る
  { path: "/api/kintai/timecard", method: "POST" },
  { path: "/api/kintai/timecard/signatures", method: "GET" },
];

function isAllowed(path: string, method: string): boolean {
  return ALLOWED.some((a) => a.path === path && a.method === method);
}

/** 定数時間比較 (alc-internal-proxy.ts と同実装)。 */
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

export async function handleIchibanboshiProxy(request: Request, env: Env): Promise<Response> {
  // ── env guard ────────────────────────────────────────────────────────────
  const saKey = await resolveSecret(env.ICHIBANBOSHI_PROXY_SA_KEY);
  if (!saKey) return jsonError(503, "ichibanboshi-proxy not configured"); // SA key 未設定
  const apiOrigin = env.ICHIBANBOSHI_ORIGIN;
  if (!apiOrigin) return jsonError(503, "ichibanboshi-proxy not configured");
  const sharedSecrets = await resolveAllSharedSecrets(env);
  if (!sharedSecrets) return jsonError(503, "ichibanboshi-proxy not configured");

  // ── ① consumer worker proof ───────────────────────────────────────────────
  const proxySecret = request.headers.get(PROXY_SECRET_HEADER) ?? "";
  if (!proxySecret || !sharedSecrets.some((s) => constantTimeEquals(proxySecret, s))) {
    return jsonError(401, "Unauthorized");
  }

  // ── ② path + method allowlist ─────────────────────────────────────────────
  const url = new URL(request.url);
  const backendPath = url.pathname.slice(ROUTE_PREFIX.length) || "/";
  // percent-encoding された `..` が forward 先で decode されて別 path に化けるのを
  // proxy 層で潰す (ohishi-logi-proxy.ts と同じ defense-in-depth)。
  if (backendPath.includes("%") || backendPath.includes("..") || backendPath.includes("\\")) {
    return jsonError(403, "forbidden");
  }
  if (!isAllowed(backendPath, request.method)) return jsonError(403, "forbidden");

  // ── ③ tenant ──────────────────────────────────────────────────────────────
  // relay が KV (`dtako-relay-config` の `dtako_accounts`) から comp_id で引いた値。
  // 欠落は 400 — 受け口側も pin が無ければ 400 で断るが、**ここで先に落とす**。
  // 素通しすると「tenant を名乗らないまま Cloud Run を 1 回叩く」が成立してしまう。
  const tenantId = request.headers.get("X-Tenant-ID")?.trim() ?? "";
  if (!tenantId) return jsonError(400, "X-Tenant-ID required");

  // ── ④ OIDC mint (Cloud Run IAM lockdown 用、aud=service URL) ───────────────
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
    "X-Tenant-ID": tenantId,
  };
  const contentType = request.headers.get("content-type");
  if (contentType) fwdHeaders["Content-Type"] = contentType;

  const method = request.method;
  const hasBody = method !== "GET" && method !== "HEAD";
  const body = hasBody ? await request.arrayBuffer() : undefined;

  return fetch(target, { method, headers: fwdHeaders, body });
}

export { ROUTE_PREFIX as ICHIBANBOSHI_PROXY_PREFIX, isAllowed as ichibanboshiProxyAllows };
