/**
 * 機械の入口 `ANY /m/<purpose>/<rest...>` (Refs ohishi-exp/rust-leave-worker#1)。
 *
 * 複合機・PC のように人のログインができない送り手が、機械用資格情報 (`lib/machine-credential.ts`) の
 * HTTP Basic で入ってくる口。アプリごとに Cloudflare Access の素通しアプリを作らずに済むよう、
 * 機械の入口を auth-worker (Access の外) 1 か所にまとめる。
 *
 * - 用途 (purpose) ごとの転送先は `MACHINE_RELAY_ROUTES` の 1 か所。表に無い用途は 404
 *   - `leave-scan` → nuxt-leave (`LEAVE_APP`) の `/dav/*` (複合機のスキャン)
 *   - `fuel-utran` → rust-fuel-worker (`FUEL_WORKER`) の `/machine/fuel-utran/*` (Windows の USB 常駐アプリの
 *     取り込み。Refs yhonda-ohishi/nginx#814)
 * - Basic が無い・通らない → 401 + `WWW-Authenticate: Basic` (理由は区別しない。複合機は 401 を見てから
 *   Basic を付け直す)
 * - 通れば、method・ヘッダ・本文を**そのまま中継**し、応答もそのまま返す (本文はストリームのまま渡し、
 *   保存も解析もしない)。`Authorization` は残す — 転送先 (nuxt-leave) がそれで `issueTicket` を呼ぶ
 * - 中継のときに `X-Internal-Shared-Secret` を付ける (転送先はこれが無い要求を 404 にする)
 * - ★ **この口では tenant を決めない・`X-Tenant-ID` を付けない** (#434)。送り手が付けてきた内部用の
 *   ヘッダ (`X-Internal-*` / `X-Tenant-*` / `X-User-*` / `X-Alc-*`) と Cookie は中継の前に消す (詐称対策)。
 *   tenant を決めるのは、転送先が呼ぶ RPC (`MachineCredentialEntrypoint`) の中の auth-worker だけ
 */
import type { Env } from "../index";
import { verifyBasic } from "../lib/machine-credential";
import { resolveSecret } from "../lib/secret";

interface MachineRelayRoute {
  /** 転送先の Service Binding の名前 (`Env` の key)。 */
  binding: "LEAVE_APP" | "FUEL_WORKER";
  /** 転送先の path の接頭辞。`/m/<purpose>` をこれに置き換える。 */
  pathPrefix: string;
}

/** 用途 → 転送先。用途を足すときは `MACHINE_CRED_PURPOSES` と併せてここに足す。 */
export const MACHINE_RELAY_ROUTES: Readonly<Record<string, MachineRelayRoute>> = {
  "leave-scan": { binding: "LEAVE_APP", pathPrefix: "/dav" },
  "fuel-utran": { binding: "FUEL_WORKER", pathPrefix: "/machine/fuel-utran" },
};

/** Service Binding 越しの fetch なので host は使われない (path と query だけが意味を持つ)。 */
const RELAY_ORIGIN = "https://machine-relay.internal";

const RELAY_RE = /^\/m\/([^/]+)(\/.*)?$/;

/** 送り手から受け取らないヘッダ (接頭辞は小文字で比較)。 */
const STRIPPED_HEADER_PREFIXES = ["x-internal-", "x-tenant-", "x-user-", "x-alc-"];
const STRIPPED_HEADERS = ["cookie", "host"];

function unauthorized(purpose: string): Response {
  return new Response(JSON.stringify({ error: "Unauthorized" }), {
    status: 401,
    headers: {
      "Content-Type": "application/json",
      "WWW-Authenticate": `Basic realm="${purpose}", charset="UTF-8"`,
    },
  });
}

function jsonError(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** `/m/` で始まる path だけを受ける (index.ts が振り分ける)。 */
export async function handleMachineRelay(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const m = RELAY_RE.exec(url.pathname);
  const purpose = m?.[1] ?? "";
  const route = Object.prototype.hasOwnProperty.call(MACHINE_RELAY_ROUTES, purpose) ? MACHINE_RELAY_ROUTES[purpose] : undefined;
  if (!m || !route) return jsonError(404, "Not found");

  const authorization = request.headers.get("Authorization");
  if (!authorization || !(await verifyBasic(env, authorization, purpose))) {
    return unauthorized(purpose);
  }

  const target = env[route.binding];
  const sharedSecret = await resolveSecret(env.INTERNAL_SHARED_SECRET);
  if (!target || !sharedSecret) return jsonError(503, "relay_unavailable");

  const headers = new Headers();
  for (const [name, value] of request.headers) {
    const lower = name.toLowerCase();
    if (STRIPPED_HEADERS.includes(lower)) continue;
    if (STRIPPED_HEADER_PREFIXES.some((p) => lower.startsWith(p))) continue;
    headers.append(name, value);
  }
  headers.set("X-Internal-Shared-Secret", sharedSecret);

  const targetUrl = `${RELAY_ORIGIN}${route.pathPrefix}${m[2] ?? "/"}${url.search}`;
  const init: RequestInit & { duplex?: "half" } = {
    method: request.method,
    headers,
    body: request.body,
    redirect: "manual",
  };
  // 本文をストリームのまま渡すときの指定 (Workers は無視、Node の fetch では必須)。
  if (request.body) init.duplex = "half";
  return target.fetch(new Request(targetUrl, init));
}
