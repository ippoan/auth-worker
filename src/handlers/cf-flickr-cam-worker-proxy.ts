/**
 * `/cf-flickr-cam-worker-proxy/*` — Flickr OAuth1.0a の callback (ブラウザ経由
 * リダイレクト) と運用者向け UI (`/oauth/start` / `/` / `/images`) だけを公開
 * するための最小限 proxy (Refs ippoan/cf-flickr-cam-worker#3,
 * ippoan/cf-flickr-cam-worker#4)。
 *
 * `cf-flickr-cam-worker` 自体は `workers_dev: false` で完全非公開化した。
 * 到達経路はここだけになる:
 *
 *   Flickr / 運用者ブラウザ → auth.ippoan.org/cf-flickr-cam-worker-proxy/*
 *     → (CF Access Application が path-scoped で保護、edge で未認証を弾く —
 *        本 handler は認証を検証しない。境界は CF Access 側)
 *     → service binding (`env.CF_FLICKR_CAM_WORKER`、SA key/OIDC 不要) →
 *       cf-flickr-cam-worker
 *
 * 既存の `ohishi-logi-proxy.ts` (device JWT) / `alc-proxy.ts` (JWT + per-tenant
 * ACL + OIDC mint) はどちらも「単一運用者・ブラウザ OAuth リダイレクト」用途
 * にはオーバースペック/不適合と判断し、本 proxy は path 転送のみを行う。
 */
import type { Env } from "../index";

const ROUTE_PREFIX = "/cf-flickr-cam-worker-proxy";

function jsonError(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export async function handleCfFlickrCamWorkerProxy(request: Request, env: Env): Promise<Response> {
  const service = env.CF_FLICKR_CAM_WORKER;
  if (!service) return jsonError(503, "cf-flickr-cam-worker-proxy not configured"); // service binding 未設定

  const url = new URL(request.url);
  const backendPath = url.pathname.slice(ROUTE_PREFIX.length) || "/";
  // ohishi-logi-proxy.ts と同じ defense-in-depth: percent-encoding された
  // `..` 等が forward 先で decode されて別 path に化けるのを proxy 層で潰す。
  if (backendPath.includes("%") || backendPath.includes("..") || backendPath.includes("\\")) {
    return jsonError(403, "forbidden");
  }

  const target = `${url.origin}${backendPath}${url.search}`;
  const method = request.method;
  const hasBody = method !== "GET" && method !== "HEAD";
  const body = hasBody ? await request.arrayBuffer() : undefined;

  // `redirect: "manual"` が必須 — 既定 (follow) だと Flickr OAuth callback
  // (`/oauth/start` が 302 で Location: https://www.flickr.com/... を返す) を
  // service binding の fetch が自動追跡してしまい、**binding 先の
  // cf-flickr-cam-worker 自身が再度呼ばれる** (service binding は URL の
  // hostname でなく binding 先に固定でルーティングされるため)。存在しない
  // path (`/services/oauth/authorize` 等) に当たり Hono の 404 を返していた
  // 実害を manual 指定で回避する — 302 はそのままクライアント (ブラウザ/Flickr)
  // に返し、実際のリダイレクト追跡はクライアント側に委ねる。
  return service.fetch(target, {
    method,
    headers: request.headers,
    body,
    redirect: "manual",
  });
}

export { ROUTE_PREFIX as CF_FLICKR_CAM_WORKER_PROXY_PREFIX };
