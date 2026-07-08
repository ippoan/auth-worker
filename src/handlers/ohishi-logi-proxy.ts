/**
 * `/ohishi-logi-proxy/*` — cf-flickr-cam-worker (Cloudflare Worker、無人 cron)
 * が device JWT で ohishi-logi (Cloud Run、無状態 camera fetcher) の `/cam/*`
 * RPC を叩くための proxy (Refs ohishi-exp/ohishi-logi#1,
 * ippoan/cf-flickr-cam-worker#1)。`device-data-proxy.ts` (rust-alc-api 向け、
 * tenant 束縛あり) と同じ device JWT 検証 + OIDC mint + Cloud Run IAM lockdown
 * パターンを ohishi-logi 向けに適用する。
 *
 * ohishi-logi は tenant/RLS を持たない無状態 backend なので
 * `device-data-proxy.ts` と違い X-Tenant-ID は注入しない。role は
 * `device-cam-flickr` 1 つのみを受理し、転送を許可する path は `/cam/` 配下に
 * 限定する (ohishi-logi の RPC surface は `/cam/dates` 等、date/hour/file name
 * を含む動的セグメントを持つため、`device-data-proxy.ts` の完全一致 Set ではなく
 * prefix 一致で判定する)。
 *
 *   ① `Authorization: Bearer <device JWT>` を `verifyJwt` で検証。
 *   ② `payload.role === DEVICE_ROLE_CAM_FLICKR` かつ path が `/cam/` 配下のみ許可。
 *   ③ `OHISHI_LOGI_PROXY_SA_KEY` (run.invoker) で aud=service URL の OIDC を mint。
 *   ④ `OHISHI_LOGI_ORIGIN` + path へ forward する。
 *
 * ohishi-logi 側は無変更 — 通常の `/cam/*` RPC をそのまま叩くだけで良い
 * (proxy が identity 検証済みという rust-alc-api#434 と同じ dumb backend 前提)。
 *
 * 値 (OIDC / SA key / device JWT) は log / response に出さない。
 */
import type { Env } from "../index";
import { extractToken } from "../lib/errors";
import { verifyJwt } from "../lib/jwt";
import { resolveSecret } from "../lib/secret";
import { mintGoogleIdToken } from "../lib/oidc";
import { DEVICE_ROLE_CAM_FLICKR } from "../lib/device";

const ROUTE_PREFIX = "/ohishi-logi-proxy";

/** 転送を許可する backend path の prefix。ohishi-logi の RPC surface はここに集約されている。 */
const ALLOWED_PATH_PREFIX = "/cam/";

function jsonError(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export async function handleOhishiLogiProxy(request: Request, env: Env): Promise<Response> {
  // ── env guard ────────────────────────────────────────────────────────────
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) return jsonError(503, "server_error");
  const saKey = await resolveSecret(env.OHISHI_LOGI_PROXY_SA_KEY);
  if (!saKey) return jsonError(503, "ohishi-logi-proxy not configured"); // SA key binding 未設定
  const apiOrigin = env.OHISHI_LOGI_ORIGIN;
  if (!apiOrigin) return jsonError(503, "server_error");

  // ── ① device JWT 検証 (browser JWT と同じ検証関数・同じ HS256 secret) ────────
  const token = extractToken(request) ?? "";
  if (!token) return jsonError(401, "Unauthorized");
  const payload = await verifyJwt(token, jwtSecret, env.WORKER_ENV);
  if (!payload) return jsonError(401, "Unauthorized");

  const role = (payload.role as string | undefined) || "";
  if (!role) return jsonError(401, "Unauthorized");

  // ── ② role + path allowlist (盗難時の blast radius を role・path 単位で限定) ──
  if (role !== DEVICE_ROLE_CAM_FLICKR) return jsonError(403, "forbidden");
  const url = new URL(request.url);
  const backendPath = url.pathname.slice(ROUTE_PREFIX.length) || "/";
  // percent-encoding (`%2e%2e` 等) はここでは decode しない — allowlist が見た
  // 生の path と forward 先が見る path が食い違うと prefix chek を回避できて
  // しまうため、`%` を含む path はまるごと拒否する (ohishi-logi 側の axum が
  // decode して初めて `..` になる余地を proxy 層で潰す、defense-in-depth)。
  if (backendPath.includes("%") || backendPath.includes("..") || backendPath.includes("\\")) {
    return jsonError(403, "forbidden");
  }
  if (!backendPath.startsWith(ALLOWED_PATH_PREFIX)) return jsonError(403, "forbidden");

  // ── ③ OIDC mint (Cloud Run IAM lockdown 用、aud=service URL) ────────────────
  let idToken: string;
  try {
    idToken = await mintGoogleIdToken(saKey, apiOrigin);
  } catch {
    return jsonError(502, "upstream auth error"); // 詳細は log のみ
  }

  // ── ④ forward ────────────────────────────────────────────────────────────
  const target = `${apiOrigin.replace(/\/$/, "")}${backendPath}${url.search}`;
  const method = request.method;
  const hasBody = method !== "GET" && method !== "HEAD";
  const body = hasBody ? await request.arrayBuffer() : undefined;

  return fetch(target, {
    method,
    headers: { Authorization: `Bearer ${idToken}` },
    body,
  });
}

export { ROUTE_PREFIX as OHISHI_LOGI_PROXY_PREFIX };
