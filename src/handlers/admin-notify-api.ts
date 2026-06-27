/**
 * /admin/notify/api/* — admin/notify ページ専用の rust-alc-api forward proxy
 * (Refs rust-alc-api#434)。
 *
 * 旧実装: admin/notify ページの client JS が rust Cloud Run を **直叩き**
 * (`fetch(ALC_API + '/api/notify/...', { Authorization: Bearer })`) していた。
 * #434 で rust は Bearer を検証せず `X-Tenant-ID` 注入を要求する dumb backend に
 * なったため、直叩きは tenant header 不在で **401** になっていた。
 *
 * 本 handler が trusted proxy として cookie/Bearer の JWT を `JWT_SECRET` で検証し
 * (`buildAdminForwardHeaders`)、検証済み identity を注入して rust へ転送する
 * (api-line-users / api-sso / api-bot-config と同方針)。allowlist は admin/notify が
 * 使う `/notify/*` 配下のみ (least privilege)。
 */
import type { Env } from "../index";
import { buildAdminForwardHeaders, debugRustResponse } from "../lib/admin-proxy";

const PREFIX = "/admin/notify/api";

function extractToken(request: Request): string | null {
  const auth = request.headers.get("Authorization");
  if (auth?.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

function jsonError(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export async function handleAdminNotifyApi(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  // PREFIX 以降が rust の /api 配下 sub-path。admin/notify が使う /notify/* のみ許可。
  const sub = url.pathname.slice(PREFIX.length);
  if (!sub.startsWith("/notify/")) {
    return jsonError("forbidden path", 403);
  }

  const token = extractToken(request);
  if (!token) return jsonError("Unauthorized", 401);

  const headers = await buildAdminForwardHeaders(token, env, "admin_notify_api");
  if (!headers) return jsonError("Unauthorized", 401);

  const method = request.method.toUpperCase();
  const hasBody = method !== "GET" && method !== "HEAD";
  let body: string | undefined;
  if (hasBody) {
    body = await request.text();
    // JSON body のときは Content-Type を引き継ぐ (rust の extractor 用)。
    const ct = request.headers.get("Content-Type");
    if (ct) headers["Content-Type"] = ct;
  }

  const target = `${env.ALC_API_ORIGIN}/api${sub}${url.search}`;
  const resp = await fetch(target, { method, headers, body });

  const text = await resp.text();
  if (!resp.ok) debugRustResponse(env, "admin_notify_api", resp.status, text);
  return new Response(text, {
    status: resp.status,
    headers: {
      "Content-Type": resp.headers.get("Content-Type") ?? "application/json",
    },
  });
}
