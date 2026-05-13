/**
 * `GET /device` — Device authorization 入口ページ。
 *
 * `verification_uri_complete` (RFC 8628 §3.3.1) からのアクセスでは
 * `?user_code=XXXX-XXXX` クエリで pre-fill される。直接 `/device` を開いた
 * 場合は空フォームを表示。
 *
 * 短い alias `?code=...` も accept (CLI が短縮 URL を生成する場合への配慮)。
 */

import type { Env } from "../index";
import { renderDevicePage } from "../lib/mcp-device-html";

function htmlResponse(html: string, status = 200): Response {
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

export function handleMcpDevicePage(request: Request, env: Env): Response {
  const url = new URL(request.url);
  const code =
    (url.searchParams.get("user_code") ?? url.searchParams.get("code") ?? "").trim();
  const issuer = env.AUTH_WORKER_ORIGIN || "https://auth.ippoan.org";
  return htmlResponse(
    renderDevicePage({
      prefilledCode: code || undefined,
      issuer,
    }),
  );
}
