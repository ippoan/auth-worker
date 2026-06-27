/**
 * LINE ユーザー管理 API endpoints
 * Client JS → auth-worker API → rust-alc-api REST API (/api/notify/recipients)
 *
 * LINE Login ユーザー (= notify_recipients のうち line_user_id を持つ行) の
 * 一覧 / 削除を proxy する。rust の tenant routes は require_tenant_header なので
 * buildAdminForwardHeaders で X-Tenant-ID を注入して叩く (SSO 設定と同方針)。
 */

import type { Env } from "../index";
import {
  buildAdminForwardHeaders,
  debugRustResponse,
} from "../lib/admin-proxy";

interface NotifyRecipient {
  id: string;
  name: string;
  line_user_id: string | null;
  lineworks_user_id: string | null;
  phone_number: string | null;
  email: string | null;
  enabled: boolean;
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function extractToken(request: Request): string | null {
  const auth = request.headers.get("Authorization");
  if (auth?.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

/** POST /api/line-users/list — LINE Login recipient (line_user_id あり) の一覧 */
export async function handleLineUsersList(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  console.log(JSON.stringify({ event: "line_users_list" }));

  const headers = await buildAdminForwardHeaders(token, env, "line_users_list");
  if (!headers) return jsonResponse({ error: "Unauthorized" }, 401);

  const resp = await fetch(`${env.ALC_API_ORIGIN}/api/notify/recipients`, {
    headers,
  });
  if (!resp.ok) {
    const text = await resp.text();
    debugRustResponse(env, "line_users_list", resp.status, text);
    return jsonResponse({ error: text }, resp.status);
  }

  const all = (await resp.json()) as NotifyRecipient[];
  const lineUsers = (Array.isArray(all) ? all : [])
    .filter((r) => r.line_user_id)
    .map((r) => ({
      id: r.id,
      name: r.name,
      lineUserId: r.line_user_id,
      enabled: r.enabled,
    }));

  return jsonResponse({ recipients: lineUsers });
}

/** POST /api/line-users/delete — recipient を削除 (body: { id }) */
export async function handleLineUserDelete(
  request: Request,
  env: Env,
): Promise<Response> {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: "Unauthorized" }, 401);

  const body = (await request.json().catch(() => ({}))) as { id?: string };
  const id = body.id;
  if (!id) return jsonResponse({ error: "id is required" }, 400);

  console.log(JSON.stringify({ event: "line_user_delete", id }));

  const headers = await buildAdminForwardHeaders(token, env, "line_user_delete");
  if (!headers) return jsonResponse({ error: "Unauthorized" }, 401);

  const resp = await fetch(
    `${env.ALC_API_ORIGIN}/api/notify/recipients/${encodeURIComponent(id)}`,
    { method: "DELETE", headers },
  );
  if (!resp.ok) {
    const text = await resp.text();
    debugRustResponse(env, "line_user_delete", resp.status, text);
    return jsonResponse({ error: text }, resp.status);
  }

  return jsonResponse({ success: true });
}
