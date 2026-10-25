/**
 * 参加の申請の API (参加ページと管理画面が呼ぶ)。
 * Client JS → auth-worker → alc-auth-worker の内部口 (`ALC_AUTH`、Refs ippoan/rust-alc-api#680)。
 * 以前は rust-alc-api の `/api/access-requests*` を叩いていた。
 *
 * 申請はログイン中の誰でも (申請者は JWT の sub)、一覧・承認・却下は申請先の会社の管理者だけ (会社は JWT の tenant)。
 */

import type { Env } from "../index";
import {
  callTenantAdmin,
  errorResponse,
  jsonResponse,
  requireCaller,
  tenantPath,
} from "../lib/alc-tenant-admin";

export async function handleAccessRequestCreate(request: Request, env: Env): Promise<Response> {
  const caller = await requireCaller(request, env, { admin: false, write: true });
  if (caller instanceof Response) return caller;

  const body = (await request.json()) as { orgSlug: string };
  if (!body.orgSlug) {
    return jsonResponse({ error: "orgSlug is required" }, 400);
  }

  console.log(JSON.stringify({ event: "access_request_create", orgSlug: body.orgSlug }));

  const r = await callTenantAdmin(env, "/internal/access-requests", {
    method: "POST",
    body: { org_slug: body.orgSlug, user_id: caller.userId },
  });
  return r.status === 201 ? jsonResponse(r.body) : errorResponse(r);
}

export async function handleAccessRequestList(request: Request, env: Env): Promise<Response> {
  const caller = await requireCaller(request, env, { admin: true, write: false });
  if (caller instanceof Response) return caller;

  const body = (await request.json()) as { statusFilter?: string };
  const query = body.statusFilter ? `?status=${encodeURIComponent(body.statusFilter)}` : "";

  const r = await callTenantAdmin(env, tenantPath(caller.tenantId, "access-requests") + query);
  return r.status === 200 ? jsonResponse(r.body) : errorResponse(r);
}

export async function handleAccessRequestApprove(request: Request, env: Env): Promise<Response> {
  const caller = await requireCaller(request, env, { admin: true, write: true });
  if (caller instanceof Response) return caller;

  const body = (await request.json()) as { requestId: string; role?: string };
  if (!body.requestId) {
    return jsonResponse({ error: "requestId is required" }, 400);
  }

  console.log(JSON.stringify({ event: "access_request_approve", requestId: body.requestId }));

  const r = await callTenantAdmin(
    env,
    tenantPath(caller.tenantId, "access-requests", body.requestId, "approve"),
    { method: "POST", body: { role: body.role } },
  );
  return r.status === 204 ? jsonResponse({ success: true }) : errorResponse(r);
}

export async function handleAccessRequestDecline(request: Request, env: Env): Promise<Response> {
  const caller = await requireCaller(request, env, { admin: true, write: true });
  if (caller instanceof Response) return caller;

  const body = (await request.json()) as { requestId: string };
  if (!body.requestId) {
    return jsonResponse({ error: "requestId is required" }, 400);
  }

  console.log(JSON.stringify({ event: "access_request_decline", requestId: body.requestId }));

  const r = await callTenantAdmin(
    env,
    tenantPath(caller.tenantId, "access-requests", body.requestId, "decline"),
    { method: "POST" },
  );
  return r.status === 204 ? jsonResponse({ success: true }) : errorResponse(r);
}
