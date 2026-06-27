/**
 * LINE Login テナント選択後の JWT 発行 (rust-alc-api#434 Phase 3)。
 *
 * callback で複数テナントが該当した場合に、ユーザーが選んだ tenant_id を受けて JWT を
 * 発行する (rust `line_select_tenant` の移植)。recipient が本当にそのテナントに居るかを
 * 検証してから発行する。redirect ではなく JSON を返す。
 */
import type { Env } from "../index";
import { resolveSecret } from "../lib/secret";
import {
  findUserByLineId,
  upsertLineUser,
  recipientsByLineId,
  saveRefreshToken,
} from "../lib/alc-internal";
import {
  createAccessToken,
  createRefreshToken,
  refreshTokenExpiresAt,
  ACCESS_TOKEN_EXPIRY_SECS,
} from "../lib/access-token";

export async function handleLineSelectTenant(request: Request, env: Env): Promise<Response> {
  let body: { line_user_id?: string; line_name?: string; tenant_id?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return new Response("invalid body", { status: 400 });
  }
  const lineUserId = body.line_user_id;
  const tenantId = body.tenant_id;
  const lineName = body.line_name ?? "";
  if (!lineUserId || !tenantId) {
    return new Response("missing line_user_id or tenant_id", { status: 400 });
  }

  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) {
    return new Response("server_error", { status: 503 });
  }

  // recipient が本当にこのテナントに存在するか検証 (rust と同じ)。
  const tenants = await recipientsByLineId(env, lineUserId);
  if (!tenants.some((t) => t.tenant_id === tenantId)) {
    return new Response("forbidden", { status: 403 });
  }

  // 既存ユーザー or 新規作成 (既存はそのテナント、新規は選択テナント)。
  const user =
    (await findUserByLineId(env, lineUserId)) ??
    (await upsertLineUser(env, { tenant_id: tenantId, line_user_id: lineUserId, name: lineName }));

  const token = await createAccessToken(
    { id: user.id, email: user.email, name: user.name, tenant_id: user.tenant_id, role: user.role },
    jwtSecret,
    user.slug,
  );
  const refresh = await createRefreshToken();
  await saveRefreshToken(env, {
    user_id: user.id,
    refresh_hash: refresh.hash,
    expires_at: refreshTokenExpiresAt(),
  });

  return Response.json({
    access_token: token,
    refresh_token: refresh.raw,
    expires_in: ACCESS_TOKEN_EXPIRY_SECS,
  });
}
