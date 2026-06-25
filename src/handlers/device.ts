/**
 * 無人デバイス (smb-watch 等) 向け device-token エンドポイント (Phase 2 / 案B)。
 *
 *   POST /device/pair    — 認証済み operator (Bearer session JWT) が device credential を発行。
 *                          device は operator の tenant に束縛される。`device_secret` は
 *                          応答 1 回限り (KV には hash のみ)。
 *   POST /device/token   — box が device_id + device_secret を提示 → 短命 device JWT を mint。
 *                          Google 不要・無人。発行 JWT は /auth/introspect で検証される。
 *   POST /device/revoke  — operator が自 tenant の device を revoke。
 *
 * pair/revoke は **Bearer session 限定** (cookie を受けない) なので CSRF surface が無い。
 * browser pairing ページは後続 PR の polish。token は box (非 browser) 専用で session 不要。
 */

import type { Env } from "../index";
import { extractToken } from "../lib/errors";
import { resolveSecret } from "../lib/secret";
import { verifyJwt } from "../lib/jwt";
import {
  createDeviceCredential,
  verifyDeviceCredential,
  revokeDeviceCredential,
  getDeviceRecord,
  mintDeviceJwt,
  normalizeDeviceRole,
  DEVICE_JWT_TTL_SECONDS,
} from "../lib/device";

function jsonNoStore(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

interface OperatorSession {
  tenantId: string;
  email: string;
}

/** Bearer session JWT を検証し operator の tenant/email を返す。不正なら null。 */
async function operatorSession(request: Request, env: Env): Promise<OperatorSession | null> {
  const token = extractToken(request);
  if (!token) return null;
  const secret = await resolveSecret(env.JWT_SECRET);
  if (!secret) return null;
  const payload = await verifyJwt(token, secret, env.WORKER_ENV);
  if (!payload) return null;
  const tenantId =
    (payload.tenant_id as string | undefined) || (payload.org as string | undefined) || "";
  if (!tenantId) return null;
  return { tenantId, email: (payload.email as string | undefined) || "" };
}

/** request body を JSON object として読む。空 / 不正は {}。 */
async function readJsonBody(request: Request): Promise<Record<string, unknown>> {
  try {
    const v = await request.json();
    return v && typeof v === "object" ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** POST /device/pair — operator が device credential を発行する。 */
export async function handleDevicePair(request: Request, env: Env): Promise<Response> {
  const session = await operatorSession(request, env);
  if (!session) return jsonNoStore({ error: "unauthorized" }, 401);

  const body = await readJsonBody(request);
  const label = typeof body.label === "string" && body.label ? body.label : "device";
  const role = normalizeDeviceRole(body.role);

  const now = Math.floor(Date.now() / 1000);
  const cred = await createDeviceCredential(env, session.tenantId, label, now, role);

  return jsonNoStore(
    {
      device_id: cred.device_id,
      device_secret: cred.device_secret,
      tenant_id: cred.record.tenant_id,
      label: cred.record.label,
      role: cred.record.role,
      note: "store device_secret now; it is not retrievable later",
    },
    201,
  );
}

/** POST /device/token — device credential を短命 device JWT に交換する。 */
export async function handleDeviceToken(request: Request, env: Env): Promise<Response> {
  const body = await readJsonBody(request);
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  const deviceSecret = typeof body.device_secret === "string" ? body.device_secret : "";
  if (!deviceId || !deviceSecret) {
    return jsonNoStore({ error: "device_id and device_secret required" }, 400);
  }

  const record = await verifyDeviceCredential(env, deviceId, deviceSecret);
  if (!record) return jsonNoStore({ error: "invalid_credential" }, 401);

  let token: string;
  try {
    token = await mintDeviceJwt(env, record, Math.floor(Date.now() / 1000));
  } catch {
    return jsonNoStore({ error: "server_error" }, 503);
  }

  return jsonNoStore({
    access_token: token,
    token_type: "Bearer",
    expires_in: DEVICE_JWT_TTL_SECONDS,
    tenant_id: record.tenant_id,
  });
}

/** POST /device/revoke — operator が自 tenant の device を revoke する。 */
export async function handleDeviceRevoke(request: Request, env: Env): Promise<Response> {
  const session = await operatorSession(request, env);
  if (!session) return jsonNoStore({ error: "unauthorized" }, 401);

  const body = await readJsonBody(request);
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  if (!deviceId) return jsonNoStore({ error: "device_id required" }, 400);

  const record = await getDeviceRecord(env, deviceId);
  if (!record) return jsonNoStore({ error: "not_found" }, 404);
  // 他 tenant の device は revoke できない。
  if (record.tenant_id !== session.tenantId) {
    return jsonNoStore({ error: "forbidden" }, 403);
  }

  await revokeDeviceCredential(env, deviceId);
  return jsonNoStore({ revoked: true, device_id: deviceId });
}
