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
import { resolveAllSharedSecrets } from "./mcp-introspect";
import {
  createDeviceCredential,
  createDeviceCredentialReplacingLabel,
  verifyDeviceCredential,
  revokeDeviceCredential,
  getDeviceRecord,
  mintDeviceJwt,
  mintHubToken,
  setDeviceSiteId,
  normalizeDeviceRole,
  DEVICE_ROLE,
  DEVICE_JWT_TTL_SECONDS,
  HUB_TOKEN_TTL_SECONDS,
  HUB_TOKEN_ELIGIBLE_ROLES,
  type HubTokenClaims,
} from "../lib/device";

/** consumer proof を運ぶ header (alc-internal-proxy / rust の app 認証と同名)。 */
const INTERNAL_SECRET_HEADER = "X-Internal-Shared-Secret";

/** 定数時間比較 (alc-internal-proxy.ts と同実装)。 */
function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

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
  const siteId = typeof body.site_id === "string" && body.site_id ? body.site_id : undefined;

  const now = Math.floor(Date.now() / 1000);
  const cred = await createDeviceCredential(env, session.tenantId, label, now, role, siteId);

  return jsonNoStore(
    {
      device_id: cred.device_id,
      device_secret: cred.device_secret,
      tenant_id: cred.record.tenant_id,
      label: cred.record.label,
      role: cred.record.role,
      site_id: cred.record.site_id,
      note: "store device_secret now; it is not retrievable later",
    },
    201,
  );
}

/**
 * POST /device/pair-internal — **server-to-server** で device credential を発行する
 * (rust-alc-api#434 caller #5、AlcoholChecker provisioning。#495 PR2 で
 * `replace_label` を追加し kiosk 端末 re-pair の mint 経路にも対応)。
 *
 * `/device/pair` は operator session JWT 限定だが、AlcoholChecker の端末登録 (claim) や
 * kiosk 端末の re-pair (rust-alc-api#495) は **operator が同席しない**ため使えない。
 * 代わりに rust-alc-api (INTERNAL_SHARED_SECRET 保持) が server-to-server で本 endpoint
 * を叩いて credential を mint する。
 *
 *   ① X-Internal-Shared-Secret を `INTERNAL_SHARED_SECRET*` と constant-time 比較 (fail-closed)。
 *   ② tenant_id は呼び出し元が明示的に渡す (必須)。
 *   ③ `replace_label: true` なら `createDeviceCredentialReplacingLabel` で同一
 *      (tenant_id, label) の旧 credential を revoke してから新規 mint する
 *      (= kiosk re-pair の credential rotate。既定は従来通り単純 mint、
 *      AlcoholChecker provisioning 等の既存呼び出しの挙動を変えない)。
 *
 * secret が漏れると任意 tenant の device credential を mint できてしまうため、本 endpoint を
 * 叩けるのは secret を持つ caller のみ。端末には secret を焼かない。
 */
export async function handleDevicePairInternal(request: Request, env: Env): Promise<Response> {
  const sharedSecrets = await resolveAllSharedSecrets(env);
  if (!sharedSecrets) return jsonNoStore({ error: "not_configured" }, 503);

  const provided = request.headers.get(INTERNAL_SECRET_HEADER) ?? "";
  if (!provided || !sharedSecrets.some((s) => constantTimeEquals(provided, s))) {
    return jsonNoStore({ error: "unauthorized" }, 401);
  }

  const body = await readJsonBody(request);
  const tenantId = typeof body.tenant_id === "string" ? body.tenant_id : "";
  if (!tenantId) return jsonNoStore({ error: "tenant_id required" }, 400);
  const label = typeof body.label === "string" && body.label ? body.label : "device";
  const role = normalizeDeviceRole(body.role);
  const siteId = typeof body.site_id === "string" && body.site_id ? body.site_id : undefined;
  const replaceLabel = body.replace_label === true;

  const now = Math.floor(Date.now() / 1000);
  const cred = replaceLabel
    ? await createDeviceCredentialReplacingLabel(env, tenantId, label, now, role, siteId)
    : await createDeviceCredential(env, tenantId, label, now, role, siteId);

  return jsonNoStore(
    {
      device_id: cred.device_id,
      device_secret: cred.device_secret,
      tenant_id: cred.record.tenant_id,
      role: cred.record.role,
      site_id: cred.record.site_id,
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

/**
 * POST /device/hub-token — device credential + 呼び出し元指定の nonce を、
 * 短命 (60s) の拠点相互認証トークンに交換する (Refs #406)。
 * `device-hub` (CoreS3) / `device-gateway` (alc-gw / P4) の credential のみ mint
 * できる。`site_id` 未設定の credential (site 未割当) は forbidden。
 */
export async function handleDeviceHubToken(request: Request, env: Env): Promise<Response> {
  const body = await readJsonBody(request);
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  const deviceSecret = typeof body.device_secret === "string" ? body.device_secret : "";
  const nonce = typeof body.nonce === "string" ? body.nonce : "";
  if (!deviceId || !deviceSecret || !nonce) {
    return jsonNoStore({ error: "device_id, device_secret and nonce required" }, 400);
  }

  const record = await verifyDeviceCredential(env, deviceId, deviceSecret);
  if (!record) return jsonNoStore({ error: "invalid_credential" }, 401);

  let token: string | null;
  try {
    token = await mintHubToken(env, record, nonce, Math.floor(Date.now() / 1000));
  } catch {
    return jsonNoStore({ error: "server_error" }, 503);
  }
  if (!token) return jsonNoStore({ error: "forbidden" }, 403);

  return jsonNoStore({
    access_token: token,
    token_type: "Bearer",
    expires_in: HUB_TOKEN_TTL_SECONDS,
    site_id: record.site_id,
  });
}

/**
 * POST /device/introspect — device credential で認証した呼び出し元に、相手デバイスが
 * mint した hub token の検証結果を返す (Refs #406)。CoreS3 (ESP32) は JWKS 検証を
 * 実装しないため、この REST 呼び出しで検証を代替する (site-device-auth-project 設計)。
 * `site_id` の一致判定 (1:1 強制) は呼び出し側の責務 — ここでは claims をそのまま返す。
 */
export async function handleDeviceIntrospect(request: Request, env: Env): Promise<Response> {
  const body = await readJsonBody(request);
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  const deviceSecret = typeof body.device_secret === "string" ? body.device_secret : "";
  const token = typeof body.token === "string" ? body.token : "";
  if (!deviceId || !deviceSecret || !token) {
    return jsonNoStore({ error: "device_id, device_secret and token required" }, 400);
  }

  const caller = await verifyDeviceCredential(env, deviceId, deviceSecret);
  if (!caller || !HUB_TOKEN_ELIGIBLE_ROLES.has(caller.role ?? DEVICE_ROLE)) {
    return jsonNoStore({ error: "unauthorized" }, 401);
  }

  const secret = await resolveSecret(env.JWT_SECRET);
  if (!secret) return jsonNoStore({ error: "server_error" }, 503);

  const payload = await verifyJwt(token, secret, env.WORKER_ENV);
  if (!payload || payload.aud !== "hub") {
    return jsonNoStore({ valid: false });
  }
  const claims = payload as unknown as HubTokenClaims;

  return jsonNoStore({ valid: true, site_id: claims.site_id, role: claims.role, claims });
}

/**
 * POST /device/site/backfill — server-to-server で既存 device credential
 * (主に現場稼働中の CoreS3) に事後で site_id を付与する (Refs #406)。
 * alc-app にまだ拠点レジストリが無いため、provisioning 済み機体を再度 WebSerial 挿さずに
 * site_id だけ割り当てる用途。認証は `/device/pair-internal` と同じ
 * `INTERNAL_SHARED_SECRET*` multi-binding。
 */
export async function handleDeviceSiteBackfill(request: Request, env: Env): Promise<Response> {
  const sharedSecrets = await resolveAllSharedSecrets(env);
  if (!sharedSecrets) return jsonNoStore({ error: "not_configured" }, 503);

  const provided = request.headers.get(INTERNAL_SECRET_HEADER) ?? "";
  if (!provided || !sharedSecrets.some((s) => constantTimeEquals(provided, s))) {
    return jsonNoStore({ error: "unauthorized" }, 401);
  }

  const body = await readJsonBody(request);
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  if (!deviceId) return jsonNoStore({ error: "device_id required" }, 400);
  // site_id 省略時は device_id 自身を既定にする (hub の site_id は自分の
  // device_id が標準、Refs #406 改訂)。
  const explicitSiteId = typeof body.site_id === "string" ? body.site_id.trim() : "";
  const siteId = explicitSiteId || deviceId;

  const record = await setDeviceSiteId(env, deviceId, siteId);
  if (!record) return jsonNoStore({ error: "not_found" }, 404);

  return jsonNoStore({ device_id: record.device_id, site_id: record.site_id, role: record.role });
}
