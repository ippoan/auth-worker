/**
 * SSO 設定の API (管理画面が呼ぶ)。
 * Client JS → auth-worker → alc-auth-worker の内部口 (`ALC_AUTH`、Refs ippoan/rust-alc-api#680)。
 * 以前は rust-alc-api の `/api/admin/sso/configs` を叩いていた。認可 (管理者か) はここで行う。
 *
 * client secret はここで `SSO_ENCRYPTION_KEY` を使って暗号化し (AES-256-GCM。rust-alc-api の `encrypt_secret` と
 * 同じ形式で、ログインの `lineworks-callback.ts` が同じ鍵で復号する)、alc-auth-worker には暗号文だけを渡す。
 */

import type { Env } from "../index";
import type {
  SsoConfigListResponse,
  SsoConfigRow as SsoConfig,
} from "../types/admin-api";
import {
  callTenantAdmin,
  errorResponse,
  jsonResponse,
  requireCaller,
  tenantPath,
} from "../lib/alc-tenant-admin";
import { encryptWithKey } from "../lib/mcp-crypto";
import { resolveSecret } from "../lib/secret";

export async function handleSsoList(request: Request, env: Env): Promise<Response> {
  const caller = await requireCaller(request, env, { admin: true, write: false });
  if (caller instanceof Response) return caller;

  console.log(JSON.stringify({ event: "sso_list" }));

  const r = await callTenantAdmin(env, tenantPath(caller.tenantId, "sso-configs"));
  if (r.status !== 200) return errorResponse(r);
  const data = r.body as SsoConfigListResponse;

  return jsonResponse({
    configs: data.configs.map((c) => ({
      provider: c.provider,
      clientId: c.client_id,
      hasClientSecret: true,
      externalOrgId: c.external_org_id,
      enabled: c.enabled,
      woffId: c.woff_id || "",
      createdAt: c.created_at,
      updatedAt: c.updated_at,
    })),
  });
}

export async function handleSsoUpsert(request: Request, env: Env): Promise<Response> {
  const caller = await requireCaller(request, env, { admin: true, write: true });
  if (caller instanceof Response) return caller;

  const body = (await request.json()) as {
    provider: string;
    clientId: string;
    clientSecret: string;
    externalOrgId: string;
    woffId?: string;
    enabled: boolean;
  };

  if (!body.provider || !body.clientId || !body.externalOrgId) {
    return jsonResponse(
      { error: "provider, clientId, externalOrgId are required" },
      400,
    );
  }

  console.log(
    JSON.stringify({
      event: "sso_upsert",
      provider: body.provider,
      externalOrgId: body.externalOrgId,
    }),
  );

  // 空の secret は「変えない」(既存の行の更新だけ。新規なら alc-auth-worker が 400 secret_required)
  let encrypted: string | null = null;
  if (body.clientSecret) {
    const key = await resolveSecret(env.SSO_ENCRYPTION_KEY);
    if (!key) return jsonResponse({ error: "sso_encryption_key_missing" }, 500);
    encrypted = await encryptWithKey(body.clientSecret, key);
  }

  const r = await callTenantAdmin(env, tenantPath(caller.tenantId, "sso-configs", body.provider), {
    method: "PUT",
    body: {
      client_id: body.clientId,
      client_secret_encrypted: encrypted,
      external_org_id: body.externalOrgId,
      woff_id: body.woffId || null,
      enabled: body.enabled ?? true,
    },
  });
  if (r.status !== 200) return errorResponse(r);
  const c = r.body as SsoConfig;

  return jsonResponse({
    provider: c.provider,
    clientId: c.client_id,
    hasClientSecret: true,
    externalOrgId: c.external_org_id,
    woffId: c.woff_id || "",
    enabled: c.enabled,
  });
}

export async function handleSsoDelete(request: Request, env: Env): Promise<Response> {
  const caller = await requireCaller(request, env, { admin: true, write: true });
  if (caller instanceof Response) return caller;

  const body = (await request.json()) as { provider: string };
  if (!body.provider) {
    return jsonResponse({ error: "provider is required" }, 400);
  }

  console.log(JSON.stringify({ event: "sso_delete", provider: body.provider }));

  const r = await callTenantAdmin(env, tenantPath(caller.tenantId, "sso-configs", body.provider), {
    method: "DELETE",
  });
  return r.status === 204 ? jsonResponse({ success: true }) : errorResponse(r);
}
