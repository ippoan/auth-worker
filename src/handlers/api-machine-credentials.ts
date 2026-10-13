/**
 * 機械用資格情報の管理 API (Refs ohishi-exp/rust-leave-worker#1)。nuxt-leave の設定画面が
 * auth.ippoan.org を直接 (cross-origin で) 呼ぶ。
 *
 *   GET  /api/machine-credentials?purpose=leave-scan        → {credentials: MachineCredentialSummary[]}
 *   POST /api/machine-credentials  body {purpose, label}    → 201 {username, password, purpose, label}
 *                                                              (password はこの応答 1 回だけ)
 *   POST /api/machine-credentials/<username>/revoke         → {revoked: true} / 404
 *
 * 認可:
 *   - `Authorization: Bearer <browser JWT>` を verifyJwt で検証し、`role === "admin"` だけ
 *   - `aud` 付き・device 系 role の token は拒否 (alc-proxy.ts の #482 と同じ判定)
 *   - tenant は JWT の `tenant_id` (無ければ `org`) だけ。body / query の tenant は受けない
 *   - dev token (`token_kind: "dev"`) は staging (`MACHINE_CRED_ENV === "staging"`) でだけ書ける。
 *     prod では GET だけ。staging で dev セッションから試験用の資格情報を発行して PC から試すため。
 *     ほかの `token_kind` (device-key 等) は環境によらず書けない
 *   - `MACHINE_CRED_ENV` が無い環境は 503
 *
 * CORS: Origin が leave / leave-staging のときだけ、その Origin を返す (cookie は使わない)。
 */
import type { Env } from "../index";
import { DEVICE_ROLES } from "../lib/device";
import { extractToken } from "../lib/errors";
import { verifyJwt } from "../lib/jwt";
import {
  createMachineCredential,
  isMachineCredPurpose,
  listMachineCredentials,
  machineCredEnvName,
  revokeMachineCredential,
} from "../lib/machine-credential";
import { resolveSecret } from "../lib/secret";

export const MACHINE_CRED_API_PATH = "/api/machine-credentials";

/** cross-origin で呼んでよい画面の origin。 */
export const MACHINE_CRED_CORS_ORIGINS: readonly string[] = [
  "https://leave.ippoan.org",
  "https://leave-staging.ippoan.org",
];

const REVOKE_RE = /^\/api\/machine-credentials\/([^/]+)\/revoke$/;

function corsHeaders(request: Request): Record<string, string> {
  const origin = request.headers.get("Origin");
  if (!origin || !MACHINE_CRED_CORS_ORIGINS.includes(origin)) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Max-Age": "600",
    Vary: "Origin",
  };
}

function json(request: Request, data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...corsHeaders(request),
    },
  });
}

interface Caller {
  tenantId: string;
  canWrite: boolean;
}

/** JWT を検証して呼び手を決める。失敗は Response (401 / 403) を返す。 */
async function authorize(request: Request, env: Env, envName: string): Promise<Caller | Response> {
  const token = extractToken(request);
  const secret = await resolveSecret(env.JWT_SECRET);
  const payload = token && secret ? await verifyJwt(token, secret, env.WORKER_ENV) : null;
  if (!payload) return json(request, { error: "Unauthorized" }, 401);
  const role = typeof payload.role === "string" ? payload.role : "";
  // device 系の token (aud 付き / device role) は同じ鍵で署名されるので明示的に弾く (#482)。
  if (payload.aud !== undefined || DEVICE_ROLES.has(role)) {
    return json(request, { error: "Unauthorized" }, 401);
  }
  const tenantId =
    (typeof payload.tenant_id === "string" && payload.tenant_id) ||
    (typeof payload.org === "string" && payload.org) ||
    "";
  if (!tenantId) return json(request, { error: "Unauthorized" }, 401);
  if (role !== "admin") return json(request, { error: "Forbidden" }, 403);
  const tokenKind = typeof payload.token_kind === "string" ? payload.token_kind : "";
  const canWrite = tokenKind === "" || (tokenKind === "dev" && envName === "staging");
  return { tenantId, canWrite };
}

export async function handleMachineCredentials(request: Request, env: Env): Promise<Response> {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders(request) });
  }
  const envName = machineCredEnvName(env);
  if (!envName) return json(request, { error: "machine_credentials_unavailable" }, 503);

  const url = new URL(request.url);
  const isCollection = url.pathname === MACHINE_CRED_API_PATH;
  const revokeMatch = REVOKE_RE.exec(url.pathname);
  if (!isCollection && !revokeMatch) return json(request, { error: "Not found" }, 404);
  const allowed = isCollection ? ["GET", "POST"] : ["POST"];
  if (!allowed.includes(request.method)) {
    return json(request, { error: "Method not allowed" }, 405);
  }

  const caller = await authorize(request, env, envName);
  if (caller instanceof Response) return caller;

  if (request.method === "GET") {
    const purpose = url.searchParams.get("purpose");
    if (purpose !== null && !isMachineCredPurpose(purpose)) {
      return json(request, { error: "invalid_purpose" }, 400);
    }
    const credentials = await listMachineCredentials(env, caller.tenantId, purpose ?? undefined);
    return json(request, { credentials });
  }

  if (!caller.canWrite) return json(request, { error: "dev_token_write_forbidden" }, 403);

  if (revokeMatch) {
    // username は `mc_` + hex なので decode しない (形が違えば revoke 側で false = 404)。
    const revoked = await revokeMachineCredential(env, caller.tenantId, revokeMatch[1]!);
    if (!revoked) return json(request, { error: "Not found" }, 404);
    return json(request, { revoked: true });
  }

  let body: { purpose?: unknown; label?: unknown };
  try {
    body = (await request.json()) as { purpose?: unknown; label?: unknown };
  } catch {
    return json(request, { error: "invalid_json" }, 400);
  }
  const purpose = body?.purpose;
  const label = body?.label;
  if (!isMachineCredPurpose(purpose)) return json(request, { error: "invalid_purpose" }, 400);
  if (typeof label !== "string") return json(request, { error: "invalid_label" }, 400);
  const created = await createMachineCredential(env, caller.tenantId, purpose, label);
  if (!created) return json(request, { error: "invalid_label" }, 400);
  return json(
    request,
    { username: created.username, password: created.password, purpose, label: label.trim() },
    201,
  );
}
