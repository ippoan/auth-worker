/**
 * `GET /internal/hub-devices`
 *
 * role=device-hub (CoreS3) の有効な device を tenant 横断で返す server-to-server
 * 専用 internal API (ippoan/auth-worker#401 / ippoan/alc-app#121)。
 *
 * cf-alc-recorder の `scheduled()` cron (電源/バッテリー履歴の定期取得) が
 * 「どの tenant にどの hub device が登録されているか」を知るために呼ぶ。
 * `listDeviceRecordsByTenant` は tenant 指定必須 (session 前提) で使えないため
 * tenant 非依存の一覧関数 (`listAllHubDeviceRecords`) を新設した。
 *
 * 認証: `/auth/introspect` と同じ `resolveAllSharedSecrets` (`INTERNAL_SHARED_SECRET*`
 * multi-binding) + `Authorization: <shared secret>` の constant-time 比較。
 * browser JWT は扱わない (server-to-server 専用)。
 *
 * レスポンス: `{ devices: [{ tenant_id, device_id }, ...] }`。
 * secret_hash / label 等の機微値は含めない。
 */
import type { Env } from "../index";
import { listAllHubDeviceRecords } from "../lib/device";
import { resolveAllSharedSecrets } from "./mcp-introspect";

function jsonNoStore(data: unknown, status = 200): Response {
  const res = new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
  res.headers.set("Cache-Control", "no-store");
  return res;
}

/** 定数時間比較 (`auth-introspect.ts` と同実装)。 */
function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function handleInternalHubDevices(request: Request, env: Env): Promise<Response> {
  const sharedSecrets = await resolveAllSharedSecrets(env);
  if (!sharedSecrets) {
    return jsonNoStore({ error: "server_error" }, 503);
  }

  const authz = request.headers.get("Authorization") ?? "";
  if (!authz || !sharedSecrets.some((s) => constantTimeEquals(authz, s))) {
    return jsonNoStore({ error: "unauthorized" }, 401);
  }

  const devices = await listAllHubDeviceRecords(env);
  return jsonNoStore({ devices });
}
