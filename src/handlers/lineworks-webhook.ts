/**
 * LINE WORKS webhook の薄い proxy。
 *
 * `POST /lineworks/hook/{識別子}` を受けて、(tenant, bot) ごとの Durable Object に丸投げする。
 * HMAC 検証・復号・キュー処理はすべて DO 側 (`LineworksWebhookDO`)。
 *
 * - LINE WORKS Developers Console の callback URL は `https://auth.ippoan.org/lineworks/hook/{識別子}`
 *   (識別子は `lib/lineworks-hook-id.ts`。画面には alc-proxy の `/api/lineworks/webhook-url` で出す)。
 * - 旧 URL `/lineworks/webhook/{bot_id}` (tenant を持たず、alc-notify が tenant をまたぐ SECURITY DEFINER の関数で
 *   bot を引いていた) と、その DO の cache を消す `/lineworks/refresh/{bot_id}` (呼び手は rust-alc-api の bot_admin だけで、
 *   もう居ない) は callback URL の切り替えの後に消した。
 * - 5xx は LINE WORKS が aggressive リトライするので、検証失敗 (401) と路径不正 (400) 以外は
 *   200 を返して DO 側のキュー再送に任せる。
 */

import type { Env } from "../index";
import { decodeHookId } from "../lib/lineworks-hook-id";
import { resolveSecret } from "../lib/secret";

/**
 * `POST /lineworks/hook/{識別子}` — tenant 付きの callback URL。
 *
 * 識別子を `SSO_ENCRYPTION_KEY` で復号して (tenant, bot) を知り、(tenant, bot) ごとの DO へ `x-tenant-id` 付きで渡す。
 * DO は alc-notify の tenant 付きの口 (`/api/internal/lineworks/tenant/…`) を `X-Tenant-ID` 付きで呼ぶので、bot は tenant の中で
 * RLS のまま引ける。読めない識別子は 404。
 */
export async function handleLineworksHook(
  request: Request,
  env: Env,
  hookId: string,
): Promise<Response> {
  if (request.method !== "POST") {
    return jsonResp(405, { error: "method_not_allowed" });
  }
  const sig = request.headers.get("x-works-signature");
  if (!sig) {
    return jsonResp(401, { error: "missing_signature" });
  }
  const key = await resolveSecret(env.SSO_ENCRYPTION_KEY);
  if (!key) return jsonResp(503, { error: "not_configured" });
  const target = hookId ? await decodeHookId(hookId, key) : null;
  if (!target) return jsonResp(404, { error: "not_found" });

  const id = env.LINEWORKS_WEBHOOK_DO.idFromName(`hook:${target.tenantId}:${target.botId}`);
  const stub = env.LINEWORKS_WEBHOOK_DO.get(id);
  const rawBody = await request.arrayBuffer();
  return stub.fetch(
    new Request("https://do/event", {
      method: "POST",
      headers: {
        "x-bot-id": target.botId,
        "x-tenant-id": target.tenantId,
        "x-works-signature": sig,
        "Content-Type": request.headers.get("content-type") ?? "application/json",
      },
      body: rawBody,
    }),
  );
}

function jsonResp(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
