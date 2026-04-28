/**
 * LINE WORKS webhook の薄い proxy。
 *
 * `POST /lineworks/webhook/{bot_id}` を受けて、bot_id ごとの Durable Object に丸投げする。
 * HMAC 検証・復号・キュー処理はすべて DO 側 (`LineworksWebhookDO`)。
 *
 * - LINE WORKS Developers Console には新 callback URL `https://auth.ippoan.org/lineworks/webhook/{bot_id}`
 *   を登録する想定。
 * - 5xx は LINE WORKS が aggressive リトライするので、検証失敗 (401) と路径不正 (400) 以外は
 *   200 を返して DO 側のキュー再送に任せる。
 */

import type { Env } from "../index";

export async function handleLineworksWebhook(
  request: Request,
  env: Env,
  botId: string,
): Promise<Response> {
  if (!botId) {
    return jsonResp(400, { error: "missing_bot_id" });
  }
  if (request.method !== "POST") {
    return jsonResp(405, { error: "method_not_allowed" });
  }
  const sig = request.headers.get("x-works-signature");
  if (!sig) {
    return jsonResp(401, { error: "missing_signature" });
  }

  const id = env.LINEWORKS_WEBHOOK_DO.idFromName(botId);
  const stub = env.LINEWORKS_WEBHOOK_DO.get(id);

  // body は consumable なので一度だけ読む。DO に rawBody を渡す。
  const rawBody = await request.arrayBuffer();
  const doReq = new Request("https://do/event", {
    method: "POST",
    headers: {
      "x-bot-id": botId,
      "x-works-signature": sig,
      "Content-Type": request.headers.get("content-type") ?? "application/json",
    },
    body: rawBody,
  });

  return stub.fetch(doReq);
}

/**
 * `POST /lineworks/refresh/{bot_id}` (auth-worker 内部、JWT 認証必須)
 *
 * rust-alc-api の bot_admin が bot_secret を更新した後に呼ばれる cache invalidation 用。
 * DO の storage から bot_secret_encrypted を削除し、次回 webhook で再 fetch させる。
 *
 * NOTE: 認証は呼び出し側 (rust-alc-api → auth-worker の internal 経路) でも通常 JWT で
 * 行うが、auth-worker 側でも require_internal_jwt 相当の検証を入れるのが筋。本実装では
 * 簡易化のため JWT_SECRET ベースの HMAC 検証 1 段で済ませる (TODO: より厳密化)。
 */
export async function handleLineworksRefresh(
  request: Request,
  env: Env,
  botId: string,
): Promise<Response> {
  if (!botId) return jsonResp(400, { error: "missing_bot_id" });
  if (request.method !== "POST") return jsonResp(405, { error: "method_not_allowed" });

  // 内部 API の JWT 検証 (aud=alc-api-internal)
  // 実装は簡易: backend が auth-worker と同じ JWT_SECRET で sign した HS256 JWT を Authorization に乗せる
  const ok = await verifyInternalAuthHeader(request, env);
  if (!ok) return jsonResp(401, { error: "unauthorized" });

  const id = env.LINEWORKS_WEBHOOK_DO.idFromName(botId);
  const stub = env.LINEWORKS_WEBHOOK_DO.get(id);
  return stub.fetch(new Request("https://do/refresh", { method: "POST" }));
}

async function verifyInternalAuthHeader(request: Request, env: Env): Promise<boolean> {
  const auth = request.headers.get("authorization") ?? request.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) return false;
  const token = auth.slice(7);
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  const expectedSig = await hmacSha256(`${headerB64}.${payloadB64}`, env.JWT_SECRET);
  if (expectedSig !== sigB64) return false;

  try {
    const payload = JSON.parse(b64UrlDecode(payloadB64)) as { aud?: string; exp?: number };
    if (payload.aud !== "alc-api-internal") return false;
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== "number" || payload.exp < now) return false;
    return true;
  } catch {
    return false;
  }
}

async function hmacSha256(input: string, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(input));
  return b64UrlEncode(new Uint8Array(sig));
}

function b64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i] ?? 0);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64UrlDecode(s: string): string {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return atob(b64);
}

function jsonResp(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
