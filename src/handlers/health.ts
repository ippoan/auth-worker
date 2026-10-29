import type { Env } from "../index";

/**
 * `GET /api/health` — auth-worker 自身の生死と版を返す。
 *
 * 以前は rust-alc-api の `/api/health` (backend の status・版) を写して返していたが、rust の撤収で
 * backend の health は無くなった (W9、Refs ippoan/rust-alc-api#680)。分割 worker の版は各 worker の
 * 応答ヘッダー `x-worker-version` / `x-worker-tag` で見る。
 */
export async function handleHealthProxy(env: Env): Promise<Response> {
  const body = {
    status: "ok",
    auth_worker_version: env.VERSION || "dev",
  };

  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
