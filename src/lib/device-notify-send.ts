/**
 * 無人デバイス向け LINE WORKS 通知の共通部分 — `/device-notify` (device JWT) と
 * `SmbIngestEntrypoint#notify` (service binding RPC) の両方から使う。
 *
 *   - 宛先の解決: AUTH_CONFIG KV の `device-notify-targets` (`key → recipient_id`)。
 *     fail-closed (未設定 / 壊れた JSON / key 未登録 → `null`)
 *   - 送信: `internalAuthToken` (aud=alc-api-internal) を付けて rust-alc-api の
 *     `POST /api/internal/lineworks/send` へ `{recipient_id, text}`
 *
 * ★ **宛先を呼び手に選ばせない** — 呼び手が渡せるのは map の key (role 等) と
 * `text` だけで、`recipient_id` は KV で固定する (`device-notify.ts` の ★ 参照)。
 *
 * 値 (internal token) は log / response に出さない。
 */
import type { Env } from "../index";
import { internalAuthToken } from "./alc-internal";

/** rust-alc-api の `require_internal_jwt` 経路 (`/alc-internal-proxy` と同じ path)。 */
const SEND_PATH = "/api/internal/lineworks/send";

/**
 * `key → recipient_id` の JSON map を置く AUTH_CONFIG KV のキー。
 *
 * **KV に置くのは、宛先変更に deploy を要らなくするため** (通知先は運用で変わる)。
 * `ohishi-exp/nuxt-dtako-admin` の relay が `netprint_targets` を自分の KV に持って
 * いるのと同じ形。値の投入は運用側の仕事で、この repo には入れない
 * (`recipient_id` をコードに焼かないこと — 焼くと deploy 無しで変えられなくなる)。
 */
const TARGETS_KEY = "device-notify-targets";

/** LINE WORKS のトークに流す 1 通の上限 (これ以上は運用上まず読まれない)。 */
export const MAX_NOTIFY_TEXT_LEN = 1000;

export function notifyJsonError(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

/**
 * KV の `device-notify-targets` から key の宛先を引く。
 * 未設定 / 壊れた JSON / key 未登録はすべて `null` (呼び出し側で拒否)。
 * 「通知先が無いのに送れたつもり」を作らないため、ここは必ず fail-closed。
 */
export async function resolveNotifyRecipient(env: Env, key: string): Promise<string | null> {
  const raw = await env.AUTH_CONFIG.get(TARGETS_KEY);
  if (!raw) return null;
  let map: unknown;
  try {
    map = JSON.parse(raw);
  } catch {
    console.error(JSON.stringify({ event: "device_notify_targets_unparsable" }));
    return null;
  }
  if (!map || typeof map !== "object" || Array.isArray(map)) return null;
  const recipient = (map as Record<string, unknown>)[key];
  return typeof recipient === "string" && recipient ? recipient : null;
}

/**
 * internal JWT を mint して `{recipient_id, text}` を rust へ送る
 * (mint は auth-worker が代行する)。
 *
 * 戻り値は上流の `Response` そのもの (成功時) か、502 の JSON error。
 * 上流の失敗本文は返さず log にだけ出す (内部情報)。`logFields` は失敗 log に
 * 足す識別子 (`{ event, role }` 等。値は secret を含めないこと)。
 */
export async function sendDeviceNotify(
  env: Env,
  apiOrigin: string,
  recipientId: string,
  text: string,
  logFields: Record<string, unknown>,
): Promise<Response> {
  let internalToken: string;
  try {
    internalToken = await internalAuthToken(env);
  } catch {
    return notifyJsonError(502, "upstream auth error"); // 詳細は log のみ
  }

  const target = `${apiOrigin.replace(/\/$/, "")}${SEND_PATH}`;
  const upstream = await fetch(target, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${internalToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ recipient_id: recipientId, text }),
  });

  if (!upstream.ok) {
    // 上流の本文はそのまま返さない (内部情報)。原因追跡は log 側で。
    const detail = await upstream.text().catch(() => "");
    console.error(
      JSON.stringify({
        ...logFields,
        status: upstream.status,
        body: detail.slice(0, 200),
      }),
    );
    return notifyJsonError(502, "upstream error");
  }

  return upstream;
}
