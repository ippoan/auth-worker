/**
 * 無人デバイス向け LINE WORKS 通知の共通部分 — `/device-notify` (device JWT) と
 * `SmbIngestEntrypoint#notify` (service binding RPC) の両方から使う。
 *
 *   - 宛先の解決: AUTH_CONFIG KV の `device-notify-targets` (`key → recipient_id`)。
 *     fail-closed (未設定 / 壊れた JSON / key 未登録 → `null`)
 *   - 送信: `POST /api/internal/lineworks/send` へ `{recipient_id, text}`。振り分け表
 *     (`alc-backend-route.ts`、`internal` として引く) が binding (`ALC_LINEWORKS`) を返せばそこへ
 *     (token は付けない)、返さなければ 404
 *     (W9 で Cloud Run への fallback を撤去、Refs ippoan/rust-alc-api#680)
 *
 * ★ **宛先を呼び手に選ばせない** — 呼び手が渡せるのは map の key (role 等) と
 * `text` だけで、`recipient_id` は KV で固定する (`device-notify.ts` の ★ 参照)。
 *
 * 値は log / response に出さない。
 */
import type { Env } from "../index";
import { forwardViaAlcBinding, resolveAlcBinding } from "./alc-backend-route";

/** alc-lineworks の送信の口 (`/alc-internal-proxy` と同じ path)。 */
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
 * `{recipient_id, text}` を送る。binding (`ALC_LINEWORKS`) があればそこへ、無ければ 404 の JSON error。
 *
 * 戻り値は上流の `Response` そのもの (成功時) か、404 / 502 の JSON error。
 * 上流の失敗本文は返さず log にだけ出す (内部情報)。`logFields` は失敗 log に
 * 足す識別子 (`{ event, role }` 等。値は secret を含めないこと)。
 */
export async function sendDeviceNotify(
  env: Env,
  recipientId: string,
  text: string,
  logFields: Record<string, unknown>,
): Promise<Response> {
  const body = JSON.stringify({ recipient_id: recipientId, text });
  const upstream = await sendUpstream(env, body);
  if (!upstream) return notifyJsonError(404, "not_found"); // binding 無し

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

/** binding があれば binding へ。無ければ null。 */
async function sendUpstream(env: Env, body: string): Promise<Response | null> {
  const binding = resolveAlcBinding(SEND_PATH, env, "internal", "POST");
  if (!binding) return null;
  return forwardViaAlcBinding(binding, SEND_PATH, "", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
}
