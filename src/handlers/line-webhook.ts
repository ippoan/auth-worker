/**
 * LINE Messaging API inbound webhook の薄い forwarder。
 *
 * LINE Developer Console の webhook URL は auth-worker の `POST /line/webhook`。ここで raw body と
 * `x-line-signature` をそのまま alc-notify-worker の `/api/internal/notify/line/webhook` へ
 * Service Binding `ALC_NOTIFY` で渡す (W8b、Refs ippoan/rust-alc-api#680。それまでは rust の internal
 * route へ OIDC 付きで forward していた)。alc-notify は binding からしか届かないので、内部用の token は付けない
 * (ほかの `ALC_NOTIFY` の口と同じ)。
 *
 * 署名検証 (全テナント channel secret 照合) は **alc-notify-worker 側**が行う (auth-worker は channel
 * secret を持たない薄い pass-through)。LINE WORKS (`/lineworks/webhook/:bot_id`) は DO で
 * HMAC 検証 + 復号するが、LINE Messaging は worker が DB に channel secret を持つため検証を
 * worker に置く方が単純。
 */
import type { Env } from "../index";

const NOTIFY_LINE_WEBHOOK_URL = "https://alc-notify/api/internal/notify/line/webhook";

export async function handleLineWebhook(request: Request, env: Env): Promise<Response> {
  const signature = request.headers.get("x-line-signature");
  if (!signature) {
    return jsonResp(401, { error: "missing_signature" });
  }
  const binding = env.ALC_NOTIFY;
  if (!binding) {
    // binding が無い env (テスト用の構成など)。LINE は 5xx を retry するので 503 を返す。
    return jsonResp(503, { error: "notify_worker_not_bound" });
  }

  // body は一度だけ読む (consumable)。worker に raw のまま渡す (署名検証のため)。
  const rawBody = await request.arrayBuffer();
  const contentType = request.headers.get("content-type") ?? "application/json";

  let res: Response;
  try {
    res = await binding.fetch(NOTIFY_LINE_WEBHOOK_URL, {
      method: "POST",
      headers: {
        "x-line-signature": signature,
        "Content-Type": contentType,
      },
      body: rawBody,
      redirect: "manual",
    });
  } catch {
    // 上流到達不可。LINE は 5xx を retry するので 502 を返す。
    return jsonResp(502, { error: "upstream_unreachable" });
  }

  // worker の status をそのまま返す (200 = follow 処理済 / 401 = 署名不一致 / 5xx = 上流障害)。
  const body = await res.text();
  return new Response(body, {
    status: res.status,
    headers: { "Content-Type": res.headers.get("content-type") ?? "application/json" },
  });
}

function jsonResp(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
