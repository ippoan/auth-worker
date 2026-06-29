/**
 * LINE Messaging API inbound webhook の薄い forwarder (#434 lockdown)。
 *
 * lockdown (`allUsers` 削除) 後、LINE platform は Google OIDC を付けられないため rust の
 * 公開 webhook には到達できない。LINE Developer Console の webhook URL を auth-worker の
 * `POST /line/webhook` に向け、ここで OIDC (aud=alc-api-internal) を mint して rust の
 * internal route `/api/internal/notify/line/webhook` へ raw body + `x-line-signature` を
 * そのまま forward する。
 *
 * 署名検証 (全テナント channel secret 照合) は **rust 側**が行う (auth-worker は channel
 * secret を持たない薄い pass-through)。LINE WORKS (`/lineworks/webhook/:bot_id`) は DO で
 * HMAC 検証 + 復号するが、LINE Messaging は rust が DB に channel secret を持つため検証を
 * rust に残す方が単純。
 */
import type { Env } from "../index";
import { internalAuthToken } from "../lib/alc-internal";

export async function handleLineWebhook(request: Request, env: Env): Promise<Response> {
  const signature = request.headers.get("x-line-signature");
  if (!signature) {
    return jsonResp(401, { error: "missing_signature" });
  }

  // body は一度だけ読む (consumable)。rust に raw のまま渡す (署名検証のため)。
  const rawBody = await request.arrayBuffer();
  const token = await internalAuthToken(env);
  const contentType = request.headers.get("content-type") ?? "application/json";

  let res: Response;
  try {
    res = await fetch(`${env.ALC_API_ORIGIN}/api/internal/notify/line/webhook`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "x-line-signature": signature,
        "Content-Type": contentType,
      },
      body: rawBody,
    });
  } catch {
    // 上流到達不可。LINE は 5xx を retry するので 502 を返す。
    return jsonResp(502, { error: "upstream_unreachable" });
  }

  // rust の status をそのまま返す (200 = follow 処理済 / 401 = 署名不一致 / 5xx = 上流障害)。
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
