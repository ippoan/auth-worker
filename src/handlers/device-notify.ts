/**
 * `/device-notify` — 無人デバイス (ohishi-data の box = ohishi-exp/smb-watch 等) が
 * **device JWT だけ**で LINE WORKS 通知を出すための口 (Refs ippoan/nuxt-pwa-carins#54)。
 *
 * carins の車検証 upload が 2026-07-01 から 7 週間止まっていたのに誰も気づかなかった
 * (#54)。原因は直したが「気づけなかったこと」は直っていない — 無人 box が毎正時に
 * 数えている `found/uploaded/failed` を人に届ける経路がこれ。
 *
 * 送信そのものは rust-alc-api の `POST /api/internal/lineworks/send`
 * (`require_internal_jwt`) に実装済みで、`/alc-internal-proxy` の allowlist にも
 * `internal-jwt` として載っている。**それでも第三の口を作るのは、`/alc-internal-proxy`
 * が `X-Alc-Proxy-Secret` (= INTERNAL_SHARED_SECRET) を要求するから**。オンプレの
 * 無人 box にこの共有 secret を置くと blast radius が大きすぎる (#434 の「SA key /
 * 共有 secret は auth-worker に集中させる」方針)。box が持つのは device credential
 * だけに保ち、**内部 JWT の mint は auth-worker が代行する** — `device-data-proxy`
 * (device JWT + role→path allowlist) と同じ考え方。
 *
 *   ① env guard (`JWT_SECRET` / `ALC_API_ORIGIN`)。
 *   ② `Authorization: Bearer <device JWT>` を `verifyJwt` で検証
 *      (`device-data-proxy.ts` と同じ HS256/JWT_SECRET)。
 *   ③ `payload.role` → 宛先 (`recipient_id`) を **AUTH_CONFIG KV から**解決。
 *      未設定 / パース不能 / role が map に無い → 403 (fail-closed)。
 *   ④ body 検証 — 受け付けるのは `text` **だけ** (下記 ★)。
 *   ⑤ `internalAuthToken` (aud=alc-api-internal) を付けて rust へ forward。
 *
 * 値 (device JWT / internal token) は log / response に出さない。
 */
import type { Env } from "../index";
import { extractToken } from "../lib/errors";
import { verifyJwt } from "../lib/jwt";
import { resolveSecret } from "../lib/secret";
import { internalAuthToken } from "../lib/alc-internal";

const ROUTE = "/device-notify";

/** rust-alc-api の `require_internal_jwt` 経路 (`/alc-internal-proxy` と同じ path)。 */
const SEND_PATH = "/api/internal/lineworks/send";

/**
 * `role → recipient_id` の JSON map を置く AUTH_CONFIG KV のキー。
 *
 * **KV に置くのは、宛先変更に deploy を要らなくするため** (通知先は運用で変わる)。
 * `ohishi-exp/nuxt-dtako-admin` の relay が `netprint_targets` を自分の KV に持って
 * いるのと同じ形。値の投入は運用側の仕事で、この repo には入れない
 * (`recipient_id` をコードに焼かないこと — 焼くと deploy 無しで変えられなくなる)。
 */
const TARGETS_KEY = "device-notify-targets";

/** LINE WORKS のトークに流す 1 通の上限 (これ以上は運用上まず読まれない)。 */
const MAX_TEXT_LEN = 1000;

function jsonError(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

/**
 * KV の `device-notify-targets` から role の宛先を引く。
 * 未設定 / 壊れた JSON / role 未登録はすべて `null` (呼び出し側で 403)。
 * 「通知先が無いのに送れたつもり」を作らないため、ここは必ず fail-closed。
 */
async function resolveRecipient(env: Env, role: string): Promise<string | null> {
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
  const recipient = (map as Record<string, unknown>)[role];
  return typeof recipient === "string" && recipient ? recipient : null;
}

export async function handleDeviceNotify(request: Request, env: Env): Promise<Response> {
  // 送信専用の口なので POST 以外は入口で落とす。
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "method_not_allowed" }), {
      status: 405,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        Allow: "POST",
      },
    });
  }

  // ── ① env guard ───────────────────────────────────────────────────────────
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) return jsonError(503, "server_error");
  const apiOrigin = env.ALC_API_ORIGIN;
  if (!apiOrigin) return jsonError(503, "server_error");

  // ── ② device JWT 検証 (browser JWT と同じ検証関数・同じ HS256 secret) ────────
  const token = extractToken(request) ?? "";
  if (!token) return jsonError(401, "Unauthorized");
  const payload = await verifyJwt(token, jwtSecret, env.WORKER_ENV);
  if (!payload) return jsonError(401, "Unauthorized");

  const tenantId = (payload.tenant_id as string | undefined) || "";
  const role = (payload.role as string | undefined) || "";
  if (!tenantId || !role) return jsonError(401, "Unauthorized");

  // ── ③ role → 宛先 (KV、fail-closed) ────────────────────────────────────────
  const recipientId = await resolveRecipient(env, role);
  if (!recipientId) return jsonError(403, "forbidden");

  // ── ④ body 検証 ───────────────────────────────────────────────────────────
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, "invalid_json");
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return jsonError(400, "invalid_body");
  }
  const input = body as Record<string, unknown>;

  // ★ **宛先を device に選ばせない。** client から受け取るのは `text` だけで、
  //   `recipient_id` / `channel_id` は auth-worker 側 (= 上の KV) で固定する。
  //   宛先を device が指定できると、box が盗まれたときに `notify_recipients` の
  //   任意の相手へ DM を送れてしまう。固定しておけば盗難時の被害は「決まった
  //   相手に文字列が飛ぶ」に留まる — この repo 全体が採っている blast radius の
  //   考え方そのもの (`device-data-proxy` の role→path allowlist と同じ)。
  //
  //   **黙って無視せず 400 で弾く。** 無視すると呼び出し側の設定ミスが
  //   「意図しない相手に届いた」の形でしか顕在化しない。rust 側
  //   (`lineworks_channels.rs` の recipient/channel 両指定) が 400 にしているのと同じ流儀。
  if ("recipient_id" in input || "channel_id" in input) {
    return jsonError(400, "recipient_id / channel_id は指定できません (宛先は role で固定)");
  }

  const text = input.text;
  if (typeof text !== "string" || text.length === 0) return jsonError(400, "text required");
  if (text.length > MAX_TEXT_LEN) return jsonError(400, `text は ${MAX_TEXT_LEN} 文字以内`);

  // ── ⑤ forward (internal JWT の mint は auth-worker が代行する) ──────────────
  let internalToken: string;
  try {
    internalToken = await internalAuthToken(env);
  } catch {
    return jsonError(502, "upstream auth error"); // 詳細は log のみ
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
        event: "device_notify_upstream_failed",
        status: upstream.status,
        role,
        body: detail.slice(0, 200),
      }),
    );
    return jsonError(502, "upstream error");
  }

  return upstream;
}

export { ROUTE as DEVICE_NOTIFY_ROUTE };
