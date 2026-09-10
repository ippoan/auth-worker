/**
 * POST /device/claim-ticket — CoreS3 (role=device-hub) が「端末登録の一回券」を取る
 * (Refs #519, ippoan/alc-app-s3#135)。
 *
 * 運行者 PWA の端末登録 (device-kiosk credential) にはこれまで管理者の Google ログインが
 * 要り、共用の運行者 PC では「ログインしていないとタイムカードが空」になっていた。
 * ここでは **USB で PC に物理的に繋がった CoreS3 だけ**が券を取れるようにして Google を外す:
 *
 *   1. CoreS3   : 自分の device JWT で `POST /device/claim-ticket` → `{ticket, expires_in}`
 *   2. CoreS3→PC: USB の host command (`AUTH TICKET`) で **券だけ**をブラウザに渡す
 *   3. ブラウザ : 既存の `POST /device/pair/token` `{device_code: ticket}` で引き換え、
 *                 device-kiosk credential (tenant は hub と同じ) を受け取る
 *
 * 券は既存の headless pairing state (`lib/device-pair.ts`) を合成しただけのもので
 * (`startPairing` → `approvePairing`)、**300 秒・1 回限り**という性質もそこから来ている。
 * device_secret も device JWT も USB には出ない。lib 側に新しい state は足していない。
 *
 * 到達性は公開 path だが、認可は device-hub の JWT (CoreS3 だけが持つ) + revoke 除外 +
 * 発行上限の 3 枚で担保する。cookie を使わないので Origin チェックは要らない。
 */

import type { Env } from "../index";
import { extractToken } from "../lib/errors";
import { resolveSecret } from "../lib/secret";
import {
  verifyDeviceJwt,
  getDeviceRecord,
  DEVICE_ROLE_HUB,
  DEVICE_ROLE_KIOSK,
} from "../lib/device";
import { startPairing, approvePairing } from "../lib/device-pair";

/** 券の有効期限 (秒)。pairing 既定 (600) より短く、USB で手渡す前提の最小限。 */
export const CLAIM_TICKET_TTL_SECONDS = 300;

/** hub 1 台あたりの発行上限 (この枚数を超えたら 429)。 */
const CLAIM_TICKET_MAX_PER_WINDOW = 5;

/** 発行上限のカウンタが生きている秒数 (= 実質の窓幅)。 */
const CLAIM_TICKET_WINDOW_SECONDS = 600;

/** 発行数カウンタの KV key prefix。`hubticket:<device_id>` → 発行済み枚数。 */
const RATE_KV_PREFIX = "hubticket:";

function jsonNoStore(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

/**
 * hub ごとの発行数を 1 つ進める。上限に達していれば false (= 429) を返す。
 *
 * 上限に当たった要求では put しないので、**拒否だけで窓が延びることはない**
 * (窓は最後に成功した発行から `CLAIM_TICKET_WINDOW_SECONDS` で閉じる)。
 */
async function consumeRateLimit(env: Env, deviceId: string): Promise<boolean> {
  const key = RATE_KV_PREFIX + deviceId;
  const parsed = Number.parseInt((await env.AUTH_CONFIG.get(key)) ?? "", 10);
  const issued = Number.isFinite(parsed) ? parsed : 0;
  if (issued >= CLAIM_TICKET_MAX_PER_WINDOW) return false;
  await env.AUTH_CONFIG.put(key, String(issued + 1), {
    expirationTtl: CLAIM_TICKET_WINDOW_SECONDS,
  });
  return true;
}

/** POST /device/claim-ticket — device-hub JWT → 端末登録の一回券。body は見ない。 */
export async function handleDeviceClaimTicket(request: Request, env: Env): Promise<Response> {
  // 設定不足は 401/403 と区別して 503 にする — firmware に「鍵を作り直せ」ではなく
  // 「後で出直せ」と伝えるため。
  if (!env.AUTH_CONFIG) return jsonNoStore({ error: "server_error" }, 503);
  if (!(await resolveSecret(env.JWT_SECRET))) return jsonNoStore({ error: "server_error" }, 503);

  const token = extractToken(request);
  if (!token) return jsonNoStore({ error: "unauthorized" }, 401);
  const claims = await verifyDeviceJwt(env, token);
  if (!claims) return jsonNoStore({ error: "unauthorized" }, 401);

  // 券を取れるのは CoreS3 (device-hub) だけ。kiosk 自身や他 role には配らない。
  if (claims.role !== DEVICE_ROLE_HUB) return jsonNoStore({ error: "forbidden" }, 403);

  // JWT は最長 1h 生きるので、失効済み hub が残りの寿命で券を取れないよう KV も見る。
  const record = await getDeviceRecord(env, claims.sub);
  if (!record || record.revoked) return jsonNoStore({ error: "forbidden" }, 403);

  if (!(await consumeRateLimit(env, claims.sub))) {
    return jsonNoStore({ error: "too_many_tickets" }, 429);
  }

  const now = Math.floor(Date.now() / 1000);
  const pairing = await startPairing(
    env,
    `kiosk via ${claims.sub.slice(0, 8)}`,
    now,
    DEVICE_ROLE_KIOSK,
    CLAIM_TICKET_TTL_SECONDS,
  );
  // 直前に自分で作った pending state なので approve は必ず通る (tenant は JWT 由来で詐称不能)。
  await approvePairing(env, pairing.user_code, claims.tenant_id, now);

  return jsonNoStore({ ticket: pairing.device_code, expires_in: CLAIM_TICKET_TTL_SECONDS });
}
