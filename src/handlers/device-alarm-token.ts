/**
 * GET /device/alarm-nonce, POST /device/alarm-token (Refs #551, ippoan/alc-app-s3#135)。
 *
 * ログイン無しで使う PC に警告デバイス (VoiceS3R) を USB で挿すと、その署名で PC を
 * **端末**として認証し、短命の device JWT (role=device-kiosk) を返す。PC には device
 * credential (device_id / device_secret) を発行も保存もしない — 端末である根拠は
 * 「登録済みの鍵で nonce に署名できる VoiceS3R が今繋がっている」ことだけで、JWT が
 * 切れたら同じ手順で取り直す。
 *
 *   1. `GET /device/alarm-nonce`  → `{nonce, expires_in}` (purpose=kiosk の nonce)
 *   2. VoiceS3R が nonce に署名する (契約は `lib/alarm-nonce.ts`)
 *   3. `POST /device/alarm-token` `{nonce, pubkey, sig}`
 *        → `{access_token, token_type, expires_in, tenant_id}` (`/device/token` と同じ形)
 *
 * JWT は `mintDeviceJwt` そのもの (aud=device、sub=`alarm:<fp>`、tenant_id=鍵のテナント、
 * role=device-kiosk)。`/device-data-proxy` の kiosk 許可表をそのまま通り、device record を
 * 引く口 (`/device/claim-ticket` 等) は record が無いので通らない。
 *
 * `/auth/device-login` (#522) と nonce・署名検証を共有するが、こちらは管理者 session を
 * 作らない。nonce は purpose で分けてあり、ログイン用の nonce はここで使えない (逆も同じ)。
 * 鍵も用途で分けてあり、ここで受け付けるのは用途 kiosk で登録した鍵だけ (Refs #554)。
 *
 * 失敗は device-login と同じく固定の 401 (どの段で落ちたかを外部に見せない)。
 * rate limit だけ 429 で区別する。ブラウザから直接 fetch されるので CORS を付ける。
 */
import type { Env } from "../index";
import { corsJsonResponse } from "../lib/errors";
import { checkAndBumpRateLimit, checkAndBumpGrantRateLimit } from "../lib/mcp-pair";
import {
  ALARM_NONCE_TTL_SEC,
  issueAlarmNonce,
  consumeAlarmNonce,
  verifyAlarmSignature,
} from "../lib/alarm-nonce";
import { mintDeviceJwt, DEVICE_ROLE_KIOSK } from "../lib/device";

/** 端末 JWT の寿命 (秒)。 */
export const ALARM_TOKEN_TTL_SEC = 900;
/** alarm-nonce の per-IP rate limit (device-nonce と同じ 30/min)。 */
const NONCE_RATE_LIMIT_PER_MINUTE = 30;
/** alarm-token の per-IP rate limit。 */
const TOKEN_IP_RATE_LIMIT_PER_MINUTE = 30;
/** alarm-token の鍵 (fingerprint) ごとの rate limit (device-login と同じ 10/min)。 */
const TOKEN_KEY_RATE_LIMIT_PER_MINUTE = 10;

/** 全失敗ケースで返す固定文言 (どの段で落ちたか外部に漏らさない)。 */
const INVALID_ALARM_TOKEN_BODY = { error: "invalid_alarm_token" };

function jsonNoStoreCors(data: unknown, status = 200): Response {
  const res = corsJsonResponse(data, status);
  res.headers.set("Cache-Control", "no-store");
  return res;
}

function invalidAlarmToken(): Response {
  return jsonNoStoreCors(INVALID_ALARM_TOKEN_BODY, 401);
}

function rateLimited(): Response {
  return jsonNoStoreCors({ error: "rate_limited" }, 429);
}

async function readJsonBody(request: Request): Promise<Record<string, unknown>> {
  try {
    const v = await request.json();
    if (v && typeof v === "object") return v as Record<string, unknown>;
  } catch {
    // 空 / 不正な body は下の検証で固定の 401 にする
  }
  return {};
}

function stringField(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function clientIp(request: Request): string {
  return request.headers.get("CF-Connecting-IP") ?? "unknown";
}

/** `GET /device/alarm-nonce` — purpose=kiosk の nonce を発行する。 */
export async function handleDeviceAlarmNonce(request: Request, env: Env): Promise<Response> {
  const okRate = await checkAndBumpRateLimit(
    env,
    clientIp(request),
    Date.now(),
    NONCE_RATE_LIMIT_PER_MINUTE,
    "device_alarm/nonce_rate",
  );
  if (!okRate) return rateLimited();

  const nonce = await issueAlarmNonce(env, { purpose: "kiosk" });
  return jsonNoStoreCors({ nonce, expires_in: ALARM_NONCE_TTL_SEC });
}

/** `POST /device/alarm-token` — `{nonce, pubkey, sig}` を検証して端末 JWT を返す。 */
export async function handleDeviceAlarmToken(request: Request, env: Env): Promise<Response> {
  const okIpRate = await checkAndBumpRateLimit(
    env,
    clientIp(request),
    Date.now(),
    TOKEN_IP_RATE_LIMIT_PER_MINUTE,
    "device_alarm/token_rate",
  );
  if (!okIpRate) return rateLimited();

  const body = await readJsonBody(request);
  const nonce = stringField(body.nonce);
  const pubkeyB64 = stringField(body.pubkey);
  const sigB64 = stringField(body.sig);
  if (!nonce || !pubkeyB64 || !sigB64) return invalidAlarmToken();

  // a. nonce を消費 (single-use、purpose=kiosk で発行したものだけ)。
  if (!(await consumeAlarmNonce(env, nonce, "kiosk"))) return invalidAlarmToken();

  // b. 登録済み・未失効・用途が kiosk の鍵で署名を検証する。
  const verified = await verifyAlarmSignature(env, { pubkeyB64, sigB64, nonce, usage: "kiosk" });
  if (!verified) return invalidAlarmToken();
  const { fingerprint, record } = verified;

  // c. 鍵ごとの rate limit。署名検証の後に置く (署名できない者に他人の鍵の枠を
  //    消費させない)。device-login の枠とは subject を分ける。
  const okKeyRate = await checkAndBumpGrantRateLimit(
    env,
    `alarm-kiosk:${fingerprint}`,
    Date.now(),
    TOKEN_KEY_RATE_LIMIT_PER_MINUTE,
  );
  if (!okKeyRate) return rateLimited();

  // d. mint は `/device/token` と同じ `mintDeviceJwt`。device record は無いので
  //    必要な 3 項目だけを渡す。
  let token: string;
  try {
    token = await mintDeviceJwt(
      env,
      { device_id: `alarm:${fingerprint}`, tenant_id: record.tenant_id, role: DEVICE_ROLE_KIOSK },
      Math.floor(Date.now() / 1000),
      ALARM_TOKEN_TTL_SEC,
    );
  } catch {
    return jsonNoStoreCors({ error: "server_error" }, 503);
  }

  console.log(
    JSON.stringify({
      event: "device_alarm_token_success",
      fingerprint,
      tenantId: record.tenant_id,
    }),
  );
  return jsonNoStoreCors({
    access_token: token,
    token_type: "Bearer",
    expires_in: ALARM_TOKEN_TTL_SEC,
    tenant_id: record.tenant_id,
  });
}
