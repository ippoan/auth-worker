/**
 * GET /auth/device-nonce, GET /auth/device-login (issue #522)。
 *
 * 管理者の認証を「Google ログイン」に加えて「登録済みの VoiceS3R (警告デバイス、
 * ippoan/alc-app-s3#205) が USB で繋がっていること」で成立させる 2 系統目。
 * VoiceS3R は機体内の ed25519 秘密鍵でサーバの nonce を署名し、公開鍵は
 * `#521` (`alarm-key.ts`) で `alarmkey:<fp>` に登録済み。ここは:
 *
 *   1. `GET /auth/device-nonce?redirect_uri=` — nonce を発行して KV に積む
 *   2. `GET /auth/device-login?pubkey=&nonce=&sig=&redirect_uri=` — 署名を検証し
 *      Google ログインと同じ `finishLogin` (`lib/finish-login.ts`) へ合流する
 *
 * nonce の発行・消費と署名検証は `/device/alarm-token` (#551) と共有する
 * (`lib/alarm-nonce.ts`)。ここで発行する nonce は purpose=login で、端末 JWT 用
 * (purpose=kiosk) の nonce はここでは受け付けない。
 *
 * 契約 (alc-app #214 / firmware #205 と共有、変えるときは issue で合意する):
 *   - nonce = 小文字 hex 32 文字。署名対象は **その ASCII 32 バイト** (hex→raw
 *     デコードした 16 バイトではない — firmware 側が hex 文字列をそのまま
 *     署名するため、サーバ側もそれに合わせる)
 *   - pubkey / sig は base64url (raw bytes、`alarm-key.ts::decodeBase64Url` と
 *     同じ decode)。sig は 64 B (Ed25519 signature 長)
 *   - `redirect_uri` は device-nonce 発行時と device-login 消費時で **完全一致**
 *     必須 (nonce 発行時に許可された origin 以外へ、署名を使い回して飛ばせない
 *     ようにする login CSRF 対策)。加えて両エンドポイントとも
 *     `isAllowedRedirectUri` を通す (Google callback と同じ defense in depth)
 *
 * `device-login` は cookie も Bearer も持たない匿名の top-level navigation
 * (Origin ヘッダは付かない想定) なので Origin チェックは行わない。
 *
 * 失敗はすべて **同じ固定文言・同じ 401** で返す (nonce 不明/再利用・
 * redirect_uri 不一致・pubkey 未登録・revoked・署名不一致のどれかを外部から
 * 判別させない — enumeration 対策)。rate limit だけ 429 で区別する。
 */
import type { Env } from "../index";
import { corsJsonResponse } from "../lib/errors";
import { isAllowedRedirectUri } from "../lib/security";
import { getAllowedOrigins } from "../lib/config";
import { checkAndBumpRateLimit, checkAndBumpGrantRateLimit } from "../lib/mcp-pair";
import {
  ALARM_NONCE_TTL_SEC,
  issueAlarmNonce,
  consumeAlarmNonce,
  verifyAlarmSignature,
} from "../lib/alarm-nonce";
import { signJwt } from "../lib/jwt";
import { resolveSecret } from "../lib/secret";
import { finishLogin } from "../lib/finish-login";

/** device-nonce の per-IP rate limit (issue 本文どおり 30/min)。 */
const NONCE_RATE_LIMIT_PER_MINUTE = 30;
/** device-login の per-subject (= fingerprint) rate limit (issue 本文どおり 10/min)。 */
const LOGIN_RATE_LIMIT_PER_MINUTE = 10;
/** device-key token の TTL (秒)。`createAccessToken` の access JWT と揃える。 */
const DEVICE_TOKEN_TTL_SEC = 3600;

/** 全失敗ケースで返す固定文言 (どの段で落ちたか外部に漏らさない)。 */
const INVALID_DEVICE_LOGIN_BODY = { error: "invalid_device_login" };

function jsonNoStoreCors(data: unknown, status = 200): Response {
  const res = corsJsonResponse(data, status);
  res.headers.set("Cache-Control", "no-store");
  return res;
}

function invalidDeviceLogin(): Response {
  return jsonNoStoreCors(INVALID_DEVICE_LOGIN_BODY, 401);
}

/**
 * `GET /auth/device-nonce?redirect_uri=<url>` — nonce を発行し、`redirect_uri`
 * と一緒に KV (`devnonce:<nonce>`, TTL 60s, purpose=login) に積む。
 */
export async function handleDeviceNonce(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const redirectUri = url.searchParams.get("redirect_uri") ?? "";
  if (!redirectUri || !isAllowedRedirectUri(redirectUri, await getAllowedOrigins(env))) {
    return jsonNoStoreCors({ error: "invalid redirect_uri" }, 400);
  }

  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const okRate = await checkAndBumpRateLimit(
    env,
    ip,
    Date.now(),
    NONCE_RATE_LIMIT_PER_MINUTE,
    "device_login/nonce_rate",
  );
  if (!okRate) {
    return jsonNoStoreCors({ error: "rate_limited" }, 429);
  }

  const nonce = await issueAlarmNonce(env, { purpose: "login", redirectUri });
  return jsonNoStoreCors({ nonce, expires_in: ALARM_NONCE_TTL_SEC });
}

/**
 * `GET /auth/device-login?pubkey=&nonce=&sig=&redirect_uri=` — 署名検証後、
 * Google ログインと同じ `finishLogin` に合流する (top-level navigation)。
 */
export async function handleDeviceLogin(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const pubkeyB64 = url.searchParams.get("pubkey") ?? "";
  const nonce = url.searchParams.get("nonce") ?? "";
  const sigB64 = url.searchParams.get("sig") ?? "";
  const redirectUri = url.searchParams.get("redirect_uri") ?? "";

  if (!pubkeyB64 || !nonce || !sigB64 || !redirectUri) {
    return invalidDeviceLogin();
  }

  // a. nonce を消費 (single-use、purpose=login で発行したものだけ)。KV の
  //    redirect_uri と query の redirect_uri が完全一致しなければ弾く (署名を
  //    別 origin へ飛ばす login CSRF 対策)。
  const nonceRecord = await consumeAlarmNonce(env, nonce, "login");
  if (!nonceRecord || nonceRecord.redirect_uri !== redirectUri) {
    return invalidDeviceLogin();
  }
  // g. Google と同じ defense-in-depth: 発行時に許可されていた origin が、消費
  //    時点でも allowlist に残っているか再検証する。
  if (!isAllowedRedirectUri(redirectUri, await getAllowedOrigins(env))) {
    return invalidDeviceLogin();
  }

  // b. / c. fp(pubkey) で alarmkey:<fp> を引き (無い / revoked / 用途が admin-login
  //    でない → 401)、登録済みの公開鍵で nonce の ASCII 32 バイトへの署名を検証する
  //    (`lib/alarm-nonce.ts`)。
  const verified = await verifyAlarmSignature(env, {
    pubkeyB64,
    sigB64,
    nonce,
    usage: "admin-login",
  });
  if (!verified) {
    return invalidDeviceLogin();
  }
  const { fingerprint, record } = verified;

  // d. per-subject (= fingerprint) rate limit。失敗は 429 (固定 401 とは区別)。
  const okRate = await checkAndBumpGrantRateLimit(
    env,
    fingerprint,
    Date.now(),
    LOGIN_RATE_LIMIT_PER_MINUTE,
  );
  if (!okRate) {
    return jsonNoStoreCors({ error: "rate_limited" }, 429);
  }

  // e. token の mint — `lib/dev-login.ts::mintDevToken` と同じ inline signJwt
  //    (`createAccessToken` / rust 厳密一致の対象は触らない)。
  const jwtSecret = await resolveSecret(env.JWT_SECRET);
  if (!jwtSecret) {
    return jsonNoStoreCors({ error: "server_error" }, 503);
  }
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    sub: `alarm:${fingerprint}`,
    email: "",
    name: `警告デバイス ${record.label}`,
    tenant_id: record.tenant_id,
    role: "admin",
    token_kind: "device-key",
    iat: now,
    exp: now + DEVICE_TOKEN_TTL_SEC,
  };
  const token = await signJwt(claims, jwtSecret);

  // f. 後段は Google と共通の finishLogin。cookie の Max-Age は token の実 TTL
  //    (3600s) に合わせる (Google の既定 24h と違い、device-key はここで揃える)。
  return finishLogin(request, env, {
    token,
    expiresAt: String(now + DEVICE_TOKEN_TTL_SEC),
    tenantId: record.tenant_id,
    email: "",
    redirectUri,
    cookieMaxAgeSec: DEVICE_TOKEN_TTL_SEC,
    eventPrefix: "device_login",
  });
}
