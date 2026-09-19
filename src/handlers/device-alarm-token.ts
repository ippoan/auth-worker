/**
 * GET /device/alarm-nonce, POST /device/alarm-token (Refs #551, ippoan/alc-app-s3#135)。
 *
 * ログイン無しで使う PC に警告デバイス (VoiceS3R) を USB で挿すと、その署名で PC を
 * **端末**として認証し、短命の device JWT を返す。PC には device credential
 * (device_id / device_secret) を発行も保存もしない — 端末である根拠は
 * 「登録済みの鍵で nonce に署名できる VoiceS3R が今繋がっている」ことだけで、JWT が
 * 切れたら同じ手順で取り直す。
 *
 *   1. `GET /device/alarm-nonce[?usage=…]` → `{nonce, expires_in}` (その用途の purpose)
 *   2. VoiceS3R が nonce に署名する (契約は `lib/alarm-nonce.ts`)
 *   3. `POST /device/alarm-token` `{nonce, pubkey, sig, usage?}`
 *        → `{access_token, token_type, expires_in, tenant_id}` (`/device/token` と同じ形)
 *
 * **用途 (usage) が role を決める** (Refs ippoan/alc-app#337):
 *
 *   | usage           | 誰の席か     | JWT の role             |
 *   |-----------------|--------------|--------------------------|
 *   | `kiosk` (既定)  | 運行者端末   | `device-kiosk`           |
 *   | `tenko-manager` | 運行管理者席 | `device-tenko-manager`   |
 *   | `bp-station`    | 血圧測定台   | `device-bp-station`      |
 *
 * **3 用途とも role は `device-<usage>` の 1:1 対応**なので、対応表は持たず
 * `roleForUsage` で計算する (Refs ippoan/alc-app#353。以前は管理者ログイン用途
 * (ブラウザ経由、席ではなく口を表す別軸) が混ざっていたため対応表が要ったが、
 * 本番で未使用だったため畳んだ — `AlarmKeyUsage` = `AlarmNoncePurpose` = この口が
 * 受け付ける用途、の 3 つが完全に同じ語彙になった)。usage は nonce の purpose にもそのまま
 * 使う。鍵 (`alarmkey:<fp>`) 側の `usage` と一致しなければ署名検証の時点で落ちるので、
 * **キオスクの鍵 (usage=kiosk) から運行管理者の role は出ない** — nonce の purpose も
 * 用途ごとに分けてあり、運行者端末向けに出した nonce への署名も使い回せない。
 * `usage` 省略時は `kiosk` (既存 CoreS3 ファーム / alc-app との後方互換)。
 *
 * JWT は `mintDeviceJwt` そのもの (aud=device、sub=`alarm:<fp>`、tenant_id=鍵のテナント、
 * role=`roleForUsage(usage)`)。`/device-data-proxy` のその role の許可表をそのまま通り、
 * device record を引く口 (`/device/claim-ticket` 等) は record が無いので通らない。
 *
 * 失敗は固定の 401 (どの段で落ちたかを外部に見せない)。
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
import { mintDeviceJwt } from "../lib/device";
import { ALARM_KEY_USAGES, type AlarmKeyUsage } from "./alarm-key";

/**
 * usage → 端末 JWT の role。`ALARM_KEY_USAGES` の 3 用途とも `device-<usage>` の
 * 1:1 対応 (Refs ippoan/alc-app#353。`DEVICE_ROLE_KIOSK` 等の定数値と一致することは
 * テストで固定する)。
 */
export function roleForUsage(usage: AlarmKeyUsage): string {
  return `device-${usage}`;
}

/** 用途の既定 (既存 CoreS3 ファーム / alc-app は usage を送らない)。 */
const DEFAULT_ALARM_TOKEN_USAGE: AlarmKeyUsage = "kiosk";

/**
 * 外部入力 (query / body) の usage を `AlarmKeyUsage` に解決する。未指定・空は既定
 * (kiosk)、`ALARM_KEY_USAGES` に無い値は null (= 呼び出し側が拒否する。fail-closed。
 * 畳んだ旧・管理者ログイン用途もここで落ちる)。
 */
function resolveAlarmTokenUsage(raw: unknown): AlarmKeyUsage | null {
  if (raw === undefined || raw === null || raw === "") return DEFAULT_ALARM_TOKEN_USAGE;
  if (typeof raw !== "string") return null;
  return (ALARM_KEY_USAGES as ReadonlyArray<string>).includes(raw) ? (raw as AlarmKeyUsage) : null;
}

/** 端末 JWT の寿命 (秒)。 */
export const ALARM_TOKEN_TTL_SEC = 900;
/** alarm-nonce の per-IP rate limit。 */
const NONCE_RATE_LIMIT_PER_MINUTE = 30;
/** alarm-token の per-IP rate limit。 */
const TOKEN_IP_RATE_LIMIT_PER_MINUTE = 30;
/** alarm-token の鍵 (fingerprint) ごとの rate limit。 */
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

/**
 * `GET /device/alarm-nonce[?usage=…]` — その用途の purpose を持つ nonce を発行する。
 * `usage` 省略時は `kiosk` (後方互換)。`ALARM_KEY_USAGES` に無い用途は 400。
 */
export async function handleDeviceAlarmNonce(request: Request, env: Env): Promise<Response> {
  const okRate = await checkAndBumpRateLimit(
    env,
    clientIp(request),
    Date.now(),
    NONCE_RATE_LIMIT_PER_MINUTE,
    "device_alarm/nonce_rate",
  );
  if (!okRate) return rateLimited();

  const usage = resolveAlarmTokenUsage(new URL(request.url).searchParams.get("usage"));
  // まだ何も認証していない口なので、ここは 401 に寄せず素直に 400 で返す
  // (呼び出し側の綴り間違いを「鍵が違う」と誤診させない)。
  if (!usage) return jsonNoStoreCors({ error: "invalid_usage" }, 400);

  // nonce の purpose は usage と同じ値 (`AlarmNoncePurpose` = `AlarmKeyUsage`)。
  const nonce = await issueAlarmNonce(env, { purpose: usage });
  return jsonNoStoreCors({ nonce, expires_in: ALARM_NONCE_TTL_SEC });
}

/** `POST /device/alarm-token` — `{nonce, pubkey, sig, usage?}` を検証して端末 JWT を返す。 */
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

  // 血圧計のボンド状態 (Refs #571)。無ければ undefined (古いファーム、「不明」として
  // 扱う = 今までどおり nonce だけで検証)。boolean 以外の値が付いていれば不正な body。
  const bpBondedRaw = body.bp_bonded;
  if (bpBondedRaw !== undefined && typeof bpBondedRaw !== "boolean") return invalidAlarmToken();
  const bpBonded = bpBondedRaw as boolean | undefined;

  // 用途。ここで決まった usage を nonce の purpose・鍵の usage・mint する role
  // (`roleForUsage`) の 3 つにそのまま使うので、3 つがズレようがない
  // (`ALARM_KEY_USAGES` に無い用途は他の失敗と同じ 401)。
  const usage = resolveAlarmTokenUsage(body.usage);
  if (!usage) return invalidAlarmToken();

  // a. nonce を消費 (single-use、この用途の purpose で発行したものだけ)。
  if (!(await consumeAlarmNonce(env, nonce, usage))) return invalidAlarmToken();

  // b. 登録済み・未失効・**用途が一致する**鍵で署名を検証する (署名対象は nonce + bpBonded、
  //    `verifyAlarmSignature` 内の `buildAlarmSignedMessage` が組み立て直す)。
  //    キオスクの鍵で運行管理者の JWT を取ろうとすると、ここで落ちる。
  const verified = await verifyAlarmSignature(env, { pubkeyB64, sigB64, nonce, usage, bpBonded });
  if (!verified) return invalidAlarmToken();
  const { fingerprint, record } = verified;

  // c. 鍵ごとの rate limit。署名検証の後に置く (署名できない者に他人の鍵の枠を
  //    消費させない)。他の用途の枠とも subject を分ける。
  const okKeyRate = await checkAndBumpGrantRateLimit(
    env,
    `alarm-${usage}:${fingerprint}`,
    Date.now(),
    TOKEN_KEY_RATE_LIMIT_PER_MINUTE,
  );
  if (!okKeyRate) return rateLimited();

  // d. mint は `/device/token` と同じ `mintDeviceJwt`。device record は無いので
  //    必要な 3 項目だけを渡す。bpBonded は署名検証を通った値そのもの (b で確かめ済み)
  //    なので、そのまま claim に渡してよい。
  let token: string;
  try {
    token = await mintDeviceJwt(
      env,
      { device_id: `alarm:${fingerprint}`, tenant_id: record.tenant_id, role: roleForUsage(usage) },
      Math.floor(Date.now() / 1000),
      ALARM_TOKEN_TTL_SEC,
      { bpBonded },
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
