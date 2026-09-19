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
 * **用途 (usage) が role を決める** (`ALARM_TOKEN_USAGES`、Refs ippoan/alc-app#337):
 *
 *   | usage          | 誰の席か       | nonce purpose  | JWT の role            |
 *   |----------------|----------------|----------------|------------------------|
 *   | `kiosk` (既定) | 運行者端末     | `kiosk`        | `device-kiosk`         |
 *   | `tenko-manager`| 運行管理者席   | `tenko-manager`| `device-tenko-manager` |
 *   | `bp-station`   | 血圧測定台     | `bp-station`   | `device-bp-station`    |
 *
 * **usage は「どの鍵を受け付けるか」と「何の role を出すか」を 1 つの表で同時に決める。**
 * 鍵 (`alarmkey:<fp>`) 側の `usage` と一致しなければ署名検証の時点で落ちるので、
 * **キオスクの鍵 (usage=kiosk) から運行管理者の role は出ない** — nonce の purpose も
 * 用途ごとに分けてあり、運行者端末向けに出した nonce への署名も使い回せない。
 * `usage` 省略時は `kiosk` (既存 CoreS3 ファーム / alc-app との後方互換)。
 *
 * JWT は `mintDeviceJwt` そのもの (aud=device、sub=`alarm:<fp>`、tenant_id=鍵のテナント、
 * role=上の表)。`/device-data-proxy` のその role の許可表をそのまま通り、device record を
 * 引く口 (`/device/claim-ticket` 等) は record が無いので通らない。
 *
 * `/auth/device-login` (#522) と nonce・署名検証を共有するが、こちらは管理者 session を
 * 作らない。ログイン用の nonce も用途 `admin-login` の鍵もここでは使えない (Refs #554) —
 * 運行管理者席にブラウザ JWT を出さないのがこの口を使う理由そのもの
 * (`device-login` は `role: "admin"` のブラウザ JWT を出し、alc-app の顔認証要件を
 * 迂回してしまう。ippoan/alc-app#337 の却下案)。
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
  type AlarmNoncePurpose,
} from "../lib/alarm-nonce";
import {
  mintDeviceJwt,
  DEVICE_ROLE_KIOSK,
  DEVICE_ROLE_TENKO_MANAGER,
  DEVICE_ROLE_BP_STATION,
} from "../lib/device";

/**
 * この口が受け付ける用途 → (nonce の purpose, mint する role) の正本。
 *
 * **ここが唯一の対応表**。鍵の照合 (`verifyAlarmSignature` の `usage`)・nonce の照合
 * (`consumeAlarmNonce` の purpose)・mint する role の 3 つを同じ 1 エントリから引くので、
 * 「キオスクの鍵で運行管理者の role が出る」取り違えが構造的に起きない。
 * 用途を足す時はこの表に 1 行足す (`AlarmKeyUsage` / `AlarmNoncePurpose` にも同名を足す)。
 *
 * `admin-login` は意図して入れない — あれは `/auth/device-login` (ブラウザ session) の用途。
 */
const ALARM_TOKEN_USAGES = {
  kiosk: { noncePurpose: "kiosk", role: DEVICE_ROLE_KIOSK },
  "tenko-manager": { noncePurpose: "tenko-manager", role: DEVICE_ROLE_TENKO_MANAGER },
  "bp-station": { noncePurpose: "bp-station", role: DEVICE_ROLE_BP_STATION },
} as const satisfies Readonly<Record<string, { noncePurpose: AlarmNoncePurpose; role: string }>>;

/** `ALARM_TOKEN_USAGES` の key (= この口で使える `AlarmKeyUsage` の部分集合)。 */
type AlarmTokenUsage = keyof typeof ALARM_TOKEN_USAGES;

/** 用途の既定 (既存 CoreS3 ファーム / alc-app は usage を送らない)。 */
const DEFAULT_ALARM_TOKEN_USAGE: AlarmTokenUsage = "kiosk";

/**
 * 外部入力 (query / body) の usage を表の key に解決する。未指定・空は既定 (kiosk)、
 * 表に無い値は null (= 呼び出し側が拒否する。`admin-login` もここで落ちる)。
 */
function resolveAlarmTokenUsage(raw: unknown): AlarmTokenUsage | null {
  if (raw === undefined || raw === null || raw === "") return DEFAULT_ALARM_TOKEN_USAGE;
  if (typeof raw !== "string") return null;
  return Object.prototype.hasOwnProperty.call(ALARM_TOKEN_USAGES, raw)
    ? (raw as AlarmTokenUsage)
    : null;
}

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

/**
 * `GET /device/alarm-nonce[?usage=…]` — その用途の purpose を持つ nonce を発行する。
 * `usage` 省略時は `kiosk` (後方互換)。表に無い用途は 400。
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

  const nonce = await issueAlarmNonce(env, { purpose: ALARM_TOKEN_USAGES[usage].noncePurpose });
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

  // 用途。ここで決まった 1 エントリから nonce の purpose・鍵の usage・mint する role を
  // 引くので、3 つがズレようがない (表に無い用途は他の失敗と同じ 401)。
  const usage = resolveAlarmTokenUsage(body.usage);
  if (!usage) return invalidAlarmToken();
  const usageConfig = ALARM_TOKEN_USAGES[usage];

  // a. nonce を消費 (single-use、この用途の purpose で発行したものだけ)。
  if (!(await consumeAlarmNonce(env, nonce, usageConfig.noncePurpose))) return invalidAlarmToken();

  // b. 登録済み・未失効・**用途が一致する**鍵で署名を検証する (署名対象は nonce + bpBonded、
  //    `verifyAlarmSignature` 内の `buildAlarmSignedMessage` が組み立て直す)。
  //    キオスクの鍵で運行管理者の JWT を取ろうとすると、ここで落ちる。
  const verified = await verifyAlarmSignature(env, { pubkeyB64, sigB64, nonce, usage, bpBonded });
  if (!verified) return invalidAlarmToken();
  const { fingerprint, record } = verified;

  // c. 鍵ごとの rate limit。署名検証の後に置く (署名できない者に他人の鍵の枠を
  //    消費させない)。device-login の枠とも、他の用途の枠とも subject を分ける。
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
      { device_id: `alarm:${fingerprint}`, tenant_id: record.tenant_id, role: usageConfig.role },
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
