/**
 * 無人デバイス (smb-watch 等) 向けの device credential + device JWT 発行 (Phase 2)。
 *
 * 設計 (ohishi-exp/smb-watch#1 Phase 2 / 案B):
 *   - pairing (browser・Google ログインで tenant 確定) で **長命 device credential**
 *     (device_id + device_secret) を 1 個発行し KV に保管する。secret は平文保存せず
 *     sha-256 ハッシュのみ持つ。revocable。
 *   - runtime (無人 box) は device credential を `/device/token` に提示し、**短命
 *     device JWT** を mint してもらう。JWT は `JWT_SECRET` (rust-alc-api と HS256 共有)
 *     で署名し、`/auth/introspect` が検証する通常の auth-worker JWT と同型。
 *   - device JWT の role は最小権限 (`DEVICE_ROLE`)。盗難時の blast radius を限定する。
 *
 * 署名様式は `internal-jwt.ts` の `signHs256` に合わせる (header {alg:HS256,typ:JWT}、
 * base64url、JWT_SECRET)。round-trip は `jwt.ts::verifyJwt` で検証できる。
 */

import { base64Encode } from "./lineworks-crypto";
import { resolveSecret, type SecretBinding } from "./secret";

const TEXT_ENCODER = new TextEncoder();

/** KV key prefix。`device:<device_id>` に DeviceRecord(JSON) を格納する。 */
const KV_PREFIX = "device:";

/**
 * label 二次索引の KV key prefix。`device-label:<tenant_id>:<label>` →
 * device_id (プレーン文字列)。`createDeviceCredentialReplacingLabel` が
 * 同一 tenant+label の再発行時に旧 credential を引くために使う (Refs #495 PR2)。
 */
const LABEL_INDEX_PREFIX = "device-label:";

function labelIndexKey(tenantId: string, label: string): string {
  return `${LABEL_INDEX_PREFIX}${tenantId}:${label}`;
}

/** device JWT の既定 TTL (1h)。box は run のたびに mint する。 */
export const DEVICE_JWT_TTL_SECONDS = 3600;

/**
 * device JWT の既定 role。carins ファイル upload 専用の最小権限。
 * admin / 他 API を含めない (= 盗難時も「1 tenant の車検証 upload」に限定)。
 */
export const DEVICE_ROLE = "device-uploader";

/**
 * alc-app キオスク端末用 role。kiosk が叩く最小 route (measurements / tenko /
 * timecard 等) のみを許可する想定で、consumer (rust-alc-api) 側が route 許可を判定する。
 * carins upload (`device-uploader`) とは blast radius を用途別に分離する (Refs rust-alc-api#434)。
 */
export const DEVICE_ROLE_KIOSK = "device-kiosk";

/**
 * Kagoya VPS 上の無人 dtako データ投入系サービス (browser-render-rust の
 * dtakolog cron / dtako-scraper の CSV アップロード) 共用 role。同一 VPS・同一
 * 運用チーム・同一機能ドメイン (dtako データの rust-alc-api への ingest) なので、
 * サービスごとに role を分けず 1 role に統一する (2026-07-01、dtako-scraper#14
 * 対応時に device-dtako-upload 単独 role 新設案から方針転換)。
 *
 * 許可 path は `device-data-proxy.ts` の `ROLE_PATH_ALLOWLIST` 側で管理
 * (`/api/dtako-logs/bulk` + `/api/upload`)。device credential (device_id/
 * device_secret) 自体はサービス・テナントごとに個別発行するため、rotate/revoke
 * の粒度は role 統一後も維持される (role は「できること」、credential は
 * 「誰が」の軸で直交する)。
 */
export const DEVICE_ROLE_DTAKO_INGEST = "device-dtako-ingest";

/**
 * dtako-scraper-relay (Cloudflare Worker、無人 cron) がスクレイプ履歴を読み書き
 * するための role (Refs ohishi-exp/nuxt-dtako-admin#931 / #933)。
 *
 * **`device-dtako-ingest` と分ける。** あちらは「**同一 VPS・同一運用チーム・
 * 同一機能ドメイン (dtako データの rust-alc-api への ingest)**」を条件に 1 role へ
 * 統一したもので、relay は **箱が違い (Kagoya VPS ではなく Cloudflare Worker)**、
 * **capability も違う (ingest ではなく履歴の読み書き)** ため、その条件に入らない。
 *
 * 再利用すると **双方向に権限が広がる** — VPS の device が履歴を書けるようになり、
 * relay が要らない `/api/upload` `/api/dtako-logs/bulk` を持つ。
 *
 * 許可 path は `device-data-proxy.ts` の `ROLE_PATH_ALLOWLIST` 側で管理
 * (`/api/scraper/history` + `/api/dtako/events/etags`)。どちらも rust の
 * `tenant_router()` = data 経路なので、**`alc-internal-proxy` では通せない**
 * (shared secret だけで X-Tenant-ID を詐称できると #434 の再現になるため、
 * あちらは data 経路を意図的に allowlist から外している)。
 */
export const DEVICE_ROLE_DTAKO_RELAY = "device-dtako-relay";

/**
 * cf-flickr-cam-worker (Cloudflare Worker、無人 cron) 用 role。ohishi-logi
 * (Cloud Run、無状態 camera fetcher) の `/cam/*` RPC のみを許可する
 * (Refs ohishi-exp/ohishi-logi#1, ippoan/cf-flickr-cam-worker#1)。
 * 許可 path は `ohishi-logi-proxy.ts` 側で管理。
 */
export const DEVICE_ROLE_CAM_FLICKR = "device-cam-flickr";

/**
 * alc-app-s3 (M5Stack CoreS3) 組み込みハブ専用 role。cf-alc-recorder (WS 受口) が
 * introspect でこの role のみ accept し、hub は測定データ ingest 用途に限定する。
 * `device-kiosk` (ブラウザキオスク) とは blast radius を分離する
 * (Refs #363, ippoan/alc-app#106)。
 */
export const DEVICE_ROLE_HUB = "device-hub";

/**
 * alc-app-s3 (AtomS3 + PoE) 印刷ブリッジ専用 role (ippoan/alc-app-s3#38)。
 * cf-alc-recorder が hub と並んで accept する (下り print/ota command の待受)。
 * /device/setup の OTA gate は role で firmware を分けるため、hub と混ぜない。
 */
export const DEVICE_ROLE_PRINT = "device-print";

/**
 * 拠点ゲートウェイ (Windows alc-gw / Unit PoE-P4) 専用 role (Refs #406)。
 * `/device/hub-token` を mint できる role の一つ。WHIP 拠点トークンの mint も
 * 将来的にこの role の device credential に統合する設計 (site-device-auth-project)。
 */
export const DEVICE_ROLE_GATEWAY = "device-gateway";

/** pairing / credential 発行で受理する device role の allowlist。 */
export const DEVICE_ROLES: ReadonlySet<string> = new Set([
  DEVICE_ROLE,
  DEVICE_ROLE_KIOSK,
  DEVICE_ROLE_DTAKO_INGEST,
  DEVICE_ROLE_DTAKO_RELAY,
  DEVICE_ROLE_CAM_FLICKR,
  DEVICE_ROLE_HUB,
  DEVICE_ROLE_PRINT,
  DEVICE_ROLE_GATEWAY,
]);

/** `/device/hub-token` を mint できる role (拠点デバイスの相互認証、Refs #406)。 */
export const HUB_TOKEN_ELIGIBLE_ROLES: ReadonlySet<string> = new Set([
  DEVICE_ROLE_HUB,
  DEVICE_ROLE_GATEWAY,
]);

/**
 * 受け取った role 文字列を allowlist で検証して返す。未知 / 空は既定 (`DEVICE_ROLE`)。
 * device JWT の role は blast radius を決めるので、外部入力をそのまま信用せず必ず通す。
 */
export function normalizeDeviceRole(raw: unknown): string {
  return typeof raw === "string" && DEVICE_ROLES.has(raw) ? raw : DEVICE_ROLE;
}

/** KV に保管する device レコード。平文 secret は持たない。 */
export interface DeviceRecord {
  device_id: string;
  tenant_id: string;
  /** sha-256(device_secret) の hex。検証は hash 同士の定数時間比較で行う。 */
  secret_hash: string;
  /** 運用識別用ラベル (例: "ohishi-data smb-watch")。 */
  label: string;
  /**
   * device JWT に載せる role (blast radius)。旧レコードには無いので
   * `mintDeviceJwt` は `?? DEVICE_ROLE` で後方互換に倒す。
   */
  role?: string;
  /**
   * 拠点 ID (Refs #406)。`device-hub` / `device-gateway` の 1:1 束縛と
   * `/device/hub-token` の claim に使う。
   *
   * **既定は hub 自身の `device_id`** (2026-07-19 改訂): 拠点は物理的に
   * 1 hub = 1 site なので、`device-hub` credential は `createDeviceCredential`
   * が siteId 省略時に自動で `device_id` を site_id にする (人手採番不要)。
   * hub が交換され device_id が変われば site_id も変わり、GW 側の再ポイントで
   * 自然に追従する (「hub 交換 = 再接続」として扱う設計)。alc-app に将来
   * 拠点レジストリができた際は、その恒久 ID への置き換えを別途検討する。
   * 未設定の既存 (この改訂前に発行された) device-hub credential は
   * `/device/setup/site` や `/device/site/backfill` で事後付与する。
   */
  site_id?: string;
  /** 発行時刻 (unix 秒)。 */
  created_at: number;
  /** revoke 済みフラグ。true なら検証は常に失敗する。 */
  revoked: boolean;
}

/** KV binding だけを要求する env サブセット。 */
export interface DeviceKvEnv {
  AUTH_CONFIG: KVNamespace;
}

/** JWT 署名に要る env サブセット (`internal-jwt.ts` と同じ)。 */
export interface DeviceJwtEnv {
  JWT_SECRET: SecretBinding;
  WORKER_ENV: string;
}

/** pairing 発行結果。`device_secret` は平文で、この 1 回だけ呼び出し側に返る。 */
export interface NewDeviceCredential {
  device_id: string;
  device_secret: string;
  record: DeviceRecord;
}

/** crypto.getRandomValues ベースの base64url ランダムトークン。 */
function randomToken(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return base64UrlEncode(buf);
}

/** sha-256 を hex 文字列で返す。 */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", TEXT_ENCODER.encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * 新規 device credential を発行し KV に保管する。
 * 返り値の `device_secret` は平文で、発行時の 1 回だけ取得できる (KV には hash のみ)。
 */
export async function createDeviceCredential(
  env: DeviceKvEnv,
  tenantId: string,
  label: string,
  now: number,
  role: string = DEVICE_ROLE,
  siteId?: string,
): Promise<NewDeviceCredential> {
  const device_id = randomToken(16);
  const device_secret = randomToken(32);
  const normalizedRole = normalizeDeviceRole(role);
  // device-hub は 1 hub = 1 site が物理的な前提なので、siteId 省略時は自分の
  // device_id を site_id にする (人手採番不要、Refs #406 改訂)。gateway 等は
  // 対象 hub の device_id を明示的に渡す運用のため自動化しない。
  const resolvedSiteId = siteId ?? (normalizedRole === DEVICE_ROLE_HUB ? device_id : undefined);
  const record: DeviceRecord = {
    device_id,
    tenant_id: tenantId,
    secret_hash: await sha256Hex(device_secret),
    label,
    role: normalizedRole,
    ...(resolvedSiteId ? { site_id: resolvedSiteId } : {}),
    created_at: now,
    revoked: false,
  };
  await env.AUTH_CONFIG.put(KV_PREFIX + device_id, JSON.stringify(record));
  return { device_id, device_secret, record };
}

/**
 * `createDeviceCredential` の label-aware 版 (Refs #495 PR2、kiosk 端末
 * re-pair 用)。同一 (tenant_id, label) で過去に発行した credential が
 * label 二次索引にあれば、新規 mint 前に revoke する。
 *
 * これにより「re-pair の度に旧 credential が dormant のまま残り続ける」
 * 問題を解消する — 索引が無かった旧 `createDeviceCredential` 単体呼び出し
 * (`/device/pair` browser flow 等) では蓄積していた。
 *
 * revoke 対象が既に無い/revoke 済みでも新規発行は続行する (冪等)。
 */
export async function createDeviceCredentialReplacingLabel(
  env: DeviceKvEnv,
  tenantId: string,
  label: string,
  now: number,
  role: string = DEVICE_ROLE,
  siteId?: string,
): Promise<NewDeviceCredential> {
  const indexKey = labelIndexKey(tenantId, label);
  const previousDeviceId = await env.AUTH_CONFIG.get(indexKey);
  if (previousDeviceId) {
    await revokeDeviceCredential(env, previousDeviceId);
  }

  const cred = await createDeviceCredential(env, tenantId, label, now, role, siteId);
  await env.AUTH_CONFIG.put(indexKey, cred.device_id);
  return cred;
}

/**
 * 既存 device credential (主に device-hub) に事後で site_id を付与する
 * (Refs #406: alc-app にまだ拠点レジストリが無いため、既に現場に出ている CoreS3
 * credential は provisioning 時ではなく事後 backfill で site_id を付ける)。
 * revoke 済み credential にも付与自体は許す (履歴保持のため forbid しない)。
 * 不在なら null。
 */
export async function setDeviceSiteId(
  env: DeviceKvEnv,
  deviceId: string,
  siteId: string,
): Promise<DeviceRecord | null> {
  const record = await getDeviceRecord(env, deviceId);
  if (!record) return null;
  record.site_id = siteId;
  await env.AUTH_CONFIG.put(KV_PREFIX + deviceId, JSON.stringify(record));
  return record;
}

/**
 * tenant に紐づく有効な (revoke されていない) device credential 一覧を
 * 発行日時降順で返す (Refs /device/setup の登録済み一覧)。
 *
 * KV には tenant 二次索引が無いため `device:` prefix を全走査して filter する
 * (device 数は運用上小さい前提。list 上限 1000 keys を超える規模になったら
 * `device-tenant:<tenant>:` 二次索引の導入を検討する)。
 */
export async function listDeviceRecordsByTenant(
  env: DeviceKvEnv,
  tenantId: string,
): Promise<DeviceRecord[]> {
  const listed = await env.AUTH_CONFIG.list({ prefix: KV_PREFIX, limit: 1000 });
  const records = await Promise.all(
    listed.keys.map((k) => getDeviceRecord(env, k.name.slice(KV_PREFIX.length))),
  );
  return records
    .filter((r): r is DeviceRecord => !!r && r.tenant_id === tenantId && !r.revoked)
    .sort((a, b) => b.created_at - a.created_at);
}

/** `listAllHubDeviceRecords` が返す最小限のフィールド (secret_hash 等の機微値は含めない)。 */
export interface HubDeviceRef {
  tenant_id: string;
  device_id: string;
}

/**
 * role=device-hub (CoreS3) の有効な device を tenant 横断で列挙する
 * (cf-alc-recorder cron の対象一覧、ippoan/alc-app#121 / #401)。
 *
 * `listDeviceRecordsByTenant` と同じ全走査 (device 数は運用上小さい前提)。
 * server-to-server 専用 (`GET /internal/hub-devices`) からのみ呼ばれるため、
 * 返り値は secret_hash / label を含まない最小限の参照だけに絞る。
 */
export async function listAllHubDeviceRecords(env: DeviceKvEnv): Promise<HubDeviceRef[]> {
  const listed = await env.AUTH_CONFIG.list({ prefix: KV_PREFIX, limit: 1000 });
  const records = await Promise.all(
    listed.keys.map((k) => getDeviceRecord(env, k.name.slice(KV_PREFIX.length))),
  );
  return records
    .filter((r): r is DeviceRecord => !!r && !r.revoked && r.role === DEVICE_ROLE_HUB)
    .map((r) => ({ tenant_id: r.tenant_id, device_id: r.device_id }));
}

/** device レコードを KV から読む。不在 / JSON 破損は null。 */
export async function getDeviceRecord(
  env: DeviceKvEnv,
  deviceId: string,
): Promise<DeviceRecord | null> {
  const raw = await env.AUTH_CONFIG.get(KV_PREFIX + deviceId);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as DeviceRecord;
  } catch {
    return null;
  }
}

/** device を revoke する。存在して revoke できたら true、不在なら false。 */
export async function revokeDeviceCredential(
  env: DeviceKvEnv,
  deviceId: string,
): Promise<boolean> {
  const record = await getDeviceRecord(env, deviceId);
  if (!record) return false;
  record.revoked = true;
  await env.AUTH_CONFIG.put(KV_PREFIX + deviceId, JSON.stringify(record));
  return true;
}

/** 長さ一致前提の定数時間比較 (hash は固定長 hex なので長さ差は即 false で良い)。 */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * device_id + device_secret を検証し、有効なら DeviceRecord を返す。
 * 不在 / revoke 済み / secret 不一致はいずれも null (情報リークを避け区別しない)。
 */
export async function verifyDeviceCredential(
  env: DeviceKvEnv,
  deviceId: string,
  deviceSecret: string,
): Promise<DeviceRecord | null> {
  const record = await getDeviceRecord(env, deviceId);
  if (!record || record.revoked) return null;
  const hash = await sha256Hex(deviceSecret);
  if (!constantTimeEqual(hash, record.secret_hash)) return null;
  return record;
}

/** device JWT の claims。introspect が読む tenant_id / role / env / exp を持つ。 */
export interface DeviceJwtClaims {
  sub: string;
  tenant_id: string;
  role: string;
  env: string;
  iat: number;
  exp: number;
  [key: string]: unknown;
}

/**
 * device JWT を mint する (HS256 / JWT_SECRET)。`/auth/introspect` が
 * verifyJwt(JWT_SECRET, WORKER_ENV) + tenant_id + ACL で検証する。
 * `JWT_SECRET` 未設定なら throw (caller が 500 を返す前提)。
 */
export async function mintDeviceJwt(
  env: DeviceJwtEnv,
  record: DeviceRecord,
  now: number,
  ttlSeconds: number = DEVICE_JWT_TTL_SECONDS,
): Promise<string> {
  const secret = await resolveSecret(env.JWT_SECRET);
  if (!secret) {
    throw new Error("JWT_SECRET not configured");
  }
  const claims: DeviceJwtClaims = {
    sub: record.device_id,
    tenant_id: record.tenant_id,
    role: record.role ?? DEVICE_ROLE,
    env: env.WORKER_ENV,
    iat: now,
    exp: now + ttlSeconds,
  };
  return signHs256(claims, secret);
}

/** `/device/hub-token` の既定 TTL (60s)。GW/hub は必要な都度 nonce 付きで mint する。 */
export const HUB_TOKEN_TTL_SECONDS = 60;

/** `/device/hub-token` が発行する claims。`aud` で通常の device JWT と区別する。 */
export interface HubTokenClaims {
  sub: string;
  site_id: string;
  role: string;
  nonce: string;
  aud: "hub";
  env: string;
  iat: number;
  exp: number;
  [key: string]: unknown;
}

/** `/device/cam-relay-token` を mint できる role (拠点ゲートウェイのカメラ中継専用、Refs alc-gw-p4#2 / alc-app#129)。 */
export const CAM_RELAY_TOKEN_ELIGIBLE_ROLES: ReadonlySet<string> = new Set([
  DEVICE_ROLE_GATEWAY,
]);

/** `/device/cam-relay-token` の既定 TTL (1h)。device は再接続を挟まず持ち回すため hub-token より長く取る。 */
export const CAM_RELAY_TOKEN_TTL_SECONDS = 3600;

/** `/device/cam-relay-token` が発行する claims。`aud` で hub token と区別する。 */
export interface CamRelayTokenClaims {
  sub: string;
  site_id: string;
  role: string;
  aud: "cam-relay";
  env: string;
  iat: number;
  exp: number;
  [key: string]: unknown;
}

/**
 * site-scope の短命トークンを mint する共通ロジック (`mintHubToken` / `mintCamRelayToken` の実体)。
 * role が `eligibleRoles` に無い、または `record.site_id` が未設定なら null を返す
 * (呼び出し側は 403 相当を返す前提)。
 */
async function mintSiteScopedToken(
  env: DeviceJwtEnv,
  record: DeviceRecord,
  now: number,
  eligibleRoles: ReadonlySet<string>,
  aud: string,
  ttlSeconds: number,
  extraClaims?: Record<string, unknown>,
): Promise<string | null> {
  const role = record.role ?? DEVICE_ROLE;
  if (!eligibleRoles.has(role)) return null;
  if (!record.site_id) return null;

  const secret = await resolveSecret(env.JWT_SECRET);
  if (!secret) {
    throw new Error("JWT_SECRET not configured");
  }
  return signHs256(
    {
      sub: record.device_id,
      site_id: record.site_id,
      role,
      aud,
      env: env.WORKER_ENV,
      iat: now,
      exp: now + ttlSeconds,
      ...extraClaims,
    },
    secret,
  );
}

/**
 * hub token を mint する (HS256 / JWT_SECRET、`mintDeviceJwt` と同じ鍵)。
 * `record.role` が `HUB_TOKEN_ELIGIBLE_ROLES` (device-hub / device-gateway) に
 * 含まれない、または `record.site_id` が未設定なら null を返す (呼び出し側は
 * 403 相当を返す前提)。nonce は呼び出し元 (相手デバイス) が指定したものをそのまま
 * claim に束縛し、平文 LAN 上でも再生不能にする (site-device-auth-project 設計)。
 */
export async function mintHubToken(
  env: DeviceJwtEnv,
  record: DeviceRecord,
  nonce: string,
  now: number,
  ttlSeconds: number = HUB_TOKEN_TTL_SECONDS,
): Promise<string | null> {
  return mintSiteScopedToken(env, record, now, HUB_TOKEN_ELIGIBLE_ROLES, "hub", ttlSeconds, { nonce });
}

/**
 * カメラ中継 (cf-alc-signaling の DO へ device 役として接続する) 用の token を mint する
 * (HS256 / JWT_SECRET、`mintHubToken` と同じ鍵)。`record.role` が
 * `CAM_RELAY_TOKEN_ELIGIBLE_ROLES` (device-gateway) に含まれない、または
 * `record.site_id` が未設定なら null (呼び出し側は 403 相当を返す前提)。
 * hub token と異なり相手デバイスと直接やり取りしないため nonce は不要
 * (TLS 越しの cloud DO への Bearer header であり LAN 上の再生耐性は不要)。
 */
export async function mintCamRelayToken(
  env: DeviceJwtEnv,
  record: DeviceRecord,
  now: number,
  ttlSeconds: number = CAM_RELAY_TOKEN_TTL_SECONDS,
): Promise<string | null> {
  return mintSiteScopedToken(env, record, now, CAM_RELAY_TOKEN_ELIGIBLE_ROLES, "cam-relay", ttlSeconds);
}

async function signHs256(payload: Record<string, unknown>, secret: string): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const headerSegment = base64UrlEncodeJson(header);
  const payloadSegment = base64UrlEncodeJson(payload);
  const signingInput = `${headerSegment}.${payloadSegment}`;
  const key = await crypto.subtle.importKey(
    "raw",
    TEXT_ENCODER.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, TEXT_ENCODER.encode(signingInput));
  return `${signingInput}.${base64UrlEncode(new Uint8Array(sig))}`;
}

function base64UrlEncodeJson(obj: unknown): string {
  return base64UrlEncode(TEXT_ENCODER.encode(JSON.stringify(obj)));
}

function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
