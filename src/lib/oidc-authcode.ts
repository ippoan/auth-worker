/**
 * Cloudflare Access 向け OIDC surface (`/oidc/*`) の authorization code / access token
 * 保管。
 *
 * - **authorization code は Durable Object** (`ALARM_NONCE_DO` の single-use ストアを
 *   インスタンス名 `oidc-code` で間借り)。authorize はブラウザが着いた拠点で code を書き、
 *   token 交換は Access のサーバが**別の拠点**から読みに来る。KV は結果整合なので、書いた
 *   拠点と違う拠点では直後の get が null になり、交換が `invalid_grant` で落ちていた
 *   (2026-11-27、authorize は SIN・token は FUK で 400 が続いた)。DO は全体で 1 つの
 *   インスタンスが直列に読み書きするので、どの拠点から呼んでも書いた直後に読め、
 *   get → delete も他の要求に割り込まれない (single-use が atomic)。
 * - access token (userinfo 用) は KV (`MCP_OAUTH_KV`) の `oidc:at:` のまま。Access は
 *   id_token の claim で identity を取り userinfo を呼んでいない (呼び出し 0 件) ため。
 *   userinfo を使う client を足すなら、こちらも同じ理由で DO へ移すこと。
 */
import type { Env } from "../index";
import type { AlarmNonceDO } from "../durable_objects/alarm-nonce-do";

/** authorization code に紐付く発行時コンテキスト。 */
export interface OidcCodeRecord {
  client_id: string;
  /** token endpoint で再提示される redirect_uri と突き合わせる (RFC 6749 §4.1.3)。 */
  redirect_uri: string;
  /** client が渡した nonce。id_token にそのまま載せて replay を防ぐ。 */
  nonce?: string;
  /** PKCE。client が code_challenge を送ってきた時だけ入る。 */
  code_challenge?: string;
  scope: string;
  /** id_token / userinfo に載せる identity (logi_auth_token から写したもの)。 */
  claims: OidcIdentityClaims;
}

/**
 * id_token / userinfo に載せる identity。`logi_auth_token` (AppClaims) から
 * 写せるものだけを持つ — この surface は新しい identity を作らず、既存
 * セッションの identity を Access に**そのまま渡す**のが役目。
 */
export interface OidcIdentityClaims {
  sub: string;
  email: string;
  name?: string;
  /** Access のポリシーで組織を絞れるようにする (custom claim)。 */
  tenant_id?: string;
  /** Access のポリシーで権限を絞れるようにする (custom claim)。 */
  role?: string;
  org_slug?: string;
}

/** authorization code の寿命。RFC 6749 §4.1.2 は「最大 10 分、1 分推奨」。 */
export const OIDC_CODE_TTL_SEC = 60;

/** userinfo 用 access token の寿命。Access は交換直後にしか使わないので短くて足りる。 */
export const OIDC_ACCESS_TOKEN_TTL_SEC = 300;

const CODE_PREFIX = "oidc:code:";
const TOKEN_PREFIX = "oidc:at:";

/** URL-safe な不透明トークンを作る (code / access_token 共用)。 */
export function generateOidcOpaqueToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * code の置き場。`AlarmNonceDO` (put / take の single-use ストア。期限は値の JSON の `exp` で
 * 見て alarm が掃除する) の、デバイス nonce とは別のインスタンス。日本寄り (`apac-ne`) に置く
 * (利用者も Access の交換も日本から。location hint は最初の `get` でだけ効く)。
 */
export function oidcCodeStore(env: Env): DurableObjectStub<AlarmNonceDO> {
  const ns = env.ALARM_NONCE_DO;
  // apac-ne (2026-06 追加) は手元の型定義にまだ無い
  return ns.get(ns.idFromName("oidc-code"), { locationHint: "apac-ne" as DurableObjectLocationHint });
}

/** 置き場に積む形。`exp` (unix 秒) は TTL の検査と alarm の掃除に使う。 */
type StoredOidcCode = OidcCodeRecord & { exp: number };

export async function putOidcCode(
  env: Env,
  code: string,
  record: OidcCodeRecord,
): Promise<void> {
  const nowMs = Date.now();
  const stored: StoredOidcCode = { ...record, exp: Math.floor(nowMs / 1000) + OIDC_CODE_TTL_SEC };
  await oidcCodeStore(env).put(CODE_PREFIX + code, JSON.stringify(stored), nowMs);
}

/**
 * code を読み出して**必ず消す** (single-use、RFC 6749 §4.1.2)。DO の中で get → delete を
 * 直列に行うので、同じ code での 2 回目の交換は (同時に来ても) 必ず null になる。
 * 期限切れ・壊れた JSON も `null` (消す動作は同じ)。
 */
export async function takeOidcCode(env: Env, code: string): Promise<OidcCodeRecord | null> {
  const raw = await oidcCodeStore(env).take(CODE_PREFIX + code);
  if (raw === null) return null;
  try {
    const { exp, ...record } = JSON.parse(raw) as StoredOidcCode;
    if (typeof exp !== "number" || exp <= Math.floor(Date.now() / 1000)) return null;
    return record;
  } catch {
    return null;
  }
}

export async function putOidcAccessToken(
  kv: KVNamespace,
  token: string,
  claims: OidcIdentityClaims,
): Promise<void> {
  await kv.put(TOKEN_PREFIX + token, JSON.stringify(claims), {
    expirationTtl: OIDC_ACCESS_TOKEN_TTL_SEC,
  });
}

/** userinfo 用。access token は single-use ではない (TTL 内は再取得可)。 */
export async function getOidcAccessTokenClaims(
  kv: KVNamespace,
  token: string,
): Promise<OidcIdentityClaims | null> {
  const raw = await kv.get(TOKEN_PREFIX + token);
  if (raw === null) return null;
  try {
    return JSON.parse(raw) as OidcIdentityClaims;
  } catch {
    return null;
  }
}
