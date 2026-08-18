/**
 * Cloudflare Access 向け OIDC surface (`/oidc/*`) の authorization code / access token
 * 保管。既存 MCP OAuth の KV (`MCP_OAUTH_KV`) を **別 prefix** で間借りする。
 *
 * prefix を分けるのは、MCP 側の `auth:request:*` / `authcode:*` と名前空間が交差せず、
 * 片方の失効・掃除がもう片方に波及しないようにするため (KV namespace 自体を増やすと
 * binding の追加 = deploy リスクが増えるので、prefix 分離で足りる範囲はそうする)。
 */

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

export async function putOidcCode(
  kv: KVNamespace,
  code: string,
  record: OidcCodeRecord,
): Promise<void> {
  await kv.put(CODE_PREFIX + code, JSON.stringify(record), {
    expirationTtl: OIDC_CODE_TTL_SEC,
  });
}

/**
 * code を読み出して**必ず消す** (single-use、RFC 6749 §4.1.2)。
 * 読めた場合でも消してから返すので、同じ code での 2 回目の交換は必ず失敗する。
 * 壊れた JSON は `null` (消す動作は同じ)。
 */
export async function takeOidcCode(
  kv: KVNamespace,
  code: string,
): Promise<OidcCodeRecord | null> {
  const key = CODE_PREFIX + code;
  const raw = await kv.get(key);
  if (raw === null) return null;
  await kv.delete(key);
  try {
    return JSON.parse(raw) as OidcCodeRecord;
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
