/**
 * ES256 (ECDSA P-256) 署名鍵の解決・JWKS 組み立て・JWT 署名。
 *
 * **用途は Cloudflare Access 向け OIDC surface の `id_token` 専用** (issue: auth-worker
 * を Access の generic OIDC プロバイダにする)。Access は IdP の `id_token` を **JWKS で
 * 検証する**ため、共有秘密で対称署名する既存の HS256 経路 (`jwt.ts` の `JWT_SECRET` /
 * `mcp-jwt.ts` の `MCP_JWT_SECRET`) は原理的に使えない — 検証側に秘密鍵を渡すことに
 * なるため。よって非対称鍵をここで新設する。
 *
 * **既存 HS256 トークンには一切影響しない。** 本 module が扱う鍵は Access 向け
 * `id_token` の署名だけに使い、`logi_auth_token` / MCP access token の発行・検証には
 * 関与しない (鍵も binding も別)。
 *
 * ## 鍵の持ち方とローテーション
 *
 * Secrets Store の 1 entry に **私有 JWK の JSON 配列** を入れる:
 *
 *   [ {"kty":"EC","crv":"P-256","x":"...","y":"...","d":"..."},  ← 先頭 = 現用 (署名に使う)
 *     {"kty":"EC","crv":"P-256","x":"...","y":"...","d":"..."} ] ← 以降 = 検証用に JWKS へ出すだけ
 *
 * ローテーションは「新しい鍵を **先頭に** 足して deploy → 旧 id_token の寿命 (数分) を
 * 過ぎたら末尾を削って deploy」の 2 段。JWKS には常に全鍵の公開部が出るので、
 * 切り替えの瞬間に Access 側で検証が落ちる窓が生まれない。単一 JWK オブジェクト
 * (配列でない) も受け付ける — 初回投入で配列を書き忘れても動くようにするため。
 *
 * `kid` は RFC 7638 の JWK Thumbprint (SHA-256, base64url) を**値から導出**する。
 * 人手で採番しないので、鍵を差し替えれば kid も自動で変わり、取り違えが起きない。
 */
import { resolveSecret, type SecretBinding } from "./secret";

/** ES256 の JWK。`d` を持つものが私有鍵、持たないものが公開鍵。 */
export interface OidcJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  /** 私有鍵成分。JWKS に出す公開 JWK では必ず落とす。 */
  d?: string;
  kid?: string;
  alg?: "ES256";
  use?: "sig";
}

/** JWKS document (RFC 7517 §5)。 */
export interface OidcJwks {
  keys: OidcJwk[];
}

/**
 * 1 要素が ES256 私有 JWK として最低限成立しているか。
 * `kty`/`crv` を厳格に見るのは、RSA 鍵を貼られて ES256 で署名しようとして
 * 実行時に落ちるより、投入時点で弾く方が原因が分かりやすいため。
 */
function isPrivateEs256Jwk(value: unknown): value is OidcJwk {
  if (typeof value !== "object" || value === null) return false;
  const j = value as Record<string, unknown>;
  return (
    j.kty === "EC" &&
    j.crv === "P-256" &&
    typeof j.x === "string" &&
    j.x !== "" &&
    typeof j.y === "string" &&
    j.y !== "" &&
    typeof j.d === "string" &&
    j.d !== ""
  );
}

/**
 * Secrets Store の生文字列を私有 JWK の配列に parse する。
 *
 * - JSON 配列 → 各要素を検証。**1 つでも不正なら全体を `null`** にする
 *   (壊れた鍵を黙って読み飛ばすと「JWKS には出ているのに検証が通らない」という
 *   最も追いにくい形の障害になるため、fail-closed にする)。
 * - 単一 JWK オブジェクト → 1 要素の配列として扱う。
 * - JSON として壊れている / 空配列 / 型不一致 → `null`。
 */
export function parseOidcSigningKeys(raw: string): OidcJwk[] | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  const list = Array.isArray(parsed) ? parsed : [parsed];
  if (list.length === 0) return null;
  const keys: OidcJwk[] = [];
  for (const item of list) {
    if (!isPrivateEs256Jwk(item)) return null;
    keys.push(item);
  }
  return keys;
}

/**
 * binding (Secrets Store / plain string) を私有 JWK 配列に解決する。
 * 未 bind・取得失敗・parse 失敗はすべて `null` — 呼び出し側は 1 分岐で 503 にできる。
 */
export async function resolveOidcSigningKeys(
  binding: SecretBinding,
): Promise<OidcJwk[] | null> {
  const raw = await resolveSecret(binding);
  if (!raw) return null;
  return parseOidcSigningKeys(raw);
}

/**
 * RFC 7638 JWK Thumbprint (SHA-256 → base64url) を `kid` として導出する。
 *
 * thumbprint の入力は「required members だけを **lexicographic order** で並べた
 * 空白なし JSON」と RFC が規定する。EC 鍵の required members は crv / kty / x / y。
 * ここを崩すと JWKS の kid と id_token header の kid がズレて Access が鍵を
 * 引けなくなるので、手で並べた固定文字列にしている。
 */
export async function jwkThumbprintKid(jwk: OidcJwk): Promise<string> {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonical),
  );
  return base64UrlEncodeBytes(new Uint8Array(digest));
}

/**
 * 私有 JWK から **公開部だけ** の JWK を作る (`d` を落とし、kid/alg/use を付ける)。
 * JWKS に出す唯一の経路をここに閉じることで、`d` の漏洩を構造的に防ぐ。
 */
export async function toPublicJwk(jwk: OidcJwk): Promise<OidcJwk> {
  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    kid: await jwkThumbprintKid(jwk),
    alg: "ES256",
    use: "sig",
  };
}

/** 私有 JWK 配列 → 公開 JWKS。先頭 (現用鍵) から順に並ぶ。 */
export async function buildJwks(keys: OidcJwk[]): Promise<OidcJwks> {
  return { keys: await Promise.all(keys.map(toPublicJwk)) };
}

/**
 * ES256 で JWT を署名する。header には `alg` / `typ` / `kid` を載せる
 * (Access は `kid` で JWKS から鍵を引く)。
 *
 * Web Crypto の ECDSA/P-256 署名は **raw な r‖s の 64 byte** を返す。これは JOSE が
 * ES256 に要求する形式そのものなので、DER への変換は不要 (ここを DER のまま出すと
 * Access 側の検証が無言で落ちる)。
 */
export async function signEs256Jwt(
  payload: Record<string, unknown>,
  jwk: OidcJwk,
): Promise<string> {
  const kid = await jwkThumbprintKid(jwk);
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d, ext: true },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const headerB64 = base64UrlEncodeStr(
    JSON.stringify({ alg: "ES256", typ: "JWT", kid }),
  );
  const payloadB64 = base64UrlEncodeStr(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${base64UrlEncodeBytes(new Uint8Array(signature))}`;
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** UTF-8 文字列 → base64url (JWT header/payload encode 用)。 */
function base64UrlEncodeStr(s: string): string {
  return base64UrlEncodeBytes(new TextEncoder().encode(s));
}
