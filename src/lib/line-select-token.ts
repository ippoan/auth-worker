/**
 * LINE Login テナント選択用の短命 handoff token (rust-alc-api#434 セキュリティ修正)。
 *
 * 複数テナントに属する LINE recipient が select-tenant する際、従来は callback が
 * **生の `line_user_id` を URL に載せ**、select-tenant が **body の `line_user_id` を信用**
 * していた。これは「victim の line_user_id を知る攻撃者が任意に JWT を mint できる」
 * auth bypass だった (rust 由来)。
 *
 * 本 token は callback (= LINE OAuth 検証済みの文脈) で `line_user_id` / `line_name` を
 * `OAUTH_STATE_SECRET` で HMAC 署名 + 10 分 TTL で封入する。select-tenant は token を
 * 検証して **token 内の line_user_id** を使い、body の line_user_id は一切信用しない。
 * token は **fragment** で front-end に渡す (query だと Referer / server log に漏れるため)。
 */

const TTL_SECONDS = 600;
const ENC = new TextEncoder();
const DEC = new TextDecoder();

function bytesToB64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function strToB64Url(s: string): string {
  return bytesToB64Url(ENC.encode(s));
}

function b64UrlToStr(s: string): string {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return DEC.decode(bytes);
}

async function hmac(data: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    ENC.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, ENC.encode(data));
  return bytesToB64Url(new Uint8Array(sig));
}

/** LINE 検証済みの line_user_id / line_name を HMAC 署名 + TTL で封入した token を返す。 */
export async function signSelectToken(
  payload: { line_user_id: string; line_name: string },
  secret: string,
  nowSec: number = Math.floor(Date.now() / 1000),
): Promise<string> {
  const body = JSON.stringify({
    line_user_id: payload.line_user_id,
    line_name: payload.line_name,
    exp: nowSec + TTL_SECONDS,
  });
  const b64 = strToB64Url(body);
  const sig = await hmac(b64, secret);
  return `${b64}.${sig}`;
}

/** token を検証し、署名・TTL OK なら line_user_id / line_name を返す。NG は null。 */
export async function verifySelectToken(
  token: string,
  secret: string,
  nowSec: number = Math.floor(Date.now() / 1000),
): Promise<{ line_user_id: string; line_name: string } | null> {
  const dot = token.indexOf(".");
  if (dot === -1) return null;
  const b64 = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (sig !== (await hmac(b64, secret))) return null;
  try {
    const obj = JSON.parse(b64UrlToStr(b64)) as {
      line_user_id?: string;
      line_name?: string;
      exp?: number;
    };
    if (!obj.exp || obj.exp < nowSec) return null;
    if (!obj.line_user_id) return null;
    return { line_user_id: obj.line_user_id, line_name: obj.line_name ?? "" };
  } catch {
    return null;
  }
}
