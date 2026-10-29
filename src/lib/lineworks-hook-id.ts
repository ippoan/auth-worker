/**
 * LINE WORKS webhook の callback URL に載せる識別子 (`/lineworks/hook/{識別子}`)。
 *
 * 識別子 = tenant と bot_id を暗号化したもの。tenant を URL に出さず、受けたときに DB を引かずに tenant と bot を知るため
 * (旧 `/lineworks/webhook/{bot_id}` は tenant を持たず、alc-notify が tenant をまたぐ SECURITY DEFINER の関数で bot を引いていた)。
 *
 * - 鍵: `SSO_ENCRYPTION_KEY` から HKDF-SHA256 で用途別に 2 つ派生させる (暗号用・IV 用)。元の鍵はこの用途に直接使わない
 * - 同じ (tenant, bot) なら毎回同じ識別子にする (URL を固定するため)。IV は HMAC-SHA256(IV 用の鍵, 平文) の先頭 12 バイト
 *   (synthetic IV)。平文が違えば IV も違うので、AES-GCM の IV の使い回しは起きない
 * - 形: base64url(IV(12B) || AES-256-GCM(平文) || tag(16B))。平文は `${tenant_id}\n${bot_id}`
 * - 復号: GCM の tag で改ざんを弾き、IV を平文から計算し直して一致を確かめる (この形で作ったものだけを通す)
 *
 * 識別子は秘密ではない (LINE WORKS の console に登録する URL)。偽の識別子では復号できず、本物でも webhook は bot secret の署名を
 * 通らない限り受け付けない。
 */

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();
const IV_BYTES = 12;
const TAG_BYTES = 16;
const ENC_INFO = "lineworks-webhook-hook-id/v1/enc";
const IV_INFO = "lineworks-webhook-hook-id/v1/iv";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** 識別子が指す tenant と bot */
export interface HookTarget {
  tenantId: string;
  botId: string;
}

async function deriveKeys(keyMaterial: string): Promise<{ enc: CryptoKey; iv: CryptoKey }> {
  const base = await crypto.subtle.importKey("raw", TEXT_ENCODER.encode(keyMaterial), "HKDF", false, [
    "deriveKey",
  ]);
  const params = (info: string) => ({
    name: "HKDF",
    hash: "SHA-256",
    salt: new Uint8Array(0),
    info: TEXT_ENCODER.encode(info),
  });
  const enc = await crypto.subtle.deriveKey(params(ENC_INFO), base, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  const iv = await crypto.subtle.deriveKey(params(IV_INFO), base, { name: "HMAC", hash: "SHA-256", length: 256 }, false, [
    "sign",
  ]);
  return { enc, iv };
}

async function syntheticIv(key: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, plaintext));
  return mac.slice(0, IV_BYTES);
}

/** (tenant, bot) → 識別子。tenant は UUID (小文字)、bot_id は空でなく改行を含まない文字列 */
export async function encodeHookId(target: HookTarget, keyMaterial: string): Promise<string> {
  const tenantId = target.tenantId.toLowerCase();
  if (!UUID_RE.test(tenantId)) throw new Error("tenant_id must be a uuid");
  if (!target.botId || target.botId.includes("\n")) throw new Error("bot_id must be non-empty without newlines");
  const plaintext = TEXT_ENCODER.encode(`${tenantId}\n${target.botId}`);
  const keys = await deriveKeys(keyMaterial);
  const iv = await syntheticIv(keys.iv, plaintext);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, keys.enc, plaintext));
  const out = new Uint8Array(IV_BYTES + sealed.length);
  out.set(iv, 0);
  out.set(sealed, IV_BYTES);
  return base64UrlEncode(out);
}

/** 識別子 → (tenant, bot)。この鍵とこの形で作ったものでなければ null */
export async function decodeHookId(hookId: string, keyMaterial: string): Promise<HookTarget | null> {
  const raw = base64UrlDecode(hookId);
  if (!raw || raw.length < IV_BYTES + TAG_BYTES + 1) return null;
  const iv = raw.slice(0, IV_BYTES);
  const keys = await deriveKeys(keyMaterial);
  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, keys.enc, raw.slice(IV_BYTES)));
  } catch {
    return null;
  }
  const expectedIv = await syntheticIv(keys.iv, plaintext);
  if (!expectedIv.every((b, i) => b === iv[i])) return null;
  // ここまで通れば encodeHookId が作ったもの (入力の形は作るときに確かめてある)
  const text = TEXT_DECODER.decode(plaintext);
  const nl = text.indexOf("\n");
  return { tenantId: text.slice(0, nl), botId: text.slice(nl + 1) };
}

/** 画面が callback URL を出すための口 (`/alc-proxy` の中で auth-worker が答える。下流へは流さない) */
export const WEBHOOK_URL_PATH = "/api/lineworks/webhook-url";

/**
 * `GET /alc-proxy/api/lineworks/webhook-url?bot_id=` — その会社の bot の callback URL の path (`{path: "/lineworks/hook/{識別子}"}`)。
 * tenant は検証済みの JWT から取る (画面からは渡させない)。admin だけ (403)。`bot_id` が無ければ 400、鍵が無ければ 503。
 * この path でなければ null (呼び手は下流へ流す)。
 */
export async function handleWebhookUrlPath(
  keyMaterial: string | null | undefined,
  backendPath: string,
  method: string,
  search: string,
  caller: { tenantId: string; role: string },
): Promise<Response | null> {
  if (backendPath !== WEBHOOK_URL_PATH) return null;
  if (method !== "GET") return json({ error: "method_not_allowed" }, 405);
  if (caller.role !== "admin") return json({ error: "forbidden" }, 403);
  const botId = new URLSearchParams(search).get("bot_id") ?? "";
  if (!botId || botId.includes("\n")) return json({ error: "bot_id_required" }, 400);
  if (!keyMaterial) return json({ error: "not_configured" }, 503);
  let hookId: string;
  try {
    hookId = await encodeHookId({ tenantId: caller.tenantId, botId }, keyMaterial);
  } catch {
    return json({ error: "invalid_tenant" }, 400);
  }
  return json({ path: `/lineworks/hook/${hookId}` }, 200);
}

function json(data: unknown, status: number): Response {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}

function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** base64url → bytes。base64url の文字以外を含めば null */
function base64UrlDecode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) return null;
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
  let bin: string;
  try {
    bin = atob(b64);
  } catch {
    return null;
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
