/**
 * LINE WORKS webhook の暗号資産を Web Crypto API で扱うユーティリティ。
 *
 * rust-alc-api 側 `crates/alc-core/src/auth_lineworks.rs::decrypt_secret` と
 * `crates/alc-notify/src/lineworks_channels.rs::verify_signature` の TypeScript 移植。
 * 暗号スキームを変えたらどちらも同じ ciphertext / signature を相互運用できる必要があるため、
 * 移植仕様は厳密に揃える:
 *
 * - **AES-256-GCM 復号**: key = SHA-256(key_material) (32 bytes)、payload = base64(nonce(12B) || ciphertext || tag(16B))
 * - **HMAC-SHA256 署名**: key = bot_secret (raw bytes、変換なし)、出力 = base64(32B)
 * - **定数時間比較**: 署名検証で必須
 */

const TEXT_DECODER = new TextDecoder();
const TEXT_ENCODER = new TextEncoder();

/**
 * `key_material` を SHA-256 でハッシュして得た 32 バイトを AES-256-GCM の鍵とし、
 * `nonce(12B) || ciphertext || tag(16B)` 形式の base64 ペイロードを復号する。
 */
export async function decryptBotSecret(
  ciphertextB64: string,
  keyMaterial: string,
): Promise<string> {
  const payload = base64Decode(ciphertextB64);
  if (payload.length < 12 + 16) {
    throw new Error("ciphertext too short");
  }
  const nonce = payload.slice(0, 12);
  const ciphertextAndTag = payload.slice(12);

  const keyBytes = await sha256(TEXT_ENCODER.encode(keyMaterial));
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    cryptoKey,
    ciphertextAndTag,
  );
  return TEXT_DECODER.decode(plaintext);
}

/**
 * HMAC-SHA256(bot_secret, body) を base64 で返す。
 * bot_secret は **そのまま raw bytes として** 鍵に使う (rust 側 hmac::Hmac::new_from_slice と同じ)。
 */
export async function signWebhookBody(
  botSecret: string,
  body: ArrayBuffer | Uint8Array,
): Promise<string> {
  const keyBytes = TEXT_ENCODER.encode(botSecret);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sigBuf = await crypto.subtle.sign("HMAC", cryptoKey, body);
  return base64Encode(new Uint8Array(sigBuf));
}

/**
 * 同じ長さの 2 配列を **定数時間** で比較。HMAC 検証はタイミング攻撃を避けるため必須。
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(buf);
}

export function base64Decode(b64: string): Uint8Array {
  // atob は Workers でも使える。バイナリ文字列を Uint8Array に変換。
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function base64Encode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i] ?? 0);
  return btoa(bin);
}
