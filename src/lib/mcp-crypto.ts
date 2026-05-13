/**
 * MCP OAuth Provider — AES-256-GCM symmetric encryption helpers.
 *
 * Phase 3 で `github_token:{sub}` を KV に置く前に暗号化する用途で導入。
 * 既存 `src/lib/lineworks-crypto.ts` の `decryptBotSecret` と同じスキーム
 * (key = SHA-256(keyMaterial)、payload = base64(nonce(12B) || ciphertext || tag(16B)))
 * を採用しているため、将来 rust 側 (alc-core::auth_lineworks::decrypt_secret) と
 * 相互運用可能。lineworks-crypto は decrypt のみで encrypt 関数を持たないため
 * 重複を避けず新規 file として切り、Phase 6 で extract / 統合候補とする (TODO)。
 *
 * - encrypt: 平文 (UTF-8) → base64 ciphertext
 * - decrypt: base64 ciphertext → 平文 (UTF-8)
 */

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

/**
 * `plaintext` を AES-256-GCM で暗号化し、`base64(nonce(12B) || ciphertext || tag(16B))`
 * を返す。nonce は呼び出し毎にランダム生成 (AES-GCM 標準)、同じ平文を 2 回呼んでも
 * 出力は異なる。
 */
export async function encryptWithKey(
  plaintext: string,
  keyMaterial: string,
): Promise<string> {
  const keyBytes = await sha256(TEXT_ENCODER.encode(keyMaterial));
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ctAndTag = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    cryptoKey,
    TEXT_ENCODER.encode(plaintext),
  );
  const payload = new Uint8Array(12 + ctAndTag.byteLength);
  payload.set(nonce, 0);
  payload.set(new Uint8Array(ctAndTag), 12);
  return base64Encode(payload);
}

/**
 * `encryptWithKey` で作った base64 payload を復号して UTF-8 文字列を返す。
 * 鍵不一致 / 改ざん / 切り詰めには Web Crypto API が OperationError を throw する
 * (呼び出し側で catch することを推奨)。
 */
export async function decryptWithKey(
  ciphertextB64: string,
  keyMaterial: string,
): Promise<string> {
  const payload = base64Decode(ciphertextB64);
  if (payload.length < 12 + 16) {
    throw new Error("ciphertext too short");
  }
  const nonce = payload.slice(0, 12);
  const ctAndTag = payload.slice(12);
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
    ctAndTag,
  );
  return TEXT_DECODER.decode(plaintext);
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(buf);
}

function base64Encode(bytes: Uint8Array): string {
  let bin = "";
  // noUncheckedIndexedAccess は bytes[i] を `T | undefined` にするが、i < length で
  // 保証されるので `!` で剥がす (`?? 0` だと右辺 branch が常に dead で 100% Branches を割る)
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}

function base64Decode(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
