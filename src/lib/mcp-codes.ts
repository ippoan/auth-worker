/**
 * MCP OAuth Provider — device_code / user_code 生成ユーティリティ。
 *
 * RFC 8628 §6.1 に従い、`user_code` は紛らわしい文字 (0/O/1/I/U 等) を排した
 * 20 子音 (`BCDFGHJKLMNPQRSTVWXZ`) からなる `XXXX-XXXX` 形式。
 * `device_code` は 256 bit (32 byte) ランダムを hex (64 文字) で返す。
 */

/** RFC 8628 §6.1 user_code: 紛らわしい文字 (0/O/1/I/U/A/E 等) 除外、20 子音 */
const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"; // 20 chars
const USER_CODE_LEN = 8; // → "XXXX-XXXX"

/**
 * 8 文字の user_code を `XXXX-XXXX` 形式で生成する。
 * Entropy: 20^8 ≈ 2.56e10 ≈ 35 bit。15 分 TTL + Phase 5 で rate-limit するため十分。
 */
export function generateUserCode(): string {
  const bytes = new Uint8Array(USER_CODE_LEN);
  crypto.getRandomValues(bytes);
  const chars: string[] = [];
  for (let i = 0; i < USER_CODE_LEN; i++) {
    // bytes[i] / USER_CODE_ALPHABET[...] は noUncheckedIndexedAccess で
    // `T | undefined` だが、固定長 + 固定 alphabet なので必ず存在する
    const idx = (bytes[i] as number) % USER_CODE_ALPHABET.length;
    chars.push(USER_CODE_ALPHABET[idx] as string);
  }
  return `${chars.slice(0, 4).join("")}-${chars.slice(4).join("")}`;
}

/** 256 bit = 32 byte ランダム hex (64 文字)。device_code は client 側に出すので
 *  予測不可能性 (forward secrecy 不要) のため通常の CSPRNG で十分。 */
export function generateDeviceCode(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
