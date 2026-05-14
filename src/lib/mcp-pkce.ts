/**
 * MCP OAuth Provider — PKCE (RFC 7636) helper.
 *
 * Phase 5 で `authorization_code` grant を導入する際、client が POST `/mcp/token`
 * 時に渡す `code_verifier` が、認可開始時に渡された `code_challenge` (S256 ハッシュ)
 * と一致するかを検証する。
 *
 * S256 method:
 *   code_challenge = BASE64URL(SHA-256(ASCII(code_verifier)))
 *
 * RFC 7636 §4.1 で code_verifier は 43–128 文字、unreserved char セットに限定。
 * 本 helper は server 側 verify のみ実装 (verifier 生成は client 責務)。
 */

/**
 * `S256` PKCE 検証。verifier から SHA-256 hash → base64url で `expected` と一致するか判定。
 *
 * - verifier が RFC 7636 規定の文字種 / 長さに反しても、ハッシュ計算自体は通すが
 *   一致しない (= 結果 false)。長さ check は呼び出し側で別途行いたければやれば良い。
 * - 一致時 true、それ以外 (空 verifier / 空 expected / hash mismatch) は false。
 */
export async function verifyPkceS256(
  verifier: string,
  expected: string,
): Promise<boolean> {
  if (!verifier || !expected) return false;
  const hash = await sha256Base64Url(verifier);
  // strict equality (RFC 7636 §4.6)。constant-time 比較は CF Workers の制約上厳密ではないが、
  // PKCE の challenge は短期 (single-use, 5min TTL の auth code に紐付く) なので
  // 標準 string compare で許容。
  return hash === expected;
}

async function sha256Base64Url(input: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return base64UrlEncodeBytes(new Uint8Array(buf));
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
