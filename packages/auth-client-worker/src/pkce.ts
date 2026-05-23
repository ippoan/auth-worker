/**
 * PKCE (RFC 7636) helpers for the Auth Code flow against auth-worker.
 *
 * The browser-consumer flow mandates S256: the worker generates a
 * high-entropy `code_verifier`, sends its SHA-256 hash (base64url-encoded,
 * no padding) as `code_challenge` to `/mcp/authorize`, then proves possession
 * by sending the original `code_verifier` to `/mcp/token` when exchanging
 * the auth `code`.
 *
 * Without PKCE, a network observer who stole the redirect's `?code=...`
 * could exchange it for a token. With PKCE the attacker also needs
 * `code_verifier`, which only the originating Worker has.
 */

/** RFC 7636 §4.1: code_verifier is 43-128 chars from the unreserved set
 *  `[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"`. 32 random bytes →
 *  base64url = 43 chars (the minimum permissible length, which still gives
 *  256 bits of entropy from the underlying random bytes). */
export function generateCodeVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/** S256 code_challenge: SHA-256(code_verifier) base64url-encoded. */
export async function computeCodeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

/** Cryptographically random `state` parameter for CSRF defense on the
 *  /oauth/login → /oauth/callback round-trip. 16 bytes → 22 chars base64url. */
export function generateState(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}
