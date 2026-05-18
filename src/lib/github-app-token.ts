/**
 * GitHub App authentication helpers — RS256 App JWT signing.
 *
 * GitHub App は installation access token を取りに行く前段で、App 自身を名乗る
 * short-lived JWT (RS256, App private key で署名) を Bearer header に乗せる必要が
 * ある。spec:
 * https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
 *
 * - `iss` = GitHub App ID
 * - `iat` = now - 60s   (clock skew tolerance per GitHub docs)
 * - `exp` = now + 540s  (max 10 min; 9 min for safety margin)
 *
 * Pure functions, no env access — `InstallationTokenStore` DO がこの module の
 * `pemToCryptoKey` + `signAppJwt` を呼んで App JWT を組み立てる。
 */

/** base64url-encode a Uint8Array or string (no padding, `-` / `_` alphabet). */
export function base64UrlEncode(input: Uint8Array | string): string {
  let bin: string;
  if (typeof input === "string") {
    bin = input;
  } else {
    bin = "";
    for (let i = 0; i < input.length; i++) {
      bin += String.fromCharCode(input[i]!);
    }
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Decode a PEM-wrapped PKCS8 private key into an `ArrayBuffer` suitable for
 * `crypto.subtle.importKey("pkcs8", ...)`. Accepts both `BEGIN PRIVATE KEY` and
 * `BEGIN RSA PRIVATE KEY` headers; whitespace inside the body is stripped.
 * Wrangler secrets stored with literal `\n` line breaks come out as actual `\n`
 * characters once `wrangler secret put` is fed via stdin, so the regex below
 * tolerates both.
 */
function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/, "")
    .replace(/-----END [A-Z ]+-----/, "")
    .replace(/\s/g, "");
  const bin = atob(b64);
  const buf = new ArrayBuffer(bin.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i++) view[i] = bin.charCodeAt(i);
  return buf;
}

/** Import a PEM PKCS8 RSA private key as a non-extractable RS256 signing key. */
export async function pemToCryptoKey(pem: string): Promise<CryptoKey> {
  const buf = pemToArrayBuffer(pem);
  return await crypto.subtle.importKey(
    "pkcs8",
    buf,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

/**
 * Sign an RS256 App JWT for the given `appId`. `nowSec` is taken as an
 * argument (not `Date.now()`) so tests can pin the timestamps deterministically.
 */
export async function signAppJwt(
  appId: string,
  key: CryptoKey,
  nowSec: number,
): Promise<string> {
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: appId,
    iat: nowSec - 60,
    exp: nowSec + 540,
  };
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(signingInput),
  );
  const sigB64 = base64UrlEncode(new Uint8Array(sig));
  return `${signingInput}.${sigB64}`;
}
