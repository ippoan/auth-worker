/**
 * redirect_uri validation and OAuth state HMAC utilities
 */

/** Check if a redirect URI is in the allowed origins whitelist */
export function isAllowedRedirectUri(
  redirectUri: string,
  allowedOrigins: string,
): boolean {
  const origins = allowedOrigins.split(",").map((o) => o.trim());
  try {
    const url = new URL(redirectUri);
    const origin = url.origin;
    return origins.some((allowed) => origin === allowed);
  } catch {
    return false;
  }
}

/** Generate HMAC-signed OAuth state parameter */
export async function generateOAuthState(
  redirectUri: string,
  secret: string,
  extra?: Record<string, string>,
): Promise<string> {
  const nonce = crypto.randomUUID();
  const statePayload = JSON.stringify({ redirect_uri: redirectUri, nonce, ...extra });
  const stateB64 = base64UrlEncode(statePayload);

  const signature = await hmacSign(stateB64, secret);
  return `${stateB64}.${signature}`;
}

/** Verify and decode HMAC-signed OAuth state parameter */
export async function verifyOAuthState(
  state: string,
  secret: string,
): Promise<{ redirect_uri: string; provider?: string; external_org_id?: string; join_org?: string } | null> {
  const dotIndex = state.indexOf(".");
  if (dotIndex === -1) return null;

  const stateB64 = state.substring(0, dotIndex);
  const signature = state.substring(dotIndex + 1);

  const expectedSignature = await hmacSign(stateB64, secret);
  if (signature !== expectedSignature) return null;

  try {
    const json = base64UrlDecode(stateB64);
    return JSON.parse(json) as { redirect_uri: string; provider?: string; external_org_id?: string; join_org?: string };
  } catch {
    return null;
  }
}

async function hmacSign(data: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data),
  );
  return base64UrlEncode(
    String.fromCharCode(...new Uint8Array(signature)),
  );
}

function base64UrlEncode(data: string): string {
  return btoa(data).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(data: string): string {
  const base64 = data.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  return atob(padded);
}
