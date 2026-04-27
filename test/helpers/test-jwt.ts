/** Generate a fake JWT for testing (not cryptographically valid, but parseable) */
export function createTestJwt(
  payload: Record<string, unknown> = {},
): string {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = btoa(
    JSON.stringify({
      sub: "test-user-id",
      org: "test-org-id",
      org_slug: "test-org",
      exp: Math.floor(Date.now() / 1000) + 3600,
      ...payload,
    }),
  );
  const signature = "test-signature";
  return `${header}.${body}.${signature}`;
}

/** Generate a real HS256-signed JWT for tests that hit verifyJwt. */
export async function signTestJwt(
  payload: Record<string, unknown>,
  secret: string,
): Promise<string> {
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64UrlEncode(
    JSON.stringify({
      exp: Math.floor(Date.now() / 1000) + 3600,
      ...payload,
    }),
  );
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data)),
  );
  return `${data}.${base64UrlEncodeBytes(sig)}`;
}

function base64UrlEncode(s: string): string {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return base64UrlEncode(s);
}
