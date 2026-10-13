const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

export function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** JSON response with CORS headers (for cross-origin API calls from frontends) */
export function corsJsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

/** CORS preflight response */
export function corsPreflight(): Response {
  return new Response(null, { headers: CORS_HEADERS });
}

/** Extract Bearer token from Authorization header */
export function extractToken(request: Request): string | null {
  const auth = request.headers.get("Authorization");
  if (auth?.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

/**
 * `Authorization: Basic <base64(user:pass)>` を分解する。Basic でない / base64 が壊れている /
 * `:` が無い → null。値の decode (form-urlencoded 等) は呼び手の規約に任せる
 * (`oidc-token` は RFC 6749 §2.3.1 の decodeURIComponent をかける、machine credential は生のまま)。
 */
export function parseBasicAuth(
  authorization: string | null | undefined,
): { username: string; password: string } | null {
  if (!authorization?.startsWith("Basic ")) return null;
  let decoded: string;
  try {
    decoded = atob(authorization.slice("Basic ".length));
  } catch {
    return null;
  }
  const sep = decoded.indexOf(":");
  if (sep === -1) return null;
  return { username: decoded.slice(0, sep), password: decoded.slice(sep + 1) };
}

export function errorResponse(status: number, message: string): Response {
  return jsonResponse({ error: message }, status);
}
