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

export function errorResponse(status: number, message: string): Response {
  return jsonResponse({ error: message }, status);
}
